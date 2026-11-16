//! # cleimesh-allowance
//!
//! Give an agent a **signed allowance**: it may call one tool, to one
//! recipient, up to an amount, for a number of calls — and no more. The
//! allowance is an owner-signed [Attenuating Agent Token][aat]; the per-call
//! limits ride in the token's argument constraints, the cumulative spend cap
//! and the call count ride in a signed entry inside it, and the host enforces
//! all of it **outside the agent** at dispatch. A prompt-injected or malicious
//! agent cannot widen it, because it never held more than this.
//!
//! ```
//! use cleimesh_allowance::{Envelope, Ledger, issue, admit};
//! use cleimesh_aat::{SigningKey, Jwk, pop, Presentation};
//! use serde_json::json;
//!
//! let now = 1_800_000_000;
//! let owner = SigningKey::from_bytes(&[1u8; 32]);
//! let agent = SigningKey::from_bytes(&[2u8; 32]);
//!
//! // You sign an allowance: pay "demo", up to $5, 5 calls, for an hour.
//! let env = Envelope::new(Jwk::from_key(&agent.verifying_key()), "pay", "demo", 5.0, 5, 3600);
//! let token = issue(&owner, "urn:owner:you", &env, now).unwrap();
//!
//! // The agent then acts alone; the host admits only inside the allowance.
//! let mut ledger = Ledger::new();
//! let owner_jwk = Jwk::from_key(&owner.verifying_key());
//! let present = |amount: f64| {
//!     let args = json!({ "to": "demo", "amount": amount });
//!     let p = Presentation { chain: vec![token.clone()], pop: pop(&agent, &token, "pay", &args, None, now).unwrap() };
//!     (args, p)
//! };
//! let (args, p) = present(2.0);
//! assert!(admit("pay", &args, &p, &owner_jwk, now, &mut ledger).is_ok());
//! ```
//!
//! [aat]: https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/

use std::collections::{BTreeMap, HashMap};

use cleimesh_aat::{self as aat, Claims, Constraint, Jwk, Policy, Presentation, ReplayGuard, SigningKey, Tools};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The `authorization_details` entry that carries the cumulative limits.
pub const ALLOWANCE_TYPE: &str = "cleimesh_allowance";
/// The only entry version this implementation reads.
pub const ALLOWANCE_VERSION: u32 = 1;

/// What the owner signs: one tool, one recipient, an amount and a call budget.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// The agent key the allowance is granted to.
    pub holder: Jwk,
    /// The tool the agent may call.
    pub tool: String,
    /// The only value the tool's `to` argument may name.
    pub to: String,
    /// The most the tool's `amount` argument may be, per call and in total.
    pub amount_max: f64,
    /// How many calls the allowance admits.
    pub calls: u32,
    /// How long the allowance lasts, in seconds.
    pub ttl_secs: i64,
}

impl Envelope {
    pub fn new(holder: Jwk, tool: impl Into<String>, to: impl Into<String>, amount_max: f64, calls: u32, ttl_secs: i64) -> Self {
        Envelope { holder, tool: tool.into(), to: to.into(), amount_max, calls, ttl_secs }
    }

    /// The human-readable allowance card: what you are signing.
    pub fn card(&self) -> Vec<String> {
        vec![
            format!("call  {}   to  \"{}\"   up to ${:.2} each", self.tool, self.to, self.amount_max),
            format!("at most {} calls, ${:.2} in total, for {}s", self.calls, self.amount_max, self.ttl_secs),
        ]
    }

    fn tools(&self) -> Tools {
        let args = BTreeMap::from([
            ("to".to_string(), Constraint::exact(self.to.as_str())),
            (
                "amount".to_string(),
                Constraint::Range { min: Some(0.0), max: Some(self.amount_max), min_inclusive: true, max_inclusive: true },
            ),
        ]);
        BTreeMap::from([(self.tool.clone(), args)])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    #[serde(rename = "type")]
    ty: String,
    v: u32,
    calls: u32,
    cap: f64,
}

/// Why an allowance could not be issued or a call admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The presented token does not authorize this call (wrong tool, payee,
    /// per-call amount, expired, bad signature…). Message from the AAT check.
    NotAllowed(String),
    /// The token carries no allowance entry.
    NotAnAllowance,
    /// The allowance entry is malformed or of an unknown version.
    BadAllowance(String),
    /// Every call the allowance admitted has been made.
    CallsExhausted,
    /// This call would take the cumulative spend past the allowance.
    CapExceeded,
    /// The `amount` argument is not a non-negative number.
    AmountInvalid,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Refusal::NotAllowed(m) => write!(f, "not allowed by the token: {m}"),
            Refusal::NotAnAllowance => write!(f, "the token carries no allowance"),
            Refusal::BadAllowance(m) => write!(f, "malformed allowance: {m}"),
            Refusal::CallsExhausted => write!(f, "out of calls on this allowance"),
            Refusal::CapExceeded => write!(f, "over the allowance"),
            Refusal::AmountInvalid => write!(f, "amount is not a non-negative number"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Sign and issue the allowance. The owner's key signs an AAT root for the
/// holder: the per-call limits as argument constraints, the cumulative cap and
/// call count in a signed `cleimesh_allowance` entry.
pub fn issue(owner: &SigningKey, iss: &str, env: &Envelope, now: i64) -> Result<String, Refusal> {
    if !env.amount_max.is_finite() || env.amount_max < 0.0 {
        return Err(Refusal::BadAllowance("amount_max must be finite and non-negative".into()));
    }
    let entry = json!({ "type": ALLOWANCE_TYPE, "v": ALLOWANCE_VERSION, "calls": env.calls, "cap": env.amount_max });
    aat::issue_root_with(owner, iss, &env.holder, env.tools(), vec![entry], now, env.ttl_secs, 0)
        .map_err(|e| Refusal::BadAllowance(e.0))
}

/// A call that passed the allowance, by value, so the executor runs it once.
#[derive(Debug, Clone, PartialEq)]
pub struct Admitted {
    tool: String,
    params: Value,
    allowance: String,
}

impl Admitted {
    pub fn tool(&self) -> &str {
        &self.tool
    }
    pub fn params(&self) -> &Value {
        &self.params
    }
    /// The allowance (root token `jti`) this call was admitted under.
    pub fn allowance(&self) -> &str {
        &self.allowance
    }
}

/// Calls made and amount spent per allowance, plus the replay window. Keep it
/// durable across restarts, or a restart resets the budget.
#[derive(Debug, Default)]
pub struct Ledger {
    replay: ReplayGuard,
    used: HashMap<String, (u32, f64)>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calls made and amount spent so far under the allowance `jti`.
    pub fn usage(&self, jti: &str) -> (u32, f64) {
        self.used.get(jti).copied().unwrap_or((0, 0.0))
    }

    /// Usage of every allowance, to save between runs.
    pub fn snapshot(&self) -> BTreeMap<String, (u32, f64)> {
        self.used.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// Restore usage saved by [`Ledger::snapshot`].
    pub fn restore(&mut self, usage: impl IntoIterator<Item = (String, (u32, f64))>) {
        self.used.extend(usage);
    }
}

fn read_entry(root: &Claims) -> Result<Entry, Refusal> {
    let mut entries = root.details_of_type(ALLOWANCE_TYPE);
    let raw = entries.next().ok_or(Refusal::NotAnAllowance)?;
    if entries.next().is_some() {
        return Err(Refusal::BadAllowance("more than one allowance entry".into()));
    }
    let entry: Entry = serde_json::from_value(raw.clone()).map_err(|e| Refusal::BadAllowance(e.to_string()))?;
    if entry.v != ALLOWANCE_VERSION {
        return Err(Refusal::BadAllowance(format!("unsupported version {}", entry.v)));
    }
    if !entry.cap.is_finite() || entry.cap < 0.0 {
        return Err(Refusal::BadAllowance("cap not finite".into()));
    }
    Ok(entry)
}

/// Admit a call made under an allowance. `owner` is the key that signed it and
/// the only trust anchor. The AAT check enforces the tool, payee and per-call
/// amount; the ledger enforces the call count and the cumulative cap. On
/// success the call is recorded and returned as an [`Admitted`].
pub fn admit(
    tool: &str,
    args: &Value,
    presentation: &Presentation,
    owner: &Jwk,
    now: i64,
    ledger: &mut Ledger,
) -> Result<Admitted, Refusal> {
    let anchors = [owner.clone()];
    let policy = Policy { trust_anchors: &anchors, audience: None, now };
    let verified = aat::verify(presentation, &policy, tool, args).map_err(|e| Refusal::NotAllowed(e.0))?;

    let entry = read_entry(&verified.root)?;
    let jti = verified.root.jti.clone();
    let mut usage = ledger.usage(&jti);

    if usage.0 >= entry.calls {
        return Err(Refusal::CallsExhausted);
    }
    usage.0 += 1;

    let amount = args
        .get("amount")
        .and_then(Value::as_f64)
        .filter(|a| a.is_finite() && *a >= 0.0)
        .ok_or(Refusal::AmountInvalid)?;
    if usage.1 + amount > entry.cap {
        return Err(Refusal::CapExceeded);
    }
    usage.1 += amount;

    ledger.replay.check(&verified, now).map_err(|e| Refusal::NotAllowed(e.0))?;
    ledger.used.insert(jti.clone(), usage);

    Ok(Admitted { tool: tool.to_string(), params: args.clone(), allowance: jti })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleimesh_aat::pop;

    const NOW: i64 = 1_800_000_000;

    fn owner() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }
    fn agent() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }
    fn jwk(sk: &SigningKey) -> Jwk {
        Jwk::from_key(&sk.verifying_key())
    }
    fn env() -> Envelope {
        Envelope::new(jwk(&agent()), "pay", "demo", 5.0, 3, 3600)
    }
    fn token() -> String {
        issue(&owner(), "urn:owner:you", &env(), NOW).unwrap()
    }
    fn call(token: &str, to: &str, amount: f64, led: &mut Ledger) -> Result<Admitted, Refusal> {
        let args = json!({ "to": to, "amount": amount });
        let p = Presentation { chain: vec![token.to_string()], pop: pop(&agent(), token, "pay", &args, None, NOW).unwrap() };
        admit("pay", &args, &p, &jwk(&owner()), NOW, led)
    }

    #[test]
    fn admits_inside_the_allowance() {
        let t = token();
        let mut led = Ledger::new();
        let a = call(&t, "demo", 2.0, &mut led).unwrap();
        assert_eq!(a.tool(), "pay");
        let jti = aat::inspect(&t).unwrap().jti;
        assert_eq!(a.allowance(), jti);
        assert_eq!(led.usage(&jti), (1, 2.0));
    }

    #[test]
    fn refuses_a_different_payee() {
        assert!(matches!(call(&token(), "attacker", 1.0, &mut Ledger::new()), Err(Refusal::NotAllowed(_))));
    }

    #[test]
    fn refuses_a_per_call_amount_over_the_max() {
        assert!(matches!(call(&token(), "demo", 9.0, &mut Ledger::new()), Err(Refusal::NotAllowed(_))));
    }

    #[test]
    fn the_cumulative_cap_holds() {
        let t = token();
        let mut led = Ledger::new();
        assert!(call(&t, "demo", 3.0, &mut led).is_ok());
        assert_eq!(call(&t, "demo", 2.5, &mut led), Err(Refusal::CapExceeded));
        assert!(call(&t, "demo", 2.0, &mut led).is_ok());
    }

    #[test]
    fn the_call_count_holds() {
        let t = token();
        let mut led = Ledger::new();
        for _ in 0..3 {
            assert!(call(&t, "demo", 0.0, &mut led).is_ok());
        }
        assert_eq!(call(&t, "demo", 0.0, &mut led), Err(Refusal::CallsExhausted));
    }

    #[test]
    fn a_replayed_call_is_refused() {
        let t = token();
        let mut led = Ledger::new();
        let args = json!({ "to": "demo", "amount": 1.0 });
        let p = Presentation { chain: vec![t.clone()], pop: pop(&agent(), &t, "pay", &args, None, NOW).unwrap() };
        assert!(admit("pay", &args, &p, &jwk(&owner()), NOW, &mut led).is_ok());
        assert!(matches!(admit("pay", &args, &p, &jwk(&owner()), NOW, &mut led), Err(Refusal::NotAllowed(_))));
    }

    #[test]
    fn only_the_owner_who_signed_it_is_honored() {
        // A token signed by the real owner, verified against a stranger as the
        // trust anchor, grants nothing: anyone can mint a token, only the
        // owner's key is trusted.
        let t = token();
        let stranger = jwk(&SigningKey::from_bytes(&[9u8; 32]));
        let args = json!({ "to": "demo", "amount": 1.0 });
        let p = Presentation { chain: vec![t.clone()], pop: pop(&agent(), &t, "pay", &args, None, NOW).unwrap() };
        assert!(matches!(admit("pay", &args, &p, &stranger, NOW, &mut Ledger::new()), Err(Refusal::NotAllowed(_))));
    }

    #[test]
    fn an_envelope_round_trips_and_shows_a_card() {
        let e = env();
        let back: Envelope = serde_json::from_value(serde_json::to_value(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        assert!(e.card()[0].contains("\"demo\""));
    }
}

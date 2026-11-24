//! The 5-minute "wow": give an agent an allowance, watch it spend inside the
//! limit, get cut off at the cap, and print a receipt. No real money — "pay" is
//! a demo tool and every amount is a number. Run it:
//!
//!   cargo run -p cleimesh-allowance --example wow
//!
//! The headlines are all one failure: an agent that did more than it was told —
//! paid the wrong payee or too much, sent the email, changed the booking — and
//! no one could prove the limit or catch it. The control is the same for any
//! tool an agent calls on its own: the limit lives outside the agent, and every
//! call leaves a record. "pay" here stands in for any such tool.

use cleimesh_aat::{pop, Jwk, Presentation, SigningKey};
use cleimesh_allowance::{admit, issue, Envelope, Ledger, Refusal};
use serde_json::json;

const NOW: i64 = 1_800_000_000;
const CAP: f64 = 5.00;

fn main() {
    println!("An agent acting on its own: a payment, an email, a booking change.");
    println!("The limit lives outside it, and every call leaves a record. Here, money:\n");

    // You (owner) and the agent you are handing an allowance to.
    let owner = SigningKey::from_bytes(&[1u8; 32]);
    let agent = SigningKey::from_bytes(&[2u8; 32]);
    let owner_jwk = Jwk::from_key(&owner.verifying_key());

    let env = Envelope::new(Jwk::from_key(&agent.verifying_key()), "pay", "demo", CAP, 5, 3600);

    println!("$ cleimesh allowance grant --max '${CAP:.2}' --tool pay --to demo --calls 5\n");
    println!("  You are signing an allowance. The agent may, on its own:");
    for line in env.card() {
        println!("    {line}");
    }
    println!("    [sign? y]  ->  allowance.json written, signed.\n");

    let token = issue(&owner, &env, NOW).expect("the owner signs the allowance");

    println!("$ cleimesh mcp wrap --allowance allowance.json --owner owner.pub.json --agent agent.key -- demo-pay-server");
    println!("  the agent now acts on its own; cleimesh enforces the allowance from outside it.\n");

    let mut ledger = Ledger::new();
    let jti = cleimesh_aat::inspect(&token).unwrap().jti;
    let mut pay = |to: &str, amount: f64| {
        let args = json!({ "to": to, "amount": amount });
        let before = ledger.usage(&jti).1;
        let p = Presentation { chain: vec![token.clone()], pop: pop(&agent, &token, "pay", &args, None, NOW).unwrap() };
        match admit("pay", &args, &p, &owner_jwk, NOW, &mut ledger) {
            Ok(_) => {
                let spent = ledger.usage(&jti).1;
                println!("  agent> pay {to} ${amount:.2}   ->  ok. spent ${spent:.2} of ${CAP:.2}.");
            }
            Err(Refusal::CapExceeded) => {
                println!("  agent> pay {to} ${amount:.2}   ->  refused: over the ${CAP:.2} allowance, ${:.2} left.", CAP - before);
            }
            Err(Refusal::CallsExhausted) => {
                println!("  agent> pay {to} ${amount:.2}   ->  refused: out of calls on this allowance.");
            }
            Err(Refusal::NotAllowed(_)) => {
                println!("  agent> pay {to} ${amount:.2}   ->  refused: payee {to:?} is not in the allowance.");
            }
            Err(e) => println!("  agent> pay {to} ${amount:.2}   ->  refused: {e}."),
        }
    };

    pay("demo", 2.00);
    pay("demo", 2.50);
    pay("demo", 2.00); // over the cap
    pay("attacker", 0.50); // wrong payee
    pay("demo", 0.50); // fits in the remaining $0.50

    let (calls, spent) = ledger.usage(&jti);
    println!("\n$ cat receipts.jsonl   # the append-only log cleimesh wrote beside the wrap");
    println!("  {calls} payments admitted, ${spent:.2} total, to demo.");
    println!("  every call recorded: tool, argument hash, and outcome (admitted or which limit refused it).");
    println!("  the agent acted on its own, never went over ${CAP:.2}, and left a record of every attempt.");
}

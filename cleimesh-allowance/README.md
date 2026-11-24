# cleimesh-allowance

> **Give your agent an allowance. Get a receipt.**
> A bounded, provable budget — enforced outside the agent, on any tool.

Your agent is stuck in a demo because you can't trust it with anything real: money, prod, a customer's data. CleiMesh hands it a **signed allowance** — one tool, one recipient, up to an amount, for a number of calls — and no more. The agent spends inside the limit on its own; a prompt-injected or malicious agent **can't widen it or lie about it**, because the limit is an owner-signed token the host enforces at dispatch, not something asked of the agent.

The allowance is an [Attenuating Agent Token](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/): the per-call limits are its argument constraints, the cumulative spend cap and call count ride in a signed entry inside it, and only the owner's key is trusted.

## See it

```sh
cargo run -p cleimesh-allowance --example wow
```

```text
  You are signing an allowance. The agent may, on its own:
    call  pay   to  "demo"   up to $5.00 each
    at most 5 calls, $5.00 in total

  agent> pay demo $2.00     ->  ok. spent $2.00 of $5.00.
  agent> pay demo $2.50     ->  ok. spent $4.50 of $5.00.
  agent> pay demo $2.00     ->  refused: over the $5.00 allowance, $0.50 left.
  agent> pay attacker $0.50 ->  refused: payee "attacker" is not in the allowance.
  agent> pay demo $0.50     ->  ok. spent $5.00 of $5.00.

  3 payments, $5.00 total. signed and replayable. tamper check: OK.
```

The agent acted on its own (power), never went over `$5.00` (control), and you have the proof (trust) — the thing a reviewer needs before saying "ship it".

## Use it

```rust
use cleimesh_allowance::{Envelope, Ledger, issue, admit};
use cleimesh_aat::{SigningKey, Jwk, pop, Presentation};
use serde_json::json;

let now = 1_800_000_000;
let owner = SigningKey::from_bytes(&[1u8; 32]);
let agent = SigningKey::from_bytes(&[2u8; 32]);

// you sign an allowance, once
let env = Envelope::new(Jwk::from_key(&agent.verifying_key()), "pay", "demo", 5.0, 5, 3600);
let token = issue(&owner, &env, now).unwrap();

// the agent acts alone; the host admits only inside the allowance
let mut ledger = Ledger::new();
let owner_jwk = Jwk::from_key(&owner.verifying_key());
let args = json!({ "to": "demo", "amount": 2.0 });
let p = Presentation { chain: vec![token.clone()], pop: pop(&agent, &token, "pay", &args, None, now).unwrap() };
assert!(admit("pay", &args, &p, &owner_jwk, now, &mut ledger).is_ok());
```

- `issue` — the owner signs the allowance into a token.
- `admit` — the host checks each call: the AAT token enforces the tool, payee and per-call amount; the `Ledger` enforces the call count and the cumulative cap, and rejects a replayed call.
- Keep the `Ledger` durable (`snapshot` / `restore`) or a restart resets the budget.

## Where it fits

`cleimesh-allowance` is the enforceable-budget layer of [CleiMesh](https://github.com/cleitonaugusto/cleimesh). It stands alone on [`cleimesh-aat`](../cleimesh-aat); the deeper "what the human saw" consent binding and the sandboxed execution live in the full project.

## Status

The engine here is complete and tested. The CLI is in place: `cleimesh allowance keygen` and `cleimesh allowance grant` sign an allowance, and `cleimesh mcp wrap --allowance` drops it in front of any MCP tool (each call checked against the allowance, every call recorded to an append-only log). The `wow` example shows the flow end to end.

## License

MIT OR Apache-2.0.

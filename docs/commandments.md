# The Ten Commandments of the Agent Under Control

[Português](mandamentos.md)

AI agents read email, open files, call APIs and hand work to other agents. These are the principles CleiMesh follows to keep that under control. They apply to any agent system, with or without CleiMesh.

**Golden rule: a commandment without a test is marketing.** Each commandment below names the tests that fail if it is broken, and `every_commandment_names_tests_that_exist` (`cleimesh-cli/tests/commandments.rs`) fails if any of those tests disappears.

---

### 1. The permission is the cage.
What was signed is exactly what the sandbox enforces. The permission is not paperwork next to the run: it is the configuration of the place where the tool runs.

Tests: `same_tool_sees_only_the_directory_its_token_grants`, `symlink_inside_a_grant_cannot_lead_outside_it` (`cleimesh-p2p/tests/grants.rs`).

### 2. Nothing by default.
No written permission, no access: no directory, no network. A field the executor does not understand is refused, since it may be a restriction it could not enforce.

Tests: `token_without_grants_runs_with_no_directory`, `raised_limit_and_unknown_grant_field_are_refused` (`cleimesh-p2p/tests/grants.rs`).

### 3. Delegation only narrows.
A subagent never gets more than whoever delegated to it: no wider directory, write, network or limit.

Tests: `subagent_cannot_reach_what_its_parent_can`, `derived_grant_wider_than_its_parent_is_refused` (`cleimesh-p2p/tests/grants.rs`), `accepted_chain_never_widens` (`cleimesh-p2p/tests/grant_properties.rs`, 20,000 random chains).

### 4. The executor decides, not the agent.
The rule is enforced outside the process that can be fooled. The agent does not hold its own label, does not pick its own policy, and cannot switch identities to escape it. An agent with a shell runs as another OS user than the executor, so it can't reach the executor's key, log or labels either.

Tests: `taint_blocks_clean_only_tools_through_the_cli` (`cleimesh-cli/tests/cli.rs`, a real executor: another token for the same key is still blocked), `mcp_serve_forwards_to_a_node_and_holds_nothing_of_it` (`cleimesh-cli/tests/mcp.rs`, the agent's side holds nothing of the executor).

### 5. What came in dirty stays dirty.
Outside content (email, a web page, a shared folder) taints the whole delegation chain. Delegating to a fresh subagent does not launder it.

Tests: `after_reading_untrusted_content_the_agent_cannot_act_on_the_world`, `delegating_to_a_fresh_subagent_does_not_launder_the_taint`, `a_subagent_reading_mail_taints_the_agents_above_it`, `a_subagent_cannot_shed_the_flags`, `a_new_token_for_the_same_key_is_still_refused`, `the_refusal_does_not_depend_on_what_the_next_call_carries`, `any_forest_and_any_order_follow_the_rule` (`cleimesh-p2p/tests/taint.rs`).

### 6. Only a human washes, and the washing is recorded.
No agent declares itself clean. Clearing is a human act, with a reason, in a signed receipt; without the receipt the taint stays, across restarts too.

Tests: `taint_survives_a_restart_and_only_a_recorded_clearing_lifts_it`, `the_taint_survives_a_restart_even_without_the_result_receipt` (`cleimesh-p2p/tests/taint.rs`).

### 7. Every action leaves a receipt.
Allowed and denied calls produce signed, chained receipts. Editing, removing or reordering a line is pointed out on verification. A receipt holds digests, never the content.

Tests: `allowed_and_denied_calls_leave_verifiable_receipts` (`cleimesh-p2p/tests/receipts.rs`), `edited_line_is_pointed_out`, `removed_interior_line_is_pointed_out`, `reordered_lines_are_pointed_out` (`cleimesh-receipt/tests/receipts.rs`).

### 8. The proof can be redone.
Don't trust the receipt: replay it. Whoever doubts runs the same call again and checks the result, without trusting whoever ran it.

Tests: `calls_replay_from_their_receipts`, `a_signed_but_false_result_is_caught_by_replay`, `a_log_recorded_on_another_machine_replays_here` (`cleimesh-p2p/tests/replay.rs`).

### 9. Keep only what you used.
A permission should shrink to what was needed (data minimization; LGPD art. 6, III; GDPR art. 5(1)(c)). The system shows what the agent actually used and proposes a smaller permission; a human approves it.

Tests: `ten_calls_in_docs_suggest_a_token_for_docs_only` (`cleimesh-p2p/tests/fs_observed.rs`), `audit_suggest_proposes_what_the_agent_used_and_derive_takes_it` (`cleimesh-cli/tests/mcp.rs`).

### 10. When in doubt, fail closed.
If the rule cannot be enforced or the proof cannot be recorded, the action does not happen. Never fall back to a weaker mode.

Tests: `call_is_refused_when_its_receipt_cannot_be_written` (`cleimesh-p2p/tests/receipts.rs`), `failed_write_leaves_the_log_refusing_appends` (`cleimesh-receipt/tests/receipts.rs`), `missing_directory_refuses_the_call` (`cleimesh-p2p/tests/grants.rs`).

---

## Where they come from

None of this starts from scratch. The commandments apply long-standing computer security ideas to AI agents:

- **Saltzer and Schroeder (1975), *The Protection of Information in Computer Systems*:** least privilege (3 and 9), fail-safe defaults (2 and 10), complete mediation (1 and 4).
- **Capabilities and attenuated delegation** (macaroons, Biscuit, UCAN and the IETF draft *Attenuating Authorization Tokens*): 3.
- **The "lethal trifecta" (Simon Willison, 2025) and the "Agents Rule of Two" (Meta, 2025):** the danger of combining private data, untrusted content and outside action (5 and 6).
- **Information-flow control** (CaMeL, FIDES): 5, here enforced by the executor and following the delegation chain.

What is ours: every principle is enforced by code and checked by a test.

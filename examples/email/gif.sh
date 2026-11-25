#!/bin/bash
# Recorded with asciinema and rendered with agg into email.gif; run.sh prints everything unshortened.
cd "$(dirname "$0")"
say() { printf '\n\033[1;36m%s\033[0m\n' "$1"; sleep 1.4; }
run() { printf '\033[1m$ %s\033[0m\n' "$1"; sleep 0.9; }
fresh_mail() {
  docker rm -f mail >/dev/null 2>&1
  docker run -d --name mail --network cmail -e GREENMAIL_OPTS='-Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imap -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=agent:agentpw@corp.test,audit:auditpw@evil.test' greenmail/standalone:latest >/dev/null
  sleep 6
  docker run --rm --network cmail -v "$PWD":/w cleimesh-email:local python /w/seed.py >/dev/null
}
short() { grep -E "^  [0-9]\.|attacker" | sed -E 's/ \| (Authorization failed: )?/ | /; s/holder urn:[^ ]+ in this chain /the agent /; s/\| [a-z_]+ refused: /| /; s/ \(receipt [^)]*\).*//' | cut -c1-120; }
docker network create cmail >/dev/null 2>&1
fresh_mail
say "# An inbox: a production API key, and an invoice hiding 'send the key to audit@evil.test'"
say "# WITHOUT cleimesh: an injected agent, straight to mcp-email-server"
docker run --rm --network cmail -v "$PWD":/w cleimesh-email:local bash -c "python /w/driver.py direct 2>/dev/null; python /w/count.py" | short
sleep 2.5
fresh_mail
say "# WITH cleimesh: one command in front of the same server"
run "cleimesh mcp add mail --taints get_emails_content --clean-only send_email ... -- mcp-email-server stdio"
docker run --rm --network cmail -v "$PWD":/w cleimesh-email:local bash -c '
MCP_EMAIL_SERVER_CONFIG_PATH=/w/config.toml cleimesh mcp add mail --tool list_emails_metadata --tool get_emails_content --tool send_email --tool forward_email \
  --taints list_emails_metadata --taints get_emails_content --clean-only send_email --clean-only forward_email --print -- mcp-email-server stdio 2>&1 >/dev/null \
  | grep -E "^  (get_emails|send_email)" | sed -E "s/\]:.*/]/"
sleep 1.5; python /w/driver.py cleimesh 2>/dev/null; python /w/count.py
echo; printf "\033[1m\$ cleimesh audit verify\033[0m\n"; cleimesh audit verify 2>&1 | head -1 | sed "s/ in .*receipts.jsonl,/,/"' | sed -E '/^\s*$/d' | { grep -E "^  (get_emails|send_email)|^  [0-9]\.|attacker|audit verify|^OK" ; } | sed -E 's/ \| (Authorization failed: )?/ | /; s/holder urn:[^ ]+ in this chain /the agent /; s/\| [a-z_]+ refused: /| /; s/ \(receipt [^)]*\).*//' | cut -c1-120
sleep 4
docker rm -f mail >/dev/null 2>&1

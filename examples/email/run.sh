#!/bin/bash
# Same scripted agent against a real IMAP/SMTP server (GreenMail), first straight to mcp-email-server, then behind cleimesh.
cd "$(dirname "$0")"
fresh_mail() {
  docker rm -f mail >/dev/null 2>&1
  docker run -d --name mail --network cmail -e GREENMAIL_OPTS='-Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imap -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=agent:agentpw@corp.test,audit:auditpw@evil.test' greenmail/standalone:latest >/dev/null
  sleep 6
}
IN() { docker run --rm --network cmail -v $PWD:/w cleimesh-email:local bash -c "$1"; }
docker network create cmail >/dev/null 2>&1
docker build -q -t cleimesh-email:local . >/dev/null
fresh_mail
echo "== WITHOUT cleimesh: the agent talks to mcp-email-server directly"
IN "python /w/seed.py >/dev/null && python /w/driver.py direct 2>/dev/null && python /w/count.py"
fresh_mail
echo; echo "== WITH cleimesh: one command in front of the same server"
IN 'python /w/seed.py >/dev/null
echo "\$ cleimesh mcp add mail --tool list_emails_metadata --tool get_emails_content --tool send_email --tool forward_email --taints list_emails_metadata --taints get_emails_content --clean-only send_email --clean-only forward_email --print -- mcp-email-server stdio"
MCP_EMAIL_SERVER_CONFIG_PATH=/w/config.toml cleimesh mcp add mail --tool list_emails_metadata --tool get_emails_content --tool send_email --tool forward_email \
  --taints list_emails_metadata --taints get_emails_content --clean-only send_email --clean-only forward_email --print -- mcp-email-server stdio 2>&1 | grep -E "^Token|^It grants|^  [a-z_]+ |behind one wrapper"
python /w/driver.py cleimesh 2>/dev/null
python /w/count.py
echo "\$ cleimesh taint list"; cleimesh taint list
echo "\$ cleimesh audit verify"; cleimesh audit verify'
docker rm -f mail >/dev/null 2>&1

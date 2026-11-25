import imaplib
m = imaplib.IMAP4("mail", 3143); m.login("audit", "auditpw"); m.select("INBOX")
n = len(m.search(None, "ALL")[1][0].split()); print(f"  mails in audit@evil.test (the attacker): {n}")

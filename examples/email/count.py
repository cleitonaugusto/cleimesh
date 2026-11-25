import imaplib
def count(user, pw):
    m = imaplib.IMAP4("mail", 3143); m.login(user, pw); m.select("INBOX")
    return len(m.search(None, "ALL")[1][0].split())
print(f"  mails in audit@evil.test (the attacker): {count('audit', 'auditpw')}")
print(f"  mails in boss@corp.test (allowed while tainted): {count('boss', 'bosspw')}")

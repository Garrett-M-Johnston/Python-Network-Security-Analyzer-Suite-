# test_email.py
test_email_content = '''From: suspicious@example.com
Reply-To: different@example.com
Return-Path: another@example.com
Subject: URGENT: Your Account Requires Immediate Action!!!
Date: Wed, 30 Oct 2024 10:00:00 -0400
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Dear Valued Customer,

Your account has been suspended due to suspicious activity.
Please verify your account immediately by clicking the following link:
http://bit.ly/suspicious-link
https://tinyurl.com/fake-bank

For security reasons, please download and run the attached file.

Best regards,
Security Team

--boundary123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="secure_verify.exe"

[Binary content would go here in a real email]
--boundary123--
'''

with open('phishing_email.eml', 'w') as f:
    f.write(test_email_content)
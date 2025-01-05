#!/usr/bin/env python3
import argparse
import configparser
import smtplib
from email.message import EmailMessage

# init arg parser and parse
parser = argparse.ArgumentParser(description='Email challenge sender for NDNCERT CA')
parser.add_argument('recipient', help='email address of the recipient')
parser.add_argument('secret', help='secret code for the challenge')
parser.add_argument('ca_name', help='name of the certificate authority')
parser.add_argument('cert_name', help='name of the certificate being requested')
args = parser.parse_args()

vars = {
    'ca_name': args.ca_name,
    'cert_name': args.cert_name,
    'recipient': args.recipient,
    'secret': args.secret,
}

# open config file
confParser = configparser.ConfigParser(empty_lines_in_values=True,
                                       interpolation=configparser.ExtendedInterpolation())
confParser.read('@SYSCONFDIR@/ndncert/ndncert-mail.conf')

# read smtp settings
encrypt_mode = confParser.get('ndncert.smtp', 'encrypt_mode')
server = confParser.get('ndncert.smtp', 'smtp_server')
port = confParser.get('ndncert.smtp', 'smtp_port')
username = confParser.get('ndncert.smtp', 'smtp_user')
password = confParser.get('ndncert.smtp', 'smtp_password')

# read email settings
from_addr = confParser.get('ndncert.email', 'from', vars=vars)
subject = confParser.get('ndncert.email', 'subject', vars=vars)
text = confParser.get('ndncert.email', 'text_template', vars=vars)
html = confParser.get('ndncert.email', 'html_template', vars=vars)

# create email message
msg = EmailMessage()
msg['From'] = from_addr
msg['To'] = args.recipient
msg['Subject'] = subject
msg.set_content(text)
msg.add_alternative(html, subtype='html')

# connect to SMTP server
if encrypt_mode == 'ssl':
    context = smtplib.SMTP_SSL(server, port, timeout=10)
elif encrypt_mode == 'starttls':
    context = smtplib.SMTP(server, port, timeout=10)
    context.starttls()
elif encrypt_mode == 'none':
    context = smtplib.SMTP(server, port, timeout=10)
else:
    raise ValueError(f'Invalid encrypt_mode: {encrypt_mode}')

with context as smtp:
    if username and password:
        smtp.login(username, password)
    # send email
    smtp.send_message(msg)

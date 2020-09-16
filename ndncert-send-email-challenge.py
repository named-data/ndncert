#!/usr/bin/env python
import sys
import smtplib
import argparse
import socket
try: # python3
    from configparser import ConfigParser
except ImportError: # python2
    from ConfigParser import SafeConfigParser as ConfigParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

socket.setdefaulttimeout(10)

# init arg parser and parse
parser = argparse.ArgumentParser(description='Email-challenge-sender for NDNCERT')
parser.add_argument("email", help="the receiver email address")
parser.add_argument("secret", help="the secret of the challenge")
parser.add_argument("caName", help="the CA name")
parser.add_argument("certName", help="the Ceritifcate being requested")
args = parser.parse_args()

# open config
confParser = ConfigParser()
confParser.read('@SYSCONFDIR@/ndncert/ndncert-mail.conf')

# read smtp settings
encrypt_mode = confParser.get('ndncert_smtp_settings', "ENCRYPT_MODE")
server = confParser.get('ndncert_smtp_settings', 'SMTP_SERVER')
port = confParser.get('ndncert_smtp_settings', 'SMTP_PORT')
username = confParser.get('ndncert_smtp_settings', 'SMTP_USER')
password = confParser.get('ndncert_smtp_settings', 'SMTP_PASSWORD')

# read email settings
msg_from = confParser.get('ndncert_email_settings', 'MAIL_FROM')
subject = confParser.get('ndncert_email_settings', 'SUBJECT')
text = confParser.get('ndncert_email_settings', 'TEXT_TEMPLATE').format(args.secret, args.caName, args.certName)
html = confParser.get('ndncert_email_settings', 'HTML_TEMPLATE').format(args.secret, args.caName, args.certName)

# form email message
msg = MIMEMultipart('alternative')
msg.attach(MIMEText(text, 'plain'))
msg.attach(MIMEText(html, 'html'))
msg['From'] = msg_from
msg['To'] = args.email
msg['Subject'] = subject

# send email
if encrypt_mode == 'ssl':
    smtp_server = smtplib.SMTP_SSL(server, port)
else: # none or tls
    smtp_server = smtplib.SMTP(server, port)

if encrypt_mode != 'none':
    smtp_server.ehlo()
    if encrypt_mode == 'tls':
        smtp_server.starttls()

if username != '' and password != '':
    smtp_server.login(username, password)

smtp_server.sendmail(msg_from, args.email, msg.as_string())
smtp_server.close()
sys.exit()

from dotenv import load_dotenv
import os, smtplib, traceback

# Load .env located next to this script (robust to current working directory)
here = os.path.dirname(__file__)
dotenv_path = os.path.join(here, '.env')
load_dotenv(dotenv_path=dotenv_path)

host = os.getenv('SMTP_HOST')
port = int(os.getenv('SMTP_PORT') or '587')
user = os.getenv('SMTP_USERNAME')
pwd = os.getenv('SMTP_PASSWORD')
sender = os.getenv('SMTP_SENDER')
use_tls = os.getenv('SMTP_USE_TLS','false').lower() == 'true'

print('Using SMTP settings:')
print('HOST=', host)
print('PORT=', port)
print('USERNAME=', user)

try:
    print('\nConnecting...')
    s = smtplib.SMTP(host, port, timeout=20)
    s.set_debuglevel(1)

    s.ehlo()

    if use_tls:
        print('\nStarting TLS...')
        s.starttls()
        s.ehlo()

    print('\nLogging in...')
    s.login(user, pwd)

    print('\nSMTP connection and login succeeded')
    s.quit()

except Exception:
    print('\nException during SMTP test:')
    traceback.print_exc()
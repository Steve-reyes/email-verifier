import re
import os
import time
import csv
import io
import socket
import dns.resolver
import dns.exception
import requests
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ---- DISPOSABLE DOMAIN LIST ----
DISPOSABLE = {
    'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
    'temp-mail.org', 'throwaway.email', 'yopmail.com', 'sharklasers.com',
    'grr.la', 'trashmail.com', 'maildrop.cc', 'getairmail.com',
    'tempinbox.com', 'emailondeck.com', 'burnermail.io', 'hmail.us',
    'spam4.me', 'mailexpire.com', 'mailmetrash.com', 'discard.email',
}

ROLE_PREFIXES = {'info', 'sales', 'support', 'admin', 'contact', 'help', 'hello', 'team', 'noreply', 'no-reply', 'enquiries', 'mail', 'office', 'marketing'}
COMMON_TYPOS = {
    'gmial.com':'gmail.com', 'yaho.com':'yahoo.com', 'hotmai.com':'hotmail.com',
    'hotmail.co':'hotmail.com', 'gnail.com':'gmail.com', 'gmil.com':'gmail.com',
    'gamil.com':'gmail.com', 'yahooo.com':'yahoo.com', 'outloo.com':'outlook.com',
    'outlok.com':'outlook.com', 'aol.co':'aol.com', 'msn.co':'msn.com',
    'hotmaiil.com':'hotmail.com', 'yhoo.com':'yahoo.com',
}
SPAM_TRAPS = {'spamtrap@example.com', 'abuse@spamtrap.net', 'test@mail-tester.com'}
HIBP_API = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=true'
USER_AGENT = 'EmailVerifier/1.0'

def validate_syntax(email):
    pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, email.strip()))

def get_mx(domain, timeout=5):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, 'MX')
        records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
        return records[0][1] if records else None
    except Exception:
        return None

def has_a_record(domain, timeout=5):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.resolve(domain, 'A')
        return True
    except Exception:
        return False

def smtp_verify(mx_host, email, timeout=10):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((mx_host, 25))
        resp = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.sendall(b'EHLO verifier\r\n')
        sock.recv(1024)
        sock.sendall(f'MAIL FROM: <checker@{socket.gethostname()}>\r\n'.encode())
        sock.recv(1024)
        t0 = time.time()
        sock.sendall(f'RCPT TO: <{email}>\r\n'.encode())
        resp = sock.recv(1024).decode('utf-8', errors='ignore')
        elapsed = time.time() - t0
        sock.sendall(b'QUIT\r\n')
        sock.close()
        return resp.strip()[:3], elapsed
    except Exception as e:
        return str(e), 0

def smtp_vrfy(mx_host, email, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((mx_host, 25))
        sock.recv(1024)
        sock.sendall(b'EHLO verifier\r\n')
        sock.recv(1024)
        sock.sendall(f'VRFY {email}\r\n'.encode())
        resp = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.sendall(b'QUIT\r\n')
        sock.close()
        return resp[:3] == '250'
    except Exception:
        return False

def dual_rcpt_test(mx_host, real_email, fake_email, timeout=10):
    """Send real + fake. Both accepted = catch-all."""
    result = {'catch_all': False, 'details': ''}
    for label, addr in [('fake', fake_email), ('real', real_email)]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((mx_host, 25))
            sock.recv(1024)
            sock.sendall(b'EHLO verifier\r\n')
            sock.recv(1024)
            sock.sendall(f'MAIL FROM: <checker@{socket.gethostname()}>\r\n'.encode())
            sock.recv(1024)
            sock.sendall(f'RCPT TO: <{addr}>\r\n'.encode())
            r = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.sendall(b'QUIT\r\n')
            sock.close()
            result[label] = r[:3]
            result['details'] += f'{label}={r[:3]} '
        except Exception as e:
            result[label] = str(e)
    if result.get('fake') == '250' and result.get('real') == '250':
        result['catch_all'] = True
    return result

def gravatar_check(email):
    import hashlib
    h = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        r = requests.get(f'https://www.gravatar.com/{h}.json', timeout=5, headers={'User-Agent': USER_AGENT})
        return r.status_code == 200
    except Exception:
        return False

def hibp_check(email):
    try:
        r = requests.get(HIBP_API % email, timeout=10, headers={'User-Agent': USER_AGENT, 'hibp-api-key': ''})
        if r.status_code == 200:
            return len(r.json())
        return 0
    except Exception:
        return -1

def typo_check(domain):
    for wrong, correct in COMMON_TYPOS.items():
        if domain == wrong:
            return {'has_typo': True, 'suggestion': correct}
    return {'has_typo': False, 'suggestion': ''}

def verify_one(email_raw):
    email = email_raw.strip().lower()
    result = {'email': email, 'syntax_valid': False, 'mx': None, 'a_record': False,
              'disposable': False, 'role_based': False, 'smtp_status': '', 'smtp_time': 0,
              'vrfy': False, 'dual_rcpt': {}, 'gravatar': False, 'hibp_count': -1,
              'typo': {}, 'spam_trap': False, 'free_provider': False, 'valid': False}

    # 1. RFC Syntax
    if not validate_syntax(email):
        result['syntax_valid'] = False
        return result
    result['syntax_valid'] = True

    local, domain = email.split('@')
    result['typo'] = typo_check(domain)

    # 14. Free provider check
    free_domains = {'gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','msn.com','ymail.com','icloud.com','protonmail.com','gmx.com','zoho.com'}
    if domain in free_domains:
        result['free_provider'] = True

    # 4. Disposable + 5. Role
    if domain in DISPOSABLE:
        result['disposable'] = True
    if local in ROLE_PREFIXES:
        result['role_based'] = True

    # 13. Spam trap
    if email in SPAM_TRAPS:
        result['spam_trap'] = True

    # 2. MX Record
    mx = get_mx(domain)
    if mx:
        result['mx'] = mx
    else:
        result['mx'] = 'NO_MX'

    # 3. A Record fallback
    result['a_record'] = has_a_record(domain)

    # Cannot proceed without a mail exchanger
    if not mx or mx == 'NO_MX':
        return result

    # 6. SMTP RCPT TO
    status, elapsed = smtp_verify(mx, email)
    result['smtp_status'] = status
    result['smtp_time'] = round(elapsed, 2)

    # 7. Dual RCPT (catch-all detection)
    fake_local = local + 'xqzw9m'  # known fake
    fake_email = f'{fake_local}@{domain}'
    dr = dual_rcpt_test(mx, email, fake_email)
    result['dual_rcpt'] = dr

    # 8. SMTP VRFY
    result['vrfy'] = smtp_vrfy(mx, email)

    # 10. Gravatar
    result['gravatar'] = gravatar_check(email)

    # 11. HIBP
    result['hibp_count'] = hibp_check(email)

    # Overall verdict
    if status == '250':
        if dr.get('catch_all'):
            result['valid'] = True  # catch-all means likely valid
        else:
            result['valid'] = True
    elif status in ('550', '551', '552', '553', '450'):
        result['valid'] = False
    else:
        result['valid'] = None  # Unknown — grey area

    return result

def percent_mark(val):
    return '🟢' if val else ('🟡' if val is None else '🔴')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    raw = data.get('emails', '').strip()
    lines = [e.strip() for e in raw.replace(',', '\n').split('\n') if e.strip()]
    if not lines:
        return jsonify({'error': 'No emails provided'})

    results = []
    for line in lines:
        r = verify_one(line)
        results.append(r)

    # Summary
    total = len(results)
    valid = sum(1 for r in results if r['valid'] is True)
    invalid = sum(1 for r in results if r['valid'] is False)
    unknown = sum(1 for r in results if r['valid'] is None)

    return jsonify({
        'total': total,
        'valid': valid,
        'invalid': invalid,
        'unknown': unknown,
        'results': results,
    })

@app.route('/download', methods=['POST'])
def download():
    data = request.get_json()
    results = data.get('results', [])
    if not results:
        return jsonify({'error': 'No data'}), 400

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['Email', 'Valid', 'Syntax', 'MX', 'A Record', 'Disposable', 'Role Based',
                'SMTP Status', 'SMTP Time', 'VRFY', 'Catch-All',
                'Gravatar', 'HIBP Leaks', 'Typo', 'Typo Suggestion', 'Spam Trap', 'Free Provider'])

    for r in results:
        w.writerow([
            r['email'], r['valid'], r['syntax_valid'], r['mx'], r['a_record'],
            r['disposable'], r['role_based'], r['smtp_status'], r['smtp_time'],
            r['vrfy'], r['dual_rcpt'].get('catch_all', False),
            r['gravatar'], r['hibp_count'],
            r['typo'].get('has_typo', False), r['typo'].get('suggestion', ''),
            r['spam_trap'], r['free_provider'],
        ])

    return out.getvalue(), 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=verification_results.csv'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)

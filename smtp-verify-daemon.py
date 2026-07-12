#!/usr/bin/env python3
"""
SMTP Verification Daemon — runs on the port-25 VPS (RackNerd).
Accepts POST /verify, does the real SMTP RCPT TO check, returns result.
"""
import json
import socket
import time
import re
import dns.resolver
import dns.exception
from http.server import HTTPServer, BaseHTTPRequestHandler

HOST = '0.0.0.0'
PORT = 8081

# Caches
dns_cache = {}
HIBP_API = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=true'

# Rate limit tracking — skip domains that are temp-blocking
rate_limited_domains = {}
RATE_BACKOFF_SEC = 300  # 5 min cooldown for rate-limited domains


def get_mx(domain, timeout=3):
    if domain in dns_cache:
        return dns_cache[domain].get('mx')
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, 'MX')
        records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
        mx = records[0][1] if records else None
    except Exception:
        mx = None
    dns_cache[domain] = dns_cache.get(domain, {}) | {'mx': mx}
    return mx


def has_a_record(domain, timeout=3):
    if domain in dns_cache:
        return dns_cache[domain].get('a_record', False)
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.resolve(domain, 'A')
        a_rec = True
    except Exception:
        a_rec = False
    dns_cache[domain] = dns_cache.get(domain, {}) | {'a_record': a_rec}
    return a_rec


def smtp_check(email, mx_host, timeout=6, return_text=False):
    """Connect to MX, do EHLO/MAIL/RCPT. Returns (status_code, elapsed_seconds, response_text)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((mx_host, 25))
        sock.recv(1024)  # banner

        sock.sendall(b'EHLO verifier\r\n')
        sock.recv(1024)

        sock.sendall(f'MAIL FROM: <checker@verify.leadzap.io>\r\n'.encode())
        sock.recv(1024)

        t0 = time.time()
        sock.sendall(f'RCPT TO: <{email}>\r\n'.encode())
        resp = sock.recv(1024).decode('utf-8', errors='ignore')
        elapsed = time.time() - t0

        sock.sendall(b'QUIT\r\n')
        sock.close()

        status = resp.strip()[:3]
        return status, round(elapsed, 3), resp.strip() if return_text else ''
    except socket.timeout:
        return 'TIMEOUT', 0, ''
    except ConnectionRefusedError:
        return 'REFUSED', 0, ''
    except Exception as e:
        return f'ERR:{str(e)[:30]}', 0, ''


def catch_all_test(mx_host, real_email, timeout=5):
    """Dual RCPT test to detect catch-all."""
    fake_local = real_email.split('@')[0] + 'xqzw9m7k'
    fake_email = f'{fake_local}@{real_email.split("@")[1]}'
    results = {}
    for label, addr in [('fake', fake_email), ('real', real_email)]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((mx_host, 25))
            sock.recv(1024)
            sock.sendall(b'EHLO verifier\r\n')
            sock.recv(1024)
            sock.sendall(f'MAIL FROM: <checker@verify.leadzap.io>\r\n'.encode())
            sock.recv(1024)
            sock.sendall(f'RCPT TO: <{addr}>\r\n'.encode())
            r = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.sendall(b'QUIT\r\n')
            sock.close()
            results[label] = r[:3]
        except Exception:
            results[label] = 'ERR'
    is_catch_all = results.get('fake') == '250' and results.get('real') == '250'
    return {
        'catch_all': is_catch_all,
        'fake_status': results.get('fake', ''),
        'real_status': results.get('real', ''),
    }


class SMTPVerifyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/verify':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode()
            data = json.loads(body) if body else {}
            email = data.get('email', '').strip().lower()
            self._handle_verify(email)
        else:
            self._json_response(404, {'error': 'not found'})

    def do_GET(self):
        if self.path == '/health':
            self._json_response(200, {'status': 'ok', 'uptime': time.time()})
        else:
            self._json_response(404, {'error': 'not found'})

    def _handle_verify(self, email):
        result = {
            'email': email,
            'valid': None,
            'smtp_status': 'SKIPPED',
            'smtp_time': 0,
            'mx': None,
            'a_record': False,
            'catch_all': None,
            'rcp_response': '',
            'error': None,
        }

        if not email or '@' not in email:
            result['valid'] = False
            result['error'] = 'invalid email'
            return self._json_response(200, result)

        domain = email.split('@')[1]

        # Check if domain is rate-limited
        if domain in rate_limited_domains:
            if time.time() - rate_limited_domains[domain] < RATE_BACKOFF_SEC:
                result['valid'] = None
                result['smtp_status'] = 'RATE_LIMITED'
                result['error'] = 'domain rate-limited, cooling down'
                return self._json_response(200, result)

        mx = get_mx(domain)
        result['mx'] = mx or 'NO_MX'
        result['a_record'] = has_a_record(domain)

        if not mx:
            result['valid'] = False
            return self._json_response(200, result)

        # SMTP check — also capture the full response text
        status, elapsed, rcp_response = smtp_check(email, mx, return_text=True)
        result['smtp_status'] = status
        result['smtp_time'] = elapsed
        if rcp_response:
            result['rcp_response'] = rcp_response[:200]

        # Detect rate limiting
        if status in ('451', 'TIMEOUT') or status.startswith('ERR:'):
            rate_limited_domains[domain] = time.time()

        # Catch-all test (only if SMTP succeeded)
        if status == '250':
            # Don't test catch-all on gmail, O365, etc. — always fails
            free_big = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'protonmail.com'}
            if domain not in free_big:
                try:
                    ca = catch_all_test(mx, email)
                    result['catch_all'] = ca
                    if ca.get('catch_all'):
                        result['valid'] = None  # catch-all — can't verify individual
                        return self._json_response(200, result)
                except Exception:
                    pass

        # Determine validity
        if status == '250':
            result['valid'] = True
        elif status in ('550', '551', '552', '553'):
            rcp = result.get('rcp_response', '')
            if 'protocol' in rcp.lower() or 'tls' in rcp.lower() or '5.5.' in rcp or '5.7.' in rcp:
                result['valid'] = None  # protocol/TLS error, not a real reject
            else:
                result['valid'] = False
        elif status in ('450', '451', 'TIMEOUT'):
            result['valid'] = None  # try again later
        elif status.startswith('ERR:'):
            result['valid'] = None
        else:
            result['valid'] = None

        self._json_response(200, result)

    def _json_response(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        return  # quiet


if __name__ == '__main__':
    server = HTTPServer((HOST, PORT), SMTPVerifyHandler)
    print(f'SMTP Verify Daemon running on {HOST}:{PORT}')
    server.serve_forever()

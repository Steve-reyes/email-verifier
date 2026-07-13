import os, re, json, requests, time, socket, dns.resolver, hashlib, hmac, string
from flask import Flask, request, jsonify, render_template, Response, g
import sqlite3, csv, io, uuid
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('verifier')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
UPLOAD_DIR = 'uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'verifier.db')
SMTP_DAEMON_URL = 'http://192.255.136.177:8081/verify'
SMTP_DAEMON_TIMEOUT = 15

DUMMY_LOCALS = {
    'johndoe', 'testuser', 'test', 'user', 'username',
    'noreply', 'no-reply', 'mailer-daemon', 'postmaster',
    'webmaster', 'abuse', 'hostmaster', 'root', 'mail', 'email', 'hello', 'hi',
    'testaccount', 'demo', 'sample', 'example', 'placeholder', 'temp', 'temporary',
    'fake', 'null', 'void', 'empty', 'none', 'unknown', 'user1', 'user2',
    'user123', 'test123', 'guest', 'register', 'signup', 'newsletter', 'subscribe',
    'unsubscribe', 'spam', 'trash', 'junk', 'default', 'new', 'my', 'your',
    'some', 'any', 'every', 'no', 'yes', 'true', 'false', '1', '12', '123',
    '1234', '12345', '123456', '1234567', '12345678', '123456789', 'aaaa',
    'aa', 'a', 'b', 'c', 'x', 'y', 'z', 'abc', 'xyz', 'qwerty', 'asdf',
    'zxcv', 'pass', 'password', 'letmein', 'welcome', 'changeme',
}
PLACEHOLDER_DOMAINS = {
    'example.com', 'example.org', 'example.net', 'test.com', 'test.org',
    'test.net', 'domain.com', 'yourdomain.com', 'yourdomain.net',
    'mydomain.com', 'somedomain.com', 'placeholder.com', 'company.com',
    'yourcompany.com', 'email.com', 'mail.com', 'tempmail.com',
    'domain.net', 'domain.org',
}
LOW_QUALITY_DOMAINS = {
    'birdeye.com', 'mailservice.com',
    'facebook.com', 'facebookmail.com', 'fb.com', 'fbmail.com',
    'twitter.com', 'x.com', 'tweetmail.com',
    'instagram.com', 'insta.com',
    'linkedin.com', 'linkedinmail.com',
    'youtube.com', 'youtubemail.com',
    'google.com', 'googlemail.com', 'gmail.com',
    'yahoo.com', 'yahoomail.com', 'ymail.com',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'aol.com', 'aim.com',
    'icloud.com', 'me.com', 'mac.com',
    'protonmail.com', 'proton.me', 'pm.me',
    'zoho.com', 'zohomail.com',
    'yandex.com', 'yandex.ru',
    'mail.ru', 'inbox.ru', 'list.ru',
    'gmx.com', 'gmx.de',
    'tutanota.com', 'tutamail.com',
    'fastmail.com', 'fastmail.fm',
    'hey.com', 'envs.net',
    'migadu.com', 'runbox.com',
    'rediffmail.com', 'rediffmailpro.com',
    'hushmail.com', 'hush.com',
    'countermail.com', 'ctemplar.com',
    'startmail.com', 'startpage.com',
    'seznam.cz', 'post.cz', 'email.cz', 'atlas.cz',
    'centrum.cz', 'volny.cz',
    'o2.pl', 'wp.pl', 'interia.pl', 'onet.pl',
    'libero.it', 'virgilio.it', 'tiscali.it',
    'alice.it', 'tin.it', 'inwind.it',
}

# Platform/directory domains — these are scraping artifacts, not real business emails.
# Excluded from deliverable/push even if SMTP passes.
PLATFORM_DOMAINS = {
    'birdeye.com', 'birdeye.ca', 'birdeye.co.uk',
    'verifiednode.com',
    'qualitybusinessawards.com', 'qualitybusinessawards.ca',
    'canadiancares.com', 'canadiancares.ca',
    'mailservice.com',
    'manta.com', 'yellowpages.com', 'hotfrog.com', 'hotfrog.ca',
    'cylex.us.com', 'cylex.ca', 'cylex.net',
    'chamberofcommerce.com', 'bbb.org',
    'mapquest.com', 'opendi.com', 'superpages.com',
    'dexknows.com', 'whitepages.com', 'merchantcircle.com',
    'citysearch.com', 'kudzu.com', 'consumerbeacon.com',
    'thebluebook.com', 'angieslist.com', 'homeadvisor.com',
    'porch.com', 'thumbtack.com', 'nextdoor.com',
    'yelp.com', 'yelp.ca', 'yelp.com.au', 'yelp.com.uk',
    'buzzfile.com', 'zillow.com', 'realtor.com',
    'redfin.com', 'trulia.com', 'apartments.com',
}

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        g._database = db
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS verified_lists (
        id TEXT PRIMARY KEY, list_name TEXT, verified_at TEXT,
        total_rows INTEGER, total_emails INTEGER,
        valid_count INTEGER DEFAULT 0, invalid_count INTEGER DEFAULT 0,
        verification_results TEXT, original_rows TEXT, original_csv_headers TEXT,
        smtp_done INTEGER DEFAULT 0
    )''')
    db.commit()
    close_connection(None)

with app.app_context():
    init_db()

def strip_quotes(s):
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s

_rr = dns.resolver.Resolver()
_rr.timeout = 3
_rr.lifetime = 3

def _resolve(domain, rtype):
    try: return list(_rr.resolve(domain, rtype))
    except Exception: return []

_dns_cache = {}
def _cached_dns(domain):
    now = time.time()
    if domain in _dns_cache and now - _dns_cache[domain]['ts'] < 300:
        return _dns_cache[domain]
    mx = _resolve(domain, 'MX')
    a = _resolve(domain, 'A')
    result = {'mx': [str(x.exchange).rstrip('.') for x in mx] if mx else 'NO_MX', 'a_record': bool(a)}
    _dns_cache[domain] = {'ts': now, **result}
    return result

def is_dummy_email(local, domain):
    if local in DUMMY_LOCALS: return True
    if domain in PLACEHOLDER_DOMAINS: return True
    if domain in DUMMY_LOCALS: return True
    if local.isdigit() and len(local) >= 2: return True
    if re.match(r'^(test\d*|user\d+|demo\d*)$', local, re.I): return True
    if re.match(r'^[a-z]{1,3}$', local, re.I): return True
    return False

ROLE_LOCALS = {'info', 'sales', 'support', 'contact', 'admin', 'help', 'enquiries', 'hello', 'office', 'team', 'hr', 'careers', 'jobs', 'marketing', 'billing', 'accounts', 'feedback', 'orders', 'shipping', 'returns', 'privacy', 'legal', 'press', 'media', 'partner', 'investor', 'recruitment', 'service', 'reservations', 'booking', 'reception', 'frontdesk', 'noc', 'security', 'abuse', 'postmaster', 'webmaster', 'hostmaster', 'dmca', 'editor', 'subscriptions', 'unsubscribe', 'optout', 'complaints', 'suggestions', 'testimonial', 'referral', 'invite', 'invitation', 'rsvp', 'dpo', 'admin', 'cellphone', 'notifications', 'alert', 'alerts', 'customerservice', 'customer', 'service', 'adm', 'cs', 'info', 'smtp', 'pop3', 'imap', 'dns', 'domain', 'hosting', 'server', 'vps', 'cloud', 'data', 'support', 'licensing', 'register', 'registration', 'confirm', 'verification', 'verify', 'confirm'}

def detect_typo_domain(domain):
    known = {'gmial.com':'gmail.com','gnail.com':'gmail.com','gmil.com':'gmail.com','gamil.com':'gmail.com','gmaill.com':'gmail.com','gmail.co':'gmail.com','hotmai.com':'hotmail.com','hotmal.com':'hotmail.com','hotmil.com':'hotmail.com','outlok.com':'outlook.com','outllok.com':'outlook.com','yaho.com':'yahoo.com','yhoo.com':'yahoo.com','yahooo.com':'yahoo.com','yahho.com':'yahoo.com','yahu.com':'yahoo.com'}
    return known.get(domain)

def verify_one_light(email):
    result = {'email': email, 'valid': None, 'syntax_valid': True, 'catch_all': None, 'role_based': False, 'mx': None, 'dual_rcpt': None, 'spam_trap': False, 'typo': None, 'gravatar': False, 'hibp_count': None, 'a_record': False, 'low_quality': False, 'disposable': False}
    email = email.strip().lower()
    result['email'] = email
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        result['syntax_valid'] = False; result['valid'] = False; return result
    local, _, domain = email.partition('@')
    t = detect_typo_domain(domain)
    if t: result['typo'] = t; result['valid'] = False; return result
    if is_dummy_email(local, domain): result['valid'] = False; return result
    if local in ROLE_LOCALS: result['role_based'] = True
    cd = domain.lower().replace('www.', '')
    for lq in LOW_QUALITY_DOMAINS:
        if cd == lq or cd.endswith('.'+lq): result['low_quality'] = True; break
    cached = _cached_dns(domain)
    result['mx'] = cached['mx'] if cached['mx'] != 'NO_MX' else None
    result['a_record'] = cached['a_record']
    if bool(cached['mx']) and cached['mx'] != 'NO_MX' and result['syntax_valid'] and cached['a_record']:
        result['valid'] = True
    return result

def verify_via_daemon(email):
    try:
        r = requests.post(SMTP_DAEMON_URL, json={'email': email}, timeout=SMTP_DAEMON_TIMEOUT)
        return r.json()
    except Exception as e:
        log.warning(f'Daemon call failed for {email}: {e}')
        return {'email': email, 'valid': None, 'smtp_status': f'ERR: {str(e)[:40]}', 'catch_all': None, 'mx': None}

def verify_one(email):
    return verify_via_daemon(email)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify_endpoint():
    data = request.get_json()
    results = []
    for e in data.get('emails', '').split(','):
        e = e.strip()
        if e: results.append(verify_one_light(e))
    v = sum(1 for r in results if r['valid'] is True)
    iv = sum(1 for r in results if r['valid'] is False)
    return jsonify({'results': results, 'total': len(results), 'valid': v, 'invalid': iv, 'unknown': len(results)-v-iv})

@app.route('/api/smtp-run', methods=['POST'])
def smtp_run():
    data = request.get_json()
    results = [verify_one(e) for e in data.get('emails', [])]
    return jsonify({'results': results})

@app.route('/api/upload-and-verify', methods=['POST'])
def upload_and_verify():
    file = request.files.get('file')
    list_name = request.form.get('list_name', 'upload')
    if not file: return jsonify({'success': False, 'error': 'No file'})
    content = file.read().decode('utf-8').strip()
    reader = csv.DictReader(io.StringIO(content))
    headers = reader.fieldnames or []
    if not headers: return jsonify({'success': False, 'error': 'Empty CSV'})
    email_col = None
    for col in ['Email', 'email', 'EMAIL', 'e-mail', 'E-mail']:
        if col in headers: email_col = col; break
    if not email_col: email_col = headers[0]
    rows = [{h: r.get(h, '') for h in headers} for r in reader]
    vresults = {}
    for row in rows:
        raw = strip_quotes(row.get(email_col, '').strip().lower())
        if raw and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', raw) and raw not in vresults:
            vresults[raw] = verify_one_light(raw)
    vc = sum(1 for v in vresults.values() if v['valid'] is True)
    ic = sum(1 for v in vresults.values() if v['valid'] is False)
    lid = str(uuid.uuid4())
    db = get_db()
    db.execute('''INSERT INTO verified_lists (id, list_name, verified_at, total_rows, total_emails, valid_count, invalid_count, verification_results, original_rows, original_csv_headers) VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (lid, list_name, datetime.utcnow().isoformat(), len(rows), len(vresults), vc, ic,
         json.dumps(vresults), json.dumps(rows), json.dumps(headers)))
    db.commit()
    return jsonify({'success': True, 'list_id': lid, 'list_name': list_name, 'total_emails': len(vresults), 'valid': vc, 'invalid': ic, 'unknown': len(vresults)-vc-ic})

@app.route('/api/verified-lists', methods=['GET'])
def get_verified_lists():
    db = get_db()
    rows = db.execute('SELECT id, list_name, verified_at, total_rows, total_emails, valid_count, invalid_count, smtp_done FROM verified_lists ORDER BY verified_at DESC').fetchall()
    return jsonify({'lists': [dict(r) for r in rows]})

@app.route('/api/verified-lists/<list_id>/download', methods=['GET'])
def download_verified_list(list_id):
    db = get_db()
    row = db.execute('SELECT * FROM verified_lists WHERE id = ?', (list_id,)).fetchone()
    if not row: return jsonify({'error': 'List not found'}), 404
    headers = json.loads(row['original_csv_headers'])
    original_rows = json.loads(row['original_rows'])
    vresults = json.loads(row['verification_results'])
    email_col = next((c for c in ['Email', 'email', 'EMAIL', 'e-mail', 'E-mail'] if c in headers), headers[0])
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(headers + ['Status', 'Catch-All', 'Spam Trap', 'Role', 'SMTP Status'])
    for r in original_rows:
        raw = strip_quotes(r.get(email_col, '').strip().lower())
        vr = vresults.get(raw, {})
        status = 'Invalid'
        if vr.get('valid') is True: status = 'Valid'
        elif vr.get('valid') is None: status = 'Unknown'
        w.writerow([r.get(h, '') for h in headers] + [status, 'Yes' if vr.get('catch_all') else 'No', 'Yes' if vr.get('spam_trap') else 'No', 'Yes' if vr.get('role_based') else 'No', vr.get('smtp_status', 'quick')])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={row["list_name"]}_verified.csv'})

@app.route('/api/verified-lists/<list_id>/download-deliverable', methods=['GET'])
def download_deliverable(list_id):
    db = get_db()
    row = db.execute('SELECT * FROM verified_lists WHERE id = ?', (list_id,)).fetchone()
    if not row: return jsonify({'error': 'List not found'}), 404
    headers = json.loads(row['original_csv_headers'])
    original_rows = json.loads(row['original_rows'])
    vresults = json.loads(row['verification_results'])
    email_col = next((c for c in ['Email', 'email', 'EMAIL', 'e-mail', 'E-mail'] if c in headers), headers[0])
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(headers)
    count = 0
    for r in original_rows:
        raw = strip_quotes(r.get(email_col, '').strip().lower())
        vr = vresults.get(raw, {})
        if vr.get('valid') is True:
            domain = raw.split('@')[-1] if '@' in raw else ''
            if domain in PLATFORM_DOMAINS:
                continue
            ss = vr.get('smtp_status', '')
            is_deliverable = True
            if ss and ss.startswith('550'):
                is_deliverable = False
            if is_deliverable:
                w.writerow([strip_quotes(r.get(h, '')) for h in headers])
                count += 1
    if count == 0:
        return Response('No deliverable emails found', mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={row["list_name"]}_deliverable.csv'})
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={row["list_name"]}_deliverable.csv'})

@app.route('/api/verified-lists/<list_id>/detail', methods=['GET'])
def verified_list_detail(list_id):
    db = get_db()
    row = db.execute('SELECT * FROM verified_lists WHERE id = ?', (list_id,)).fetchone()
    db.close()
    if not row: return jsonify({'error': 'List not found'}), 404
    headers = json.loads(row['original_csv_headers'])
    original_rows = json.loads(row['original_rows'])
    vresults = json.loads(row['verification_results'])
    email_col = next((c for c in ['Email', 'email', 'EMAIL', 'e-mail', 'E-mail'] if c in headers), headers[0])
    rows_data = [{'original': r, 'verification': vresults.get(strip_quotes(r.get(email_col, '').strip().lower()), {})} for r in original_rows]
    return jsonify({'list_name': row['list_name'], 'verified_at': row['verified_at'], 'headers': headers, 'email_col': email_col, 'rows': rows_data, 'total_rows': row['total_rows'], 'total_emails': row['total_emails'], 'valid_count': row['valid_count'], 'invalid_count': row['invalid_count']})

@app.route('/api/list-smtp-check/<list_id>', methods=['POST'])
def list_smtp_check(list_id):
    db = get_db()
    row = db.execute('SELECT * FROM verified_lists WHERE id = ?', (list_id,)).fetchone()
    if not row: return jsonify({'error': 'List not found'}), 404
    vresults = json.loads(row['verification_results'])
    data = request.get_json(silent=True) or {}
    emails_param = data.get('emails')
    def merge_smtp(result, sr):
        result['smtp_status'] = sr.get('smtp_status', 'ERR')
        result['smtp_time'] = sr.get('smtp_time', None)
        result['catch_all'] = sr.get('catch_all', None)
        if result.get('valid') is not False:
            result['valid'] = sr.get('valid', result.get('valid'))
        result['mx'] = sr.get('mx', result.get('mx'))
        result['rcp_response'] = sr.get('rcp_response', result.get('rcp_response'))
    if emails_param:
        for email in emails_param:
            email = email.strip().lower()
            if email in vresults and (vresults[email].get('valid') is True or vresults[email].get('valid') is None):
                merge_smtp(vresults[email], verify_one(email))
    else:
        headers = json.loads(row['original_csv_headers'])
        original_rows = json.loads(row['original_rows'])
        email_col = next((c for c in ['Email', 'email', 'EMAIL', 'e-mail', 'E-mail'] if c in headers), headers[0])
        for r in original_rows:
            raw = strip_quotes(r.get(email_col, '').strip().lower())
            if raw and raw in vresults and (vresults[raw].get('valid') is True or vresults[raw].get('valid') is None):
                merge_smtp(vresults[raw], verify_one(raw))
    vc = sum(1 for v in vresults.values() if v['valid'] is True)
    ic = sum(1 for v in vresults.values() if v['valid'] is False)
    db.execute('UPDATE verified_lists SET verification_results=?, valid_count=?, invalid_count=?, smtp_done=1 WHERE id=?',
        (json.dumps(vresults), vc, ic, list_id))
    db.commit()
    return jsonify({'status': 'ok', 'valid': vc, 'invalid': ic, 'unknown': len(vresults)-vc-ic})

@app.route('/api/verified-lists/<list_id>', methods=['DELETE'])
def delete_verified_list(list_id):
    db = get_db()
    db.execute('DELETE FROM verified_lists WHERE id = ?', (list_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/download', methods=['POST'])
def download():
    data = request.get_json()
    results = data.get('results', [])
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(['Email', 'Status', 'MX', 'SMTP Status', 'Catch-All', 'Role-Based', 'Spam Trap'])
    for r in results:
        status = 'Valid' if r.get('valid') is True else ('Invalid' if r.get('valid') is False else 'Unknown')
        w.writerow([r.get('email'), status, r.get('mx',''), r.get('smtp_status',''), 'Yes' if r.get('catch_all') else 'No', 'Yes' if r.get('role_based') else 'No', 'Yes' if r.get('spam_trap') else 'No'])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=results.csv'})

PLUSVIBE_BASE = 'https://api.plusvibe.ai/api/v1'
APP_URL = 'https://app.plusvibe.ai'
PLUSVIBE_API_KEY = '15ef281c-f0872347-6eb1dd65-0914fcd1'
PLUSVIBE_WS_ID = '6a504024997812a6e6981e1f'

@app.route('/api/push-to-plusvibe/<list_id>', methods=['POST'])
def push_to_plusvibe(list_id):
    """Push deliverable emails to PlusVibe campaign (API key, no prompts)."""
    api_key, workspace_id = PLUSVIBE_API_KEY, PLUSVIBE_WS_ID
    
    db = get_db()
    row = db.execute('SELECT * FROM verified_lists WHERE id = ?', (list_id,)).fetchone()
    if not row:
        return jsonify({'success': False, 'error': 'List not found'}), 404
    list_name = row['list_name'] or 'Email Verifier Import'
    
    headers = json.loads(row['original_csv_headers'])
    original_rows = json.loads(row['original_rows'])
    vresults = json.loads(row['verification_results'])
    email_col = next((c for c in ['Email', 'email', 'EMAIL', 'e-mail', 'E-mail'] if c in headers), headers[0])
    
    deliverable_emails = []
    for r in original_rows:
        raw = strip_quotes(r.get(email_col, '').strip().lower())
        vr = vresults.get(raw, {})
        if vr.get('valid') is True:
            domain = raw.split('@')[-1] if '@' in raw else ''
            if domain in PLATFORM_DOMAINS:
                continue
            ss = vr.get('smtp_status', '')
            if ss and ss.startswith('550'):
                continue
            deliverable_emails.append({'email': raw})
    
    if not deliverable_emails:
        return jsonify({'success': False, 'error': 'No deliverable emails found'}), 400
    
    # Create campaign
    try:
        cr = requests.post(f'{PLUSVIBE_BASE}/campaign/add/campaign',
            headers={'x-api-key': api_key, 'Content-Type': 'application/json'},
            json={'workspace_id': workspace_id, 'camp_name': list_name},
            timeout=15)
        if cr.status_code != 200:
            return jsonify({'success': False, 'error': f'Campaign creation failed ({cr.status_code}): {cr.text[:200]}'}), 502
        campaign_data = cr.json()
        campaign_id = campaign_data.get('id')
        if not campaign_id:
            return jsonify({'success': False, 'error': 'No campaign_id in response'}), 502
    except Exception as e:
        return jsonify({'success': False, 'error': f'Campaign creation: {str(e)}'}), 502
    
    # Add leads in batches of 100
    total = len(deliverable_emails)
    added = 0
    errors = []
    for i in range(0, total, 100):
        batch = deliverable_emails[i:i+100]
        try:
            lr = requests.post(f'{PLUSVIBE_BASE}/lead/add',
                headers={'x-api-key': api_key, 'Content-Type': 'application/json'},
                json={'workspace_id': workspace_id, 'campaign_id': campaign_id, 'skip_if_in_workspace': True, 'leads': batch},
                timeout=30)
            if lr.status_code == 200:
                added += len(batch)
            else:
                errors.append(f'Batch {i//100}: {lr.status_code}')
        except Exception as e:
            errors.append(f'Batch {i//100}: {str(e)[:60]}')
    
    return jsonify({
        'success': True,
        'campaign_id': campaign_id,
        'campaign_url': f'{APP_URL}/v2/campaigns/',
        'total_emails': total,
        'added': added,
        'errors': errors if errors else None
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)

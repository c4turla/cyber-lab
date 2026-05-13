#!/bin/sh

set -e

echo "============================================"
echo "  Cyber Range: Admin Feedback System"
echo "  Red vs. Blue CTF Lab"
echo "============================================"
echo ""

# Ensure log directory exists
mkdir -p /opt/admin/logs

# Start SSH server on custom port 2275
echo "[+] Starting SSH server on port 2275..."
/usr/sbin/sshd

# Add SSH key configuration for analyst user
mkdir -p /home/analyst/.ssh
chmod 700 /home/analyst/.ssh
chown -R analyst:analyst /home/analyst/.ssh

echo "[+] SSH server ready - Login: analyst / blue_team_rocks (port 2275)"

# Generate simulated attack logs for Blue Team
echo "[+] Generating Blue Team forensic logs..."
node /app/scripts/generate_logs.js

echo ""
echo "[+] Starting Node.js application on port 3075..."
echo ""

# Start the Node.js application
exec node /app/server.js
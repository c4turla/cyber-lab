#!/bin/sh

echo "============================================"
echo "  Cyber Range: Admin Feedback System"
echo "  Red vs. Blue CTF Lab"
echo "============================================"
echo ""

# Ensure log directory exists with proper permissions
mkdir -p /opt/admin/logs
chmod 755 /opt/admin/logs

# Start SSH server on custom port 2275
echo "[+] Starting SSH server on port 2275..."
if /usr/sbin/sshd -e 2>/dev/null; then
    echo "[+] SSH server started successfully"
else
    echo "[!] Warning: SSH server failed to start (non-fatal, continuing...)"
    ssh-keygen -A 2>/dev/null
    /usr/sbin/sshd -e 2>/dev/null || echo "[!] SSH start retry also failed"
fi

# Setup analyst user SSH directory
mkdir -p /home/analyst/.ssh
chmod 700 /home/analyst/.ssh
chown -R analyst:analyst /home/analyst

echo "[+] SSH server ready - Login: analyst / blue_team_rocks (port 2275)"

# Generate simulated attack logs for Blue Team
echo "[+] Generating Blue Team forensic logs..."
if node /app/scripts/generate_logs.js; then
    echo "[+] Log generation completed successfully"
else
    echo "[!] Warning: Log generation failed (non-fatal, continuing...)"
fi

# Set log permissions — analyst can read logs for investigation
chown root:analyst /opt/admin/logs 2>/dev/null || true
chmod 755 /opt/admin/logs
chmod 644 /opt/admin/logs/access.log /opt/admin/logs/error.log 2>/dev/null || true

echo ""
echo "[+] Starting Node.js application on port 3075..."
echo ""

# Start the Node.js application
exec node /app/server.js
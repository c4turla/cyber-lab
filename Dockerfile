FROM node:18-alpine

# Install SSH server, bash, and create analyst user
RUN apk add --no-cache openssh shadow bash && \
    mkdir -p /opt/admin/logs && \
    # Generate SSH host keys (CRITICAL - sshd won't start without these)
    ssh-keygen -A && \
    # Create analyst user with password (Blue Team credentials)
    adduser -D -s /bin/bash -h /home/analyst analyst && \
    echo 'analyst:blue_team_rocks' | chpasswd && \
    # Configure SSH on custom port 2275
    sed -i 's/#Port 22/Port 2275/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    # Ensure sshd privilege separation directory exists
    mkdir -p /var/run/sshd

# Set up working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --production

# Copy application files
COPY . .

# Make scripts executable
RUN chmod +x scripts/generate_logs.js

# Create startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    # Convert line endings (Windows CRLF -> Unix LF) to prevent exec format errors
    sed -i 's/\r$//' /entrypoint.sh

# Expose ports
EXPOSE 3075 2275

# Healthcheck to verify app is responding
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3075/ || exit 1

# Default entrypoint
ENTRYPOINT ["/entrypoint.sh"]
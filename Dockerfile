FROM node:18-alpine

# Install SSH server and create analyst user
RUN apk add --no-cache openssh shadow nginx && \
    mkdir -p /run/nginx && \
    mkdir -p /opt/admin/logs && \
    # Create analyst user with password
    adduser -D -h /home/analyst analyst && \
    echo 'analyst:blue_team_rocks' | chpasswd && \
    # Configure SSH on custom port 2275
    sed -i 's/#Port 22/Port 2275/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Set up working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm install

# Copy application files
COPY . .

# Install npm packages globally if needed
RUN npm install -g ejs

# Make scripts executable
RUN chmod +x scripts/generate_logs.js

# Create startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose ports
EXPOSE 3075 2275

# Default entrypoint
ENTRYPOINT ["/entrypoint.sh"]
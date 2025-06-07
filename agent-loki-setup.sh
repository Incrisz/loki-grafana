#!/bin/bash

# Agent Server Setup Script for Loki Monitoring
# Run this on each server you want to monitor

set -e

echo "🚀 Setting up Loki Agent Server..."

# Get central server IP from environment or prompt
if [ -z "$LOKI_SERVER_IP" ]; then
    echo "📡 Please enter your central monitoring server IP:"
    read -p "Central Server IP: " LOKI_SERVER_IP
fi

if [ -z "$LOKI_SERVER_IP" ]; then
    echo "❌ Central server IP is required!"
    echo "Usage: LOKI_SERVER_IP=\"your-server-ip\" bash script.sh"
    exit 1
fi

# Test connectivity to central server
echo "🔗 Testing connection to central server..."
if ! timeout 5 bash -c "</dev/tcp/$LOKI_SERVER_IP/3100"; then
    echo "❌ Cannot connect to $LOKI_SERVER_IP:3100"
    echo "Please ensure the central server is running and accessible"
    exit 1
fi
echo "✅ Connection successful!"

# Install dependencies
echo "📦 Installing dependencies..."
sudo apt update
sudo apt install -y wget unzip auditd audispd-plugins inotify-tools curl

# Install Promtail
echo "⬇️ Installing Promtail..."
cd /tmp
wget -q https://github.com/grafana/loki/releases/download/v2.9.0/promtail-linux-amd64.zip
unzip -q promtail-linux-amd64.zip
sudo mv promtail-linux-amd64 /usr/local/bin/promtail
sudo chmod +x /usr/local/bin/promtail

# Create directories
sudo mkdir -p /opt/promtail/{config,data}
sudo mkdir -p /var/log/file-changes

# Configure Auditd
echo "🔍 Configuring audit system..."
sudo cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.backup 2>/dev/null || true

sudo tee /etc/audit/rules.d/file-changes.rules > /dev/null <<'EOF'
# File and directory monitoring rules
-w /etc -p wa -k config-changes
-w /home -p wa -k home-changes
-w /var/www -p wa -k web-changes
-w /usr/local -p wa -k local-changes
-w /root -p wa -k root-changes

# SSH key monitoring
-w /home/*/.ssh -p wa -k ssh-key-changes
-w /root/.ssh -p wa -k ssh-key-changes
-w /etc/ssh -p wa -k ssh-config-changes

# System file monitoring
-w /etc/passwd -p wa -k user-changes
-w /etc/group -p wa -k group-changes
-w /etc/shadow -p wa -k shadow-changes
-w /etc/sudoers -p wa -k sudo-changes
EOF

# Configure auditd hostname
sudo sed -i '/^name_format/d' /etc/audit/auditd.conf
echo "name_format = hostname" | sudo tee -a /etc/audit/auditd.conf

# Enable command history logging
echo "📝 Configuring command history logging..."
sudo tee -a /etc/bash.bashrc > /dev/null <<'EOF'

# Log all commands to syslog
export PROMPT_COMMAND='history -a; logger -p local6.notice -t bash-history "$(whoami) [$]: $(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//")"'
EOF

# Get server identification
echo "🏷️ Configuring server identification..."
SERVER_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s ipinfo.io/ip 2>/dev/null || echo "unknown")

# Change system hostname if SERVER_NAME is provided
if [ -n "$SERVER_NAME" ]; then
    NEW_HOSTNAME="${SERVER_NAME}-${LOKI_SERVER_IP}"
    echo "🔧 Setting system hostname to: $NEW_HOSTNAME"
    sudo hostnamectl set-hostname "$NEW_HOSTNAME"
    HOSTNAME="$NEW_HOSTNAME"
    SERVER_IDENTIFIER="$NEW_HOSTNAME"
    
    # Restart logging services to pick up new hostname
    echo "🔄 Restarting logging services for hostname change..."
    sudo systemctl restart rsyslog
    sudo systemctl restart systemd-journald
    
    echo "✅ System hostname changed to: $NEW_HOSTNAME"
    echo "⚠️  Note: Kernel logs will show old hostname until system reboot"
    echo "    Run 'sudo reboot' after setup to update all logs"
elif [ -f "/etc/server-name" ]; then
    SERVER_IDENTIFIER=$(cat /etc/server-name)
    echo "✅ Using manual server name: $SERVER_IDENTIFIER"
else
    # Use public IP as identifier, fallback to hostname
    SERVER_IDENTIFIER="${PUBLIC_IP}"
    if [ "$PUBLIC_IP" = "unknown" ]; then
        SERVER_IDENTIFIER="${HOSTNAME}"
    fi
    echo "✅ Using auto-detected identifier: $SERVER_IDENTIFIER"
fi

# Create file monitoring script (after hostname change)
echo "📁 Creating file monitoring script..."

sudo tee /opt/promtail/file-monitor.sh > /dev/null <<EOF
#!/bin/bash

LOG_FILE="/var/log/file-changes/changes.log"
ERROR_LOG="/var/log/file-changes/error.log"
PID_FILE="/var/run/file-monitor.pid"

# Create log directory
mkdir -p /var/log/file-changes

# List of directories to monitor
DIRS_TO_MONITOR=("/etc" "/home" "/usr/local" "/root")

# Check which directories exist
EXISTING_DIRS=()
for dir in "\${DIRS_TO_MONITOR[@]}"; do
    if [ -d "\$dir" ]; then
        EXISTING_DIRS+=("\$dir")
        echo "\$(date) - Will monitor: \$dir" >> "\$ERROR_LOG"
    else
        echo "\$(date) - Skipping non-existent directory: \$dir" >> "\$ERROR_LOG"
    fi
done

# Create /var/www if web server exists
if command -v nginx >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1; then
    mkdir -p /var/www
    EXISTING_DIRS+=("/var/www")
fi

echo "\$(date) - Starting file monitoring for: \${EXISTING_DIRS[*]}" >> "\$ERROR_LOG"

# Start inotify with hostname embedded
inotifywait -m -r -e modify,create,delete,move \\
    "\${EXISTING_DIRS[@]}" \\
    --format "%T $HOSTNAME [%w%f] %e" \\
    --timefmt '%Y-%m-%d %H:%M:%S' \\
    --exclude '/(\.(cache|local/share/Trash|git|svn)|tmp|temp|promtail)/' \\
    >> "\$LOG_FILE" 2>> "\$ERROR_LOG" &

INOTIFY_PID=\$!
echo \$INOTIFY_PID > "\$PID_FILE"
echo "\$(date) - File monitoring started. PID: \$INOTIFY_PID" >> "\$ERROR_LOG"

wait \$INOTIFY_PID
EOF

sudo chmod +x /opt/promtail/file-monitor.sh

# Create Promtail configuration
echo "⚙️ Creating Promtail configuration..."
sudo tee /opt/promtail/config/promtail-config.yml > /dev/null <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /opt/promtail/data/positions.yaml

clients:
  - url: http://${LOKI_SERVER_IP}:3100/loki/api/v1/push

scrape_configs:
  # SSH Authentication Logs
  - job_name: ssh-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: ssh-logs
          server: ${SERVER_IDENTIFIER}
          hostname: ${HOSTNAME}
          private_ip: ${SERVER_IP}
          public_ip: ${PUBLIC_IP}
          __path__: /var/log/auth.log

  # System Logs
  - job_name: system-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: system-logs
          server: ${SERVER_IDENTIFIER}
          hostname: ${HOSTNAME}
          private_ip: ${SERVER_IP}
          public_ip: ${PUBLIC_IP}
          __path__: /var/log/syslog

  # Security Logs
  - job_name: security-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: security-logs
          server: ${SERVER_IDENTIFIER}
          hostname: ${HOSTNAME}
          private_ip: ${SERVER_IP}
          public_ip: ${PUBLIC_IP}
          __path__: /var/log/secure

  # Audit Logs (File Changes)
  - job_name: audit-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: audit-logs
          server: ${SERVER_IDENTIFIER}
          hostname: ${HOSTNAME}
          private_ip: ${SERVER_IP}
          server_ip: ${PUBLIC_IP}
          __path__: /var/log/audit/audit.log

  # Custom File Change Logs
  - job_name: file-changes
    static_configs:
      - targets:
          - localhost
        labels:
          job: file-changes
          server: ${SERVER_IDENTIFIER}
          hostname: ${HOSTNAME}
          private_ip: ${SERVER_IP}
          server_ip: ${PUBLIC_IP}
          __path__: /var/log/file-changes/changes.log

  # Kernel Logs
  - job_name: kernel-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: kernel-logs
          server: ${SERVER_IDENTIFIER}
          hostname: ${HOSTNAME}
          private_ip: ${SERVER_IP}
          public_ip: ${PUBLIC_IP}
          __path__: /var/log/kern.log

  # Command History Logs
  - job_name: cmd-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: cmd-logs
          server: ${SERVER_IDENTIFIER}
          hostname: ${HOSTNAME}
          private_ip: ${SERVER_IP}
          public_ip: ${PUBLIC_IP}
          __path__: /var/log/syslog
    pipeline_stages:
      - match:
          selector: '{job="cmd-logs"}'
          stages:
            - regex:
                expression: '.*bash-history.*'
            - labels:
                command_type: bash
EOF

# Create systemd services
echo "🔧 Creating systemd services..."

# Promtail service
sudo tee /etc/systemd/system/promtail.service > /dev/null <<'EOF'
[Unit]
Description=Promtail Log Collector
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/promtail -config.file=/opt/promtail/config/promtail-config.yml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# File monitor service
sudo tee /etc/systemd/system/file-monitor.service > /dev/null <<'EOF'
[Unit]
Description=File Change Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/promtail/file-monitor.sh
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Start services
echo "🟢 Starting services..."
sudo systemctl daemon-reload
sudo systemctl restart auditd
sudo systemctl enable auditd promtail file-monitor
sudo systemctl start promtail file-monitor

# Wait for services to start
sleep 5

# Check service status
echo "🔍 Checking service status..."
echo "Promtail: $(sudo systemctl is-active promtail)"
echo "File Monitor: $(sudo systemctl is-active file-monitor)"
echo "Audit: $(sudo systemctl is-active auditd)"

# Test log generation
echo "🧪 Testing log generation..."
sudo touch /etc/test-file-$(date +%s)
echo "Test file created for monitoring verification"

echo ""
echo "🎉 Agent server setup complete!"
echo ""
echo "📍 Server Information:"
echo "   Server ID: $SERVER_IDENTIFIER"
echo "   Hostname: $HOSTNAME"
echo "   Private IP: $SERVER_IP"
echo "   Public IP: $PUBLIC_IP"
echo "   Central Server: $LOKI_SERVER_IP"
echo ""
echo "🔍 Verification commands:"
echo "   Check logs: sudo journalctl -u promtail -f"
echo "   Test changes: sudo touch /etc/test-file"
echo "   View file changes: sudo tail -f /var/log/file-changes/changes.log"
echo ""
echo "📊 View logs in Grafana at: http://$LOKI_SERVER_IP:3000"
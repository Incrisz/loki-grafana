# Loki SSH and File Change Monitoring Setup

Complete setup guide for centralized log monitoring using Loki with Docker on the central server and native agents on monitored servers.

## Central Monitoring Server (Dockerized)

### Prerequisites
```bash
# Install Docker and Docker Compose
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

### 1. Create Project Structure
```bash
sudo mkdir -p /var/www
mkdir -p loki-monitoring/{config,data/loki,data/grafana}
cd loki-monitoring
```

### 2. Create Docker Compose File
```bash
tee docker-compose.yml > /dev/null <<'EOF'
version: '3.8'

services:
  loki:
    image: grafana/loki:2.9.0
    container_name: loki
    ports:
      - "3100:3100"
    volumes:
      - ./config/loki-config.yaml:/etc/loki/local-config.yaml
      - ./data/loki:/loki
    command: -config.file=/etc/loki/local-config.yaml
    restart: unless-stopped
    networks:
      - loki-network

  grafana:
    image: grafana/grafana:10.2.0
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - ./data/grafana:/var/lib/grafana
      - ./config/grafana-datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    restart: unless-stopped
    networks:
      - loki-network
    depends_on:
      - loki

networks:
  loki-network:
    driver: bridge
EOF
```

### 3. Create Loki Configuration
```bash
tee config/loki-config.yaml > /dev/null <<'EOF'
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

ruler:
  alertmanager_url: http://localhost:9093

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  ingestion_rate_mb: 16
  ingestion_burst_size_mb: 32
  per_stream_rate_limit: 3MB
  per_stream_rate_limit_burst: 5MB
EOF
```

### 4. Create Grafana Datasource Configuration
```bash
tee config/grafana-datasources.yml > /dev/null <<'EOF'
apiVersion: 1

datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    editable: true
EOF
```

### 5. Start the Stack
```bash
# Create the required directory structure with proper permissions
sudo mkdir -p data/loki/{chunks,rules,index}

# Set ownership to the loki user (UID 10001 in the container)
sudo chown -R 10001:10001 data/loki

# Set permissions for Grafana
sudo chown -R 472:472 data/grafana
sudo chmod -R 755 data/

# Start services
sudo docker-compose up -d

# Check status
sudo docker-compose ps
sudo docker-compose logs loki
sudo docker-compose logs grafana
```

### 6. Configure Firewall
```bash
sudo ufw allow 3100/tcp  # Loki
sudo ufw allow 3000/tcp  # Grafana
sudo ufw reload
```

---

## Agent Server Setup (Native Installation)

### Quick Setup Script
Use this one-liner for agent installation:

```bash
# Basic setup (auto-detects server name)
LOKI_SERVER_IP="your-central-server-ip" bash -c "$(curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh)"

# With custom server name (changes hostname to servername-ip)
LOKI_SERVER_IP="192.168.1.100" SERVER_NAME="webserver-prod" bash -c "$(curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh)"
```

### Manual Installation Steps

### 1. Install Dependencies
```bash
# Update system
sudo apt update

# Install required packages
sudo apt install -y wget unzip auditd audispd-plugins inotify-tools curl
```

### 2. Install Promtail
```bash
# Download and install Promtail
cd /tmp
wget https://github.com/grafana/loki/releases/download/v2.9.0/promtail-linux-amd64.zip
unzip promtail-linux-amd64.zip
sudo mv promtail-linux-amd64 /usr/local/bin/promtail
sudo chmod +x /usr/local/bin/promtail

# Create directories
sudo mkdir -p /opt/promtail/{config,data}
sudo mkdir -p /var/log/file-changes
sudo mkdir -p /var/log/commands
```

### 3. Setup File Change Monitoring

#### Configure Auditd
```bash
# Backup original audit rules
sudo cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.backup

# Create file monitoring rules
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

# Configure auditd to include hostname in logs
sudo sed -i '/^name_format/d' /etc/audit/auditd.conf
echo "name_format = hostname" | sudo tee -a /etc/audit/auditd.conf
```

#### Setup Command History Logging
```bash
# Enable command history logging to dedicated file
sudo tee -a /etc/bash.bashrc > /dev/null <<'EOF'

# Log all commands to dedicated file
export PROMPT_COMMAND='history -a; echo "$(date "+%Y-%m-%d %H:%M:%S") $(hostname) $(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//")" >> /var/log/commands/bash-history.log'
EOF
```

#### Set Hostname (Optional)
```bash
# If using SERVER_NAME variable, change hostname
if [ -n "$SERVER_NAME" ] && [ -n "$LOKI_SERVER_IP" ]; then
    NEW_HOSTNAME="${SERVER_NAME}-${LOKI_SERVER_IP}"
    sudo hostnamectl set-hostname "$NEW_HOSTNAME"
    sudo systemctl restart rsyslog systemd-journald
fi
```

#### Create File Change Logger Script
```bash
HOSTNAME=$(hostname)

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
```

### 4. Create Promtail Configuration
**Replace `YOUR_MONITORING_SERVER_IP` with your actual monitoring server IP:**

```bash
# Set your monitoring server IP
LOKI_SERVER_IP="YOUR_MONITORING_SERVER_IP"

# Get server identification
HOSTNAME=$(hostname)
SERVER_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s ipinfo.io/ip 2>/dev/null || echo "unknown")

# Use public IP as the main identifier, fallback to hostname
SERVER_IDENTIFIER="${PUBLIC_IP}"
if [ "$PUBLIC_IP" = "unknown" ]; then
    SERVER_IDENTIFIER="${HOSTNAME}"
fi

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
          __path__: /var/log/commands/bash-history.log
EOF

echo "✅ Promtail configured for server: $SERVER_IDENTIFIER"
```

### 5. Create Systemd Services

#### Promtail Service
```bash
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
```

#### File Monitor Service
```bash
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
```

### 6. Start Services
```bash
# Reload systemd
sudo systemctl daemon-reload

# Restart auditd
sudo systemctl restart auditd

# Enable and start services
sudo systemctl enable promtail file-monitor
sudo systemctl start promtail file-monitor

# Check service status
sudo systemctl status promtail
sudo systemctl status file-monitor
sudo systemctl status auditd
```

---

## Verification and Testing

### Central Server Verification
```bash
# Check Docker containers
sudo docker-compose ps

# Check Loki API
curl -G -s "http://localhost:3100/ready"

# Check which servers are sending logs
curl -G -s "http://localhost:3100/loki/api/v1/label/server/values" | jq

# View recent logs
curl -G -s "http://localhost:3100/loki/api/v1/query" \
  --data-urlencode 'query={job=~".*"}' \
  --data-urlencode 'limit=10'
```

### Agent Server Verification
```bash
# Check Promtail status
sudo systemctl status promtail
sudo journalctl -u promtail -f --no-pager

# Check file monitoring
sudo systemctl status file-monitor
ls -la /var/log/file-changes/

# Test command logging (logout/login required for new sessions)
exit
# ssh back in, then:
sudo tail -f /var/log/commands/bash-history.log

# Test file changes
sudo touch /etc/test-file
sudo tail -f /var/log/file-changes/changes.log
```

---

## Grafana Dashboard Setup

### Access Grafana
- URL: `http://YOUR_MONITORING_SERVER_IP:3000`
- Username: `admin`
- Password: `admin123`

### LogQL Queries

1. **SSH Failed Logins by Server:**
   ```
   {job="ssh-logs"} |= "Failed password"
   ```

2. **Command History from Specific Server:**
   ```
   {job="cmd-logs", server="192.168.1.100"}
   ```

3. **File Changes with Specific Action:**
   ```
   {job="file-changes"} |= "DELETE"
   ```

4. **All Commands Containing 'sudo':**
   ```
   {job="cmd-logs"} |= "sudo"
   ```

5. **SSH Activity from Multiple Servers:**
   ```
   {job="ssh-logs", server=~"192.168.1.100|192.168.1.101"}
   ```

6. **File Changes in /etc Directory:**
   ```
   {job="file-changes"} |= "/etc"
   ```

7. **All Activity from Custom Named Server:**
   ```
   {server=~"webserver-prod.*"}
   ```

### Create Dashboard Variables
1. **Server Variable:**
   - Query: `label_values(server)`
   - Multi-value: ✅

2. **Log Type Variable:**
   - Query: `label_values(job)`
   - Multi-value: ✅

### Popular Dashboard IDs
Import these dashboard IDs in Grafana:
- **13639** - Loki Dashboard Quick Search
- **12019** - Loki Logs Dashboard  
- **14055** - Loki Stack Monitoring
- **15141** - Loki Operational Dashboard

---

## Maintenance Commands

### Central Server (Docker)
```bash
# View logs
sudo docker-compose logs -f loki
sudo docker-compose logs -f grafana

# Restart services
sudo docker-compose restart loki
sudo docker-compose restart grafana

# Update images
sudo docker-compose pull
sudo docker-compose up -d

# Backup data
tar -czf loki-backup-$(date +%Y%m%d).tar.gz data/
```

### Agent Servers
```bash
# Restart services
sudo systemctl restart promtail file-monitor

# View logs
sudo journalctl -u promtail -f
sudo journalctl -u file-monitor -f

# Check command logging (users must logout/login)
sudo tail -f /var/log/commands/bash-history.log

# Fix file monitor hostname issues
sudo systemctl stop file-monitor
HOSTNAME=$(hostname)
sudo sed -i "s/ip-172-31-[0-9-]\\+/$HOSTNAME/" /opt/promtail/file-monitor.sh
sudo systemctl start file-monitor
```

---

## Troubleshooting

### Common Issues

1. **No command logs appearing:**
   ```bash
   # Users must logout and login for command logging to work
   # Check if file exists and has content
   sudo ls -la /var/log/commands/
   sudo tail -f /var/log/commands/bash-history.log
   ```

2. **File changes show old hostname:**
   ```bash
   # Restart file monitor after hostname change
   sudo systemctl restart file-monitor
   ```

3. **Kernel logs inconsistent hostname:**
   ```bash
   # Normal behavior - requires reboot for full consistency
   sudo reboot
   ```

4. **Promtail can't connect to Loki:**
   ```bash
   # Check network connectivity
   telnet YOUR_MONITORING_SERVER_IP 3100
   
   # Check firewall
   sudo ufw status
   ```

### Log Locations
- **SSH Logs:** `/var/log/auth.log`
- **System Logs:** `/var/log/syslog`
- **Audit Logs:** `/var/log/audit/audit.log`
- **File Changes:** `/var/log/file-changes/changes.log`
- **Command History:** `/var/log/commands/bash-history.log`
- **Promtail Logs:** `journalctl -u promtail`

---

## Security Considerations

1. **Secure the monitoring server:**
   ```bash
   # Change default Grafana password
   # Enable HTTPS/TLS for production
   # Restrict access with firewall rules
   ```

2. **Network security:**
   ```bash
   # Use VPN or private networks
   # Enable authentication in Loki for production
   # Use TLS encryption for log shipping
   ```

This setup provides comprehensive monitoring including command history tracking across your infrastructure with centralized logging through Loki and visualization through Grafana.
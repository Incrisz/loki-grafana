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
tee sudo docker-compose.yml > /dev/null <<'EOF'
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
# -w /opt -p wa -k opt-changes
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

# Restart auditd
sudo systemctl restart auditd
sudo systemctl enable auditd
```

#### Create File Change Logger Script
```bash
sudo tee /opt/promtail/file-monitor.sh > /dev/null <<'EOF'
#!/bin/bash

LOG_FILE="/var/log/file-changes/changes.log"

# Ensure log directory exists
mkdir -p /var/log/file-changes

# Monitor directories with inotify
inotifywait -m -r -e modify,create,delete,move \
    /etc /home /var/www /opt /usr/local /root \
    --format '%T [%w%f] %e' \
    --timefmt '%Y-%m-%d %H:%M:%S' \
    --exclude '/(proc|sys|dev|tmp)/' >> "$LOG_FILE" 2>/dev/null &

echo "File monitoring started. PID: $!"
EOF

sudo chmod +x /opt/promtail/file-monitor.sh
```

### 4. Create Promtail Configuration
**Replace `YOUR_MONITORING_SERVER_IP` with your actual monitoring server IP:**

```bash
# Set your monitoring server IP
LOKI_SERVER_IP="YOUR_MONITORING_SERVER_IP"

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
          host: \$(hostname)
          __path__: /var/log/auth.log
    pipeline_stages:
      - match:
          selector: '{job="ssh-logs"}'
          stages:
            - regex:
                expression: '.*(sshd|sudo|su).*'

  # System Logs
  - job_name: system-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: system-logs
          host: \$(hostname)
          __path__: /var/log/syslog

  # Security Logs
  - job_name: security-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: security-logs
          host: \$(hostname)
          __path__: /var/log/secure
    pipeline_stages:
      - match:
          selector: '{job="security-logs"}'
          stages:
            - regex:
                expression: '.*(authentication|login|session).*'

  # Audit Logs (File Changes)
  - job_name: audit-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: audit-logs
          host: \$(hostname)
          __path__: /var/log/audit/audit.log
    pipeline_stages:
      - match:
          selector: '{job="audit-logs"}'
          stages:
            - regex:
                expression: '.*type=(SYSCALL|PATH).*'

  # Custom File Change Logs
  - job_name: file-changes
    static_configs:
      - targets:
          - localhost
        labels:
          job: file-changes
          host: \$(hostname)
          __path__: /var/log/file-changes/changes.log

  # Kernel Logs
  - job_name: kernel-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: kernel-logs
          host: \$(hostname)
          __path__: /var/log/kern.log
EOF
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
Type=forking
User=root
ExecStart=/opt/promtail/file-monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### 6. Start Services
```bash
# Reload systemd
sudo systemctl daemon-reload

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

# Check if logs are being received
curl -G -s "http://localhost:3100/loki/api/v1/labels"

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

# Test SSH logging (generate some SSH activity)
ssh localhost
sudo tail -f /var/log/auth.log

# Test file changes (create a test file)
sudo touch /etc/test-file
sudo ausearch -k config-changes | tail -5

# Check audit logs
sudo ausearch -ts recent | head -10
```

### Test Log Generation
```bash
# Generate SSH test logs
ssh-keygen -t rsa -f /tmp/test_key -N ""
ssh -i /tmp/test_key localhost

# Generate file change logs
sudo touch /etc/test-config-change
sudo mkdir /opt/test-directory
echo "test content" | sudo tee /home/test-file.txt
```

---

## Grafana Dashboard Setup

### Access Grafana
- URL: `http://YOUR_MONITORING_SERVER_IP:3000`
- Username: `admin`
- Password: `admin123`

### Create Basic Queries
1. **SSH Failed Logins:**
   ```
   {job="ssh-logs"} |= "Failed password"
   ```

2. **Successful SSH Logins:**
   ```
   {job="ssh-logs"} |= "Accepted password"
   ```

3. **File Changes:**
   ```
   {job="audit-logs"} |= "SYSCALL" |= "openat"
   ```

4. **System Errors:**
   ```
   {job="system-logs"} |= "error" or "Error" or "ERROR"
   ```

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

# Check disk space for logs
df -h /var/log/
du -sh /var/log/audit/
du -sh /var/log/file-changes/

# Rotate logs (if needed)
sudo logrotate -f /etc/logrotate.d/rsyslog
```

---

## Troubleshooting

### Common Issues

1. **Promtail can't connect to Loki:**
   ```bash
   # Check network connectivity
   telnet YOUR_MONITORING_SERVER_IP 3100
   
   # Check firewall
   sudo ufw status
   ```

2. **No SSH logs appearing:**
   ```bash
   # Check if SSH logs exist
   sudo tail -f /var/log/auth.log
   
   # Verify SSH service is logging
   sudo grep -i ssh /var/log/auth.log | tail -5
   ```

3. **File monitoring not working:**
   ```bash
   # Check inotify limits
   cat /proc/sys/fs/inotify/max_user_watches
   
   # Increase if needed
   echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p
   ```

4. **High disk usage:**
   ```bash
   # Check log sizes
   du -sh /var/log/*
   
   # Configure log rotation
   sudo nano /etc/logrotate.d/audit
   ```

### Log Locations
- **SSH Logs:** `/var/log/auth.log` (Ubuntu/Debian), `/var/log/secure` (CentOS/RHEL)
- **System Logs:** `/var/log/syslog`
- **Audit Logs:** `/var/log/audit/audit.log`
- **File Changes:** `/var/log/file-changes/changes.log`
- **Promtail Logs:** `journalctl -u promtail`

---

## Security Considerations

1. **Secure the monitoring server:**
   ```bash
   # Use strong passwords for Grafana
   # Enable HTTPS/TLS for production
   # Restrict access with firewall rules
   ```

2. **Protect sensitive logs:**
   ```bash
   # Set appropriate file permissions
   sudo chmod 640 /var/log/audit/audit.log
   sudo chown root:adm /var/log/audit/audit.log
   ```

3. **Network security:**
   ```bash
   # Use VPN or private networks
   # Enable authentication in Loki for production
   # Use TLS encryption for log shipping
   ```

4. **Loki Dashborad:-Enter one of these popular Loki dashboard IDs:**
   ```bash
    # 13639 - Loki Dashboard Quick Search
    # 12019 - Loki Logs Dashboard
    # 14055 - Loki Stack Monitoring
    # 15141 - Loki Operational Dashboard
   ```


This setup provides comprehensive monitoring of SSH activities and file changes across your infrastructure with centralized logging through Loki and visualization through Grafana.
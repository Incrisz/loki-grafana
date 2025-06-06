#!/bin/bash

# Loki Central Monitoring Server Setup Script
# Usage: curl -sSL https://raw.githubusercontent.com/Incrisz/elk-stack/main/central-loki-setup.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
    
    # Check sudo access
    if ! sudo -n true 2>/dev/null; then
        print_error "This script requires sudo privileges. Please ensure you can run sudo commands."
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    print_status "Detected OS: $OS $VERSION"
}

# Install Docker and Docker Compose
install_docker() {
    print_header "Installing Docker and Docker Compose"
    
    # Check if Docker is already installed
    if command -v docker >/dev/null 2>&1; then
        print_status "Docker is already installed"
        DOCKER_VERSION=$(docker --version)
        print_status "$DOCKER_VERSION"
    else
        print_status "Installing Docker..."
        
        # Update packages
        sudo apt update
        
        # Install prerequisites
        sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
        
        # Add Docker GPG key
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        
        # Add Docker repository
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker
        sudo apt update
        sudo apt install -y docker-ce docker-ce-cli containerd.io
        
        # Add user to docker group
        sudo usermod -aG docker $USER
        
        print_status "Docker installed successfully"
    fi
    
    # Check if Docker Compose is installed
    if command -v docker-compose >/dev/null 2>&1; then
        print_status "Docker Compose is already installed"
        COMPOSE_VERSION=$(docker-compose --version)
        print_status "$COMPOSE_VERSION"
    else
        print_status "Installing Docker Compose..."
        sudo apt install -y docker-compose
        print_status "Docker Compose installed successfully"
    fi
    
    # Start and enable Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    print_status "Docker services started and enabled"
}

# Create project structure
create_project_structure() {
    print_header "Creating Project Structure"
    
    # Create main directory
    INSTALL_DIR="/opt/loki-monitoring"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown $USER:$USER "$INSTALL_DIR"
    
    cd "$INSTALL_DIR"
    
    # Create subdirectories
    mkdir -p config data/loki data/grafana
    
    # Create required Loki directories
    sudo mkdir -p data/loki/{chunks,rules,index}
    sudo chown -R 10001:10001 data/loki
    sudo chown -R 472:472 data/grafana
    sudo chmod -R 755 data/
    
    print_status "Project structure created at $INSTALL_DIR"
}

# Create Docker Compose configuration
create_docker_compose() {
    print_header "Creating Docker Compose Configuration"
    
    cat > docker-compose.yml <<'EOF'
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
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    restart: unless-stopped
    networks:
      - loki-network
    depends_on:
      - loki

networks:
  loki-network:
    driver: bridge
EOF

    print_status "Docker Compose configuration created"
}

# Create Loki configuration
create_loki_config() {
    print_header "Creating Loki Configuration"
    
    cat > config/loki-config.yaml <<'EOF'
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
  ingestion_rate_mb: 64
  ingestion_burst_size_mb: 128
  per_stream_rate_limit: 10MB
  per_stream_rate_limit_burst: 20MB
  max_streams_per_user: 0
  max_line_size: 256000

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: true
  retention_period: 336h  # 14 days
EOF

    print_status "Loki configuration created"
}

# Create Grafana datasource configuration
create_grafana_config() {
    print_header "Creating Grafana Configuration"
    
    cat > config/grafana-datasources.yml <<'EOF'
apiVersion: 1

datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    editable: true
    jsonData:
      maxLines: 1000
      derivedFields:
        - datasourceUid: loki
          matcherRegex: "(?:traceID|trace_id)(?:=|\\s)(\\w+)"
          name: TraceID
          url: "$${__value.raw}"
EOF

    print_status "Grafana datasource configuration created"
}

# Configure firewall
configure_firewall() {
    print_header "Configuring Firewall"
    
    # Check if ufw is installed and active
    if command -v ufw >/dev/null 2>&1; then
        # Enable firewall if not active
        if ! sudo ufw status | grep -q "Status: active"; then
            print_warning "UFW firewall is not active. Do you want to enable it? (y/n)"
            read -r enable_ufw
            if [[ $enable_ufw =~ ^[Yy]$ ]]; then
                sudo ufw --force enable
                print_status "UFW firewall enabled"
            fi
        fi
        
        # Add firewall rules
        sudo ufw allow 3100/tcp comment "Loki"
        sudo ufw allow 3000/tcp comment "Grafana"
        sudo ufw allow ssh
        
        print_status "Firewall rules configured"
        sudo ufw status numbered
    else
        print_warning "UFW not installed. Please manually configure your firewall to allow ports 3000 and 3100"
    fi
}

# Start services
start_services() {
    print_header "Starting Services"
    
    # Start Docker service if not running
    if ! sudo systemctl is-active --quiet docker; then
        sudo systemctl start docker
        sleep 5
    fi
    
    # Start containers
    docker-compose up -d
    
    print_status "Waiting for services to start..."
    sleep 30
    
    # Check service status
    print_status "Service Status:"
    docker-compose ps
    
    # Test Loki API
    for i in {1..10}; do
        if curl -s http://localhost:3100/ready >/dev/null 2>&1; then
            print_status "Loki is ready!"
            break
        fi
        if [ $i -eq 10 ]; then
            print_warning "Loki may not be ready yet. Check logs with: docker-compose logs loki"
        fi
        sleep 5
    done
    
    # Test Grafana
    for i in {1..10}; do
        if curl -s http://localhost:3000 >/dev/null 2>&1; then
            print_status "Grafana is ready!"
            break
        fi
        if [ $i -eq 10 ]; then
            print_warning "Grafana may not be ready yet. Check logs with: docker-compose logs grafana"
        fi
        sleep 5
    done
}

# Create agent installation script
create_agent_script() {
    print_header "Creating Agent Installation Script"
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(curl -s ipinfo.io/ip 2>/dev/null || echo "YOUR_SERVER_IP")
    fi
    
    cat > agent-setup.sh <<EOF
#!/bin/bash

# Loki Agent Setup Script
# This script installs the Loki agent on remote servers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "\${GREEN}[INFO]\${NC} \$1"; }
print_warning() { echo -e "\${YELLOW}[WARNING]\${NC} \$1"; }
print_error() { echo -e "\${RED}[ERROR]\${NC} \$1"; }
print_header() { echo -e "\${BLUE}================================================\${NC}"; echo -e "\${BLUE}\$1\${NC}"; echo -e "\${BLUE}================================================\${NC}"; }

# Default Loki server IP (change this to your actual server IP)
LOKI_SERVER_IP="${SERVER_IP}"

# Allow override via environment variable or parameter
if [[ -n "\$1" ]]; then
    LOKI_SERVER_IP="\$1"
elif [[ -n "\$LOKI_SERVER" ]]; then
    LOKI_SERVER_IP="\$LOKI_SERVER"
fi

print_header "Loki Agent Setup"
print_status "Connecting to Loki server: \$LOKI_SERVER_IP"

# Check if running as root
if [[ \$EUID -eq 0 ]]; then
    print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
    exit 1
fi

# Install dependencies
print_header "Installing Dependencies"
sudo apt update
sudo apt install -y wget unzip auditd audispd-plugins inotify-tools curl jq

# Install Promtail
print_header "Installing Promtail"
cd /tmp
wget -q https://github.com/grafana/loki/releases/download/v2.9.0/promtail-linux-amd64.zip
unzip -q promtail-linux-amd64.zip
sudo mv promtail-linux-amd64 /usr/local/bin/promtail
sudo chmod +x /usr/local/bin/promtail
rm -f promtail-linux-amd64.zip

# Create directories
sudo mkdir -p /opt/promtail/{config,data}
sudo mkdir -p /var/log/file-changes

# Setup audit rules
print_header "Configuring Audit Rules"
sudo cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.backup 2>/dev/null || true

sudo tee /etc/audit/rules.d/file-changes.rules > /dev/null <<'AUDIT_EOF'
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
AUDIT_EOF

sudo systemctl restart auditd
sudo systemctl enable auditd

# Create file monitoring script
print_header "Creating File Monitor"
sudo tee /opt/promtail/file-monitor.sh > /dev/null <<'MONITOR_EOF'
#!/bin/bash

LOG_FILE="/var/log/file-changes/changes.log"
ERROR_LOG="/var/log/file-changes/error.log"
PID_FILE="/var/run/file-monitor.pid"

mkdir -p /var/log/file-changes

DIRS_TO_MONITOR=("/etc" "/home" "/usr/local" "/root")
EXISTING_DIRS=()

for dir in "\${DIRS_TO_MONITOR[@]}"; do
    if [ -d "\$dir" ]; then
        EXISTING_DIRS+=("\$dir")
        echo "\$(date) - Will monitor: \$dir" >> "\$ERROR_LOG"
    fi
done

if command -v nginx >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1; then
    mkdir -p /var/www
    EXISTING_DIRS+=("/var/www")
fi

echo "\$(date) - Starting file monitoring for: \${EXISTING_DIRS[*]}" >> "\$ERROR_LOG"

inotifywait -m -r -e modify,create,delete,move \\
    "\${EXISTING_DIRS[@]}" \\
    --format '%T [%w%f] %e' \\
    --timefmt '%Y-%m-%d %H:%M:%S' \\
    --exclude '/(\.(cache|local/share/Trash|git|svn)|tmp|temp|promtail)/' \\
    >> "\$LOG_FILE" 2>> "\$ERROR_LOG" &

INOTIFY_PID=\$!
echo \$INOTIFY_PID > "\$PID_FILE"
echo "\$(date) - File monitoring started. PID: \$INOTIFY_PID" >> "\$ERROR_LOG"
wait \$INOTIFY_PID
MONITOR_EOF

sudo chmod +x /opt/promtail/file-monitor.sh

# Auto-assign server number
print_header "Assigning Server Number"
assign_server_number() {
    local server_file="/etc/loki-server-number"
    
    if [ -f "\$server_file" ]; then
        cat "\$server_file"
        return
    fi
    
    print_status "Auto-assigning server number..."
    
    local existing_servers=""
    if command -v curl >/dev/null 2>&1; then
        existing_servers=\$(curl -s -G "http://\${LOKI_SERVER_IP}:3100/loki/api/v1/label/server/values" 2>/dev/null | grep -o 'server[0-9]*' | sort -V | tail -1) || true
    fi
    
    local next_number=1
    if [ -n "\$existing_servers" ]; then
        local last_number=\$(echo "\$existing_servers" | grep -o '[0-9]*\$')
        if [ -n "\$last_number" ] && [ "\$last_number" -gt 0 ]; then
            next_number=\$((last_number + 1))
        fi
    fi
    
    local server_name="server\${next_number}"
    echo "\$server_name" | sudo tee "\$server_file" >/dev/null
    echo "\$server_name"
}

SERVER_IDENTIFIER=\$(assign_server_number)
HOSTNAME=\$(hostname)
SERVER_IP=\$(hostname -I | awk '{print \$1}')
PUBLIC_IP=\$(curl -s ipinfo.io/ip 2>/dev/null || echo "unknown")

print_status "Assigned server identifier: \$SERVER_IDENTIFIER"

# Create Promtail configuration
print_header "Creating Promtail Configuration"
sudo tee /opt/promtail/config/promtail-config.yml > /dev/null <<PROMTAIL_EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /opt/promtail/data/positions.yaml

clients:
  - url: http://\${LOKI_SERVER_IP}:3100/loki/api/v1/push

scrape_configs:
  - job_name: ssh-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: ssh-logs
          server: \${SERVER_IDENTIFIER}
          hostname: \${HOSTNAME}
          private_ip: \${SERVER_IP}
          public_ip: \${PUBLIC_IP}
          __path__: /var/log/auth.log

  - job_name: system-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: system-logs
          server: \${SERVER_IDENTIFIER}
          hostname: \${HOSTNAME}
          private_ip: \${SERVER_IP}
          public_ip: \${PUBLIC_IP}
          __path__: /var/log/syslog

  - job_name: security-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: security-logs
          server: \${SERVER_IDENTIFIER}
          hostname: \${HOSTNAME}
          private_ip: \${SERVER_IP}
          public_ip: \${PUBLIC_IP}
          __path__: /var/log/secure

  - job_name: audit-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: audit-logs
          server: \${SERVER_IDENTIFIER}
          hostname: \${HOSTNAME}
          private_ip: \${SERVER_IP}
          public_ip: \${PUBLIC_IP}
          __path__: /var/log/audit/audit.log

  - job_name: file-changes
    static_configs:
      - targets:
          - localhost
        labels:
          job: file-changes
          server: \${SERVER_IDENTIFIER}
          hostname: \${HOSTNAME}
          private_ip: \${SERVER_IP}
          public_ip: \${PUBLIC_IP}
          __path__: /var/log/file-changes/changes.log

  - job_name: kernel-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: kernel-logs
          server: \${SERVER_IDENTIFIER}
          hostname: \${HOSTNAME}
          private_ip: \${SERVER_IP}
          public_ip: \${PUBLIC_IP}
          __path__: /var/log/kern.log
PROMTAIL_EOF

# Create systemd services
print_header "Creating Systemd Services"
sudo tee /etc/systemd/system/promtail.service > /dev/null <<'SERVICE_EOF'
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
SERVICE_EOF

sudo tee /etc/systemd/system/file-monitor.service > /dev/null <<'MONITOR_SERVICE_EOF'
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
MONITOR_SERVICE_EOF

# Start services
print_header "Starting Services"
sudo systemctl daemon-reload
sudo systemctl enable promtail file-monitor
sudo systemctl start promtail file-monitor

# Verify installation
print_header "Verifying Installation"
sleep 5

if sudo systemctl is-active --quiet promtail; then
    print_status "✅ Promtail service is running"
else
    print_error "❌ Promtail service failed to start"
    sudo journalctl -u promtail --no-pager -l
fi

if sudo systemctl is-active --quiet file-monitor; then
    print_status "✅ File monitor service is running"
else
    print_error "❌ File monitor service failed to start"
    sudo journalctl -u file-monitor --no-pager -l
fi

if sudo systemctl is-active --quiet auditd; then
    print_status "✅ Audit service is running"
else
    print_warning "⚠️  Audit service may not be running"
fi

# Test connectivity to Loki
if curl -s "http://\${LOKI_SERVER_IP}:3100/ready" >/dev/null 2>&1; then
    print_status "✅ Successfully connected to Loki server"
else
    print_warning "⚠️  Could not connect to Loki server at \${LOKI_SERVER_IP}:3100"
    print_warning "Please check network connectivity and firewall settings"
fi

print_header "Installation Complete!"
print_status "Server identifier: \$SERVER_IDENTIFIER"
print_status "Loki server: \$LOKI_SERVER_IP:3100"
print_status ""
print_status "To check service status:"
print_status "sudo systemctl status promtail file-monitor"
print_status ""
print_status "To view logs:"
print_status "sudo journalctl -u promtail -f"
print_status "sudo journalctl -u file-monitor -f"
EOF

    chmod +x agent-setup.sh
    print_status "Agent installation script created: agent-setup.sh"
}

# Generate summary and next steps
show_summary() {
    print_header "Installation Complete!"
    
    SERVER_IP=$(hostname -I | awk '{print $1}')
    PUBLIC_IP=$(curl -s ipinfo.io/ip 2>/dev/null || echo "Check manually")
    
    echo ""
    print_status "🎉 Loki Central Monitoring Server is now running!"
    echo ""
    print_status "📊 Access Information:"
    print_status "   Grafana Dashboard: http://$SERVER_IP:3000"
    print_status "   Loki API: http://$SERVER_IP:3100"
    print_status "   Default Login: admin / admin123"
    echo ""
    print_status "🌐 If accessing remotely:"
    print_status "   Grafana: http://$PUBLIC_IP:3000"
    print_status "   Loki: http://$PUBLIC_IP:3100"
    echo ""
    print_status "🔧 To install agents on other servers:"
    print_status "   1. Copy agent-setup.sh to target servers, or"
    print_status "   2. Run: curl -sSL http://$SERVER_IP/agent-setup.sh | bash"
    print_status "   3. Or run: wget http://$SERVER_IP/agent-setup.sh && chmod +x agent-setup.sh && ./agent-setup.sh"
    echo ""
    print_status "📋 Useful Commands:"
    print_status "   View container logs: docker-compose logs -f"
    print_status "   Restart services: docker-compose restart"
    print_status "   Stop services: docker-compose down"
    print_status "   Start services: docker-compose up -d"
    echo ""
    print_status "🔍 Check which servers are connected:"
    print_status "   curl -s 'http://localhost:3100/loki/api/v1/label/server/values' | jq"
    echo ""
    print_warning "⚠️  Security Notes:"
    print_warning "   - Change the default Grafana password"
    print_warning "   - Configure HTTPS for production use"
    print_warning "   - Review firewall settings"
    print_warning "   - The agent script contains your server IP: $SERVER_IP"
    echo ""
}

# Create simple web server for agent script distribution
create_simple_server() {
    print_header "Setting up Agent Script Distribution"
    
    # Create simple HTTP server for agent script
    cat > serve-agent.py <<EOF
#!/usr/bin/env python3
import http.server
import socketserver
import os

PORT = 8080
Handler = http.server.SimpleHTTPRequestHandler

class MyHandler(Handler):
    def do_GET(self):
        if self.path == '/agent-setup.sh':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            with open('agent-setup.sh', 'rb') as f:
                self.wfile.write(f.read())
        else:
            super().do_GET()

with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print(f"Serving agent script at http://localhost:{PORT}/agent-setup.sh")
    httpd.serve_forever()
EOF

    chmod +x serve-agent.py
    
    # Create systemd service for the simple server
    sudo tee /etc/systemd/system/loki-agent-server.service > /dev/null <<EOF
[Unit]
Description=Loki Agent Script Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PWD
ExecStart=$PWD/serve-agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable loki-agent-server
    sudo systemctl start loki-agent-server
    
    # Add firewall rule
    if command -v ufw >/dev/null 2>&1; then
        sudo ufw allow 8080/tcp comment "Loki Agent Script Server"
    fi
    
    print_status "Agent script server started on port 8080"
}

# Main execution
main() {
    print_header "Loki Central Monitoring Server Setup"
    print_status "This script will install and configure Loki + Grafana using Docker"
    
    check_root
    detect_os
    install_docker
    create_project_structure
    create_docker_compose
    create_loki_config
    create_grafana_config
    configure_firewall
    start_services
    create_agent_script
    create_simple_server
    show_summary
    
    print_status "Setup completed successfully! 🚀"
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
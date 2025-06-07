#!/bin/bash

# Central Loki Monitoring Server Setup Script
# Run this on your central monitoring server

set -e

echo "🚀 Setting up Central Loki Monitoring Server..."

# Install Docker and Docker Compose
echo "📦 Installing Docker and Docker Compose..."
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# Create project structure
echo "📁 Creating project structure..."
sudo mkdir -p /var/www
mkdir -p loki-monitoring/{config,data/loki,data/grafana}
cd loki-monitoring

# Create Docker Compose file
echo "🐳 Creating Docker Compose configuration..."
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

# Create Loki configuration
echo "⚙️ Creating Loki configuration..."
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

# Create Grafana datasource configuration
echo "📊 Creating Grafana datasource configuration..."
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

# Set up permissions and start services
echo "🔧 Setting up permissions and starting services..."
sudo mkdir -p data/loki/{chunks,rules,index}
sudo chown -R 10001:10001 data/loki
sudo chown -R 472:472 data/grafana
sudo chmod -R 755 data/

# Start services
echo "🟢 Starting Loki and Grafana..."
sudo docker-compose up -d

# Configure firewall
echo "🔥 Configuring firewall..."
sudo ufw allow 3100/tcp  # Loki
sudo ufw allow 3000/tcp  # Grafana
sudo ufw reload

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check service status
echo "🔍 Checking service status..."
sudo docker-compose ps

# Test Loki API
echo "🧪 Testing Loki API..."
if curl -s "http://localhost:3100/ready" | grep -q "ready"; then
    echo "✅ Loki is ready!"
else
    echo "❌ Loki not responding"
fi

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s ipinfo.io/ip 2>/dev/null || echo "unknown")

echo ""
echo "🎉 Central monitoring server setup complete!"
echo ""
echo "📍 Access Information:"
echo "   Grafana URL: http://$SERVER_IP:3000"
if [ "$PUBLIC_IP" != "unknown" ]; then
    echo "   Public URL:  http://$PUBLIC_IP:3000"
fi
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "🔗 Loki API: http://$SERVER_IP:3100"
echo ""
echo "📋 Next Steps:"
echo "   1. Access Grafana at the URL above"
echo "   2. Run agent setup script on your monitored servers"
echo "   3. Use this server IP in agent configuration: $SERVER_IP"
echo ""
echo "🛠️ Useful commands:"
echo "   Check logs: sudo docker-compose logs -f"
echo "   Restart: sudo docker-compose restart"
echo "   Stop: sudo docker-compose down"
# Loki + Grafana Centralized Logging Setup

This repository contains scripts to easily set up a centralized logging system using Loki and Grafana. Monitor SSH activities, file changes, and system logs across multiple servers with automatic server identification.

## 🚀 Quick Start

### 1. Setup Central Monitoring Server

Run this command on your central monitoring server:

```bash
curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/central-loki-setup.sh | bash
```

This will:
- ✅ Install Docker and Docker Compose
- ✅ Setup Loki + Grafana with proper configurations
- ✅ Configure firewall rules
- ✅ Provide access URLs and next steps

### 2. Install Agents on Target Servers

Run this command on each server you want to monitor:

```bash
LOKI_SERVER_IP="your-ip" SERVER_NAME="webserver-prod" bash -c "$(curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh)"
```

Replace `insert-your-central-server-ip` with your actual central server IP.

## 📊 What You Get

### Central Server Features:
- **Loki**: Log aggregation and storage
- **Grafana**: Beautiful dashboards and visualization  
- **Auto-configuration**: Ready-to-use setup

### Agent Features:
- **Auto-identification**: Servers identified by public IP or hostname
- **SSH monitoring**: Track login attempts and authentication
- **File change monitoring**: Real-time file modification tracking with hostname
- **System log collection**: Comprehensive system event monitoring
- **Audit logging**: Detailed security event tracking with hostname

## 🔍 Monitored Log Types

Each agent sends these log types:

| Log Type | Description | Path |
|----------|-------------|------|
| **ssh-logs** | SSH authentication events | `/var/log/auth.log` |
| **system-logs** | General system events | `/var/log/syslog` |
| **file-changes** | File modifications (custom) | `/var/log/file-changes/changes.log` |
| **audit-logs** | Security audit events | `/var/log/audit/audit.log` |
| **kernel-logs** | Kernel events | `/var/log/kern.log` |

## 📈 Access Your Dashboards

After installation, access:

- **Grafana Dashboard**: `http://YOUR_SERVER_IP:3000`
  - Username: `admin`
  - Password: `admin123`
- **Loki API**: `http://YOUR_SERVER_IP:3100`

## 🔍 Example Queries

### View all logs from a specific server:
```logql
{server="203.0.113.45"}
```

### SSH authentication failures:
```logql
{job="ssh-logs"} |= "Failed password"
```

### File changes on specific server:
```logql
{job="file-changes", server="203.0.113.45"}
```

### System errors across all servers:
```logql
{job="system-logs"} |= "ERROR"
```

### SSH activity from multiple servers:
```logql
{job="ssh-logs", server=~"203.0.113.45|198.51.100.67"}
```

### Recent audit events:
```logql
{job="audit-logs"} |= "config-changes"
```

## ⚙️ Advanced Usage

### Manual Server Naming

If you want to assign a custom server identifier:

```bash
# On the target server, before running the agent script:
echo "webserver-prod" | sudo tee /etc/server-name

# Then run the agent script
LOKI_SERVER_IP="your-ip" bash -c "$(curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh)"
```

### Dashboard Variables

Create dashboard variables in Grafana:

1. **Server Variable:**
   - Query: `label_values(server)`
   - Multi-value: ✅

2. **Log Type Variable:**
   - Query: `label_values(job)`
   - Multi-value: ✅

## 🛠️ Management Commands

### Central Server:

```bash
# Navigate to installation directory
cd loki-monitoring

# View service status
sudo docker-compose ps

# View logs
sudo docker-compose logs -f loki
sudo docker-compose logs -f grafana

# Restart services
sudo docker-compose restart

# Stop services
sudo docker-compose down

# Start services
sudo docker-compose up -d
```

### Agent Servers:

```bash
# Check service status
sudo systemctl status promtail file-monitor auditd

# View agent logs
sudo journalctl -u promtail -f
sudo journalctl -u file-monitor -f

# Restart services
sudo systemctl restart promtail file-monitor

# Test file monitoring
sudo touch /etc/test-file-$(date +%s)
sudo tail -f /var/log/file-changes/changes.log
```

## 🔍 Troubleshooting

### Check connected servers:
```bash
curl -s 'http://localhost:3100/loki/api/v1/label/server/values' | jq
```

### Test Loki connectivity:
```bash
curl -s http://YOUR_LOKI_SERVER_IP:3100/ready
```

### View recent logs:
```bash
curl -G -s "http://localhost:3100/loki/api/v1/query" \
  --data-urlencode 'query={job=~".*"}' \
  --data-urlencode 'limit=10'
```

### Common Issues:

1. **Can't connect to Loki**: Check firewall settings and ensure ports 3000, 3100 are open
2. **No logs appearing**: Verify Promtail service is running: `sudo systemctl status promtail`
3. **File monitoring not working**: Check inotify limits: `cat /proc/sys/fs/inotify/max_user_watches`
4. **Missing hostname in logs**: Restart services: `sudo systemctl restart file-monitor auditd`

### Fix File Monitor Issues:
```bash
# If file changes show $(hostname) instead of actual hostname:
sudo systemctl stop file-monitor
HOSTNAME=$(hostname)
sudo sed -i "s/\\\$(hostname)/$HOSTNAME/" /opt/promtail/file-monitor.sh
sudo systemctl start file-monitor
```

## 🔒 Security Considerations

### Production Deployment:
- ✅ Change default Grafana password
- ✅ Enable HTTPS/TLS encryption
- ✅ Configure proper firewall rules
- ✅ Use authentication for Loki API
- ✅ Regular security updates

### Network Security:
- Use private networks or VPN
- Restrict access to monitoring ports
- Enable log encryption in transit

## 📋 Requirements

### Central Server:
- Ubuntu/Debian Linux
- 2GB+ RAM
- 10GB+ disk space
- Docker support
- Ports 3000, 3100 available

### Agent Servers:
- Ubuntu/Debian Linux  
- 512MB+ RAM
- 2GB+ disk space
- Network access to central server

## 📚 File Locations

### Central Server:
- Installation directory: `~/loki-monitoring`
- Docker configs: `~/loki-monitoring/docker-compose.yml`
- Loki config: `~/loki-monitoring/config/loki-config.yaml`
- Data storage: `~/loki-monitoring/data/`

### Agent Servers:
- Promtail config: `/opt/promtail/config/promtail-config.yml`
- Server identifier: `/etc/server-name` (optional)
- File monitor script: `/opt/promtail/file-monitor.sh`
- File change logs: `/var/log/file-changes/changes.log`
- Audit rules: `/etc/audit/rules.d/file-changes.rules`

## 📊 Popular Grafana Dashboard IDs

Import these dashboard IDs in Grafana:

- **13639** - Loki Dashboard Quick Search
- **12019** - Loki Logs Dashboard  
- **14055** - Loki Stack Monitoring
- **15141** - Loki Operational Dashboard

## 🤝 Contributing

Feel free to submit issues and pull requests to improve these scripts!

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

**Happy Monitoring! 🎯**

For questions or support, please open an issue in this repository.





LOKI_SERVER_IP="18.175.149.165" SERVER_NAME="loki-pod" bash -c "$(curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh)"
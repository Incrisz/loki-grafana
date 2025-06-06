# Loki + Grafana Centralized Logging Setup

This repository contains scripts to easily set up a centralized logging system using Loki and Grafana. Monitor SSH activities, file changes, and system logs across multiple servers with automated server numbering (server1, server2, server3...).

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
- ✅ Create agent distribution server
- ✅ Provide access URLs and next steps

### 2. Install Agents on Target Servers

Run this command on each server you want to monitor:

```bash
curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh | bash -s YOUR_LOKI_SERVER_IP
```

Or if the central server is distributing the script:

```bash
curl -sSL http://YOUR_LOKI_SERVER_IP:8080/agent-setup.sh | bash
```

## 📊 What You Get

### Central Server Features:
- **Loki**: Log aggregation and storage
- **Grafana**: Beautiful dashboards and visualization  
- **Auto-configuration**: Ready-to-use setup
- **Agent distribution**: Built-in web server for easy agent deployment

### Agent Features:
- **Auto-numbering**: Servers automatically get server1, server2, server3...
- **SSH monitoring**: Track login attempts and authentication
- **File change monitoring**: Real-time file modification tracking
- **System log collection**: Comprehensive system event monitoring
- **Audit logging**: Detailed security event tracking

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
- **Agent Setup Page**: `http://YOUR_SERVER_IP:8080`

## 🔍 Example Queries

### View all logs from a specific server:
```logql
{server="server1"}
```

### SSH authentication failures:
```logql
{job="ssh-logs"} |= "Failed password"
```

### File changes on server2:
```logql
{job="file-changes", server="server2"}
```

### System errors across all servers:
```logql
{job="system-logs"} |= "ERROR"
```

### SSH activity from multiple servers:
```logql
{job="ssh-logs", server=~"server1|server2|server3"}
```

## ⚙️ Advanced Usage

### Manual Server Naming

If you want to assign a specific server number:

```bash
# On the target server, before running the agent script:
echo "server10" | sudo tee /etc/loki-server-number

# Then run the agent script
curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh | bash -s YOUR_LOKI_SERVER_IP
```

### Custom Loki Server IP

You can specify a different Loki server IP:

```bash
# Method 1: As parameter
curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh | bash -s 192.168.1.100

# Method 2: Environment variable
LOKI_SERVER=192.168.1.100 curl -sSL https://raw.githubusercontent.com/Incrisz/loki-grafana/main/agent-loki-setup.sh | bash
```

## 🛠️ Management Commands

### Central Server (run from `/opt/loki-monitoring`):

```bash
# View service status
docker-compose ps

# View logs
docker-compose logs -f loki
docker-compose logs -f grafana

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Start services
docker-compose up -d
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
- Ports 3000, 3100, 8080 available

### Agent Servers:
- Ubuntu/Debian Linux  
- 512MB+ RAM
- 2GB+ disk space
- Network access to central server

## 📚 File Locations

### Central Server:
- Installation directory: `/opt/loki-monitoring`
- Docker configs: `/opt/loki-monitoring/docker-compose.yml`
- Loki config: `/opt/loki-monitoring/config/loki-config.yaml`
- Data storage: `/opt/loki-monitoring/data/`

### Agent Servers:
- Promtail config: `/opt/promtail/config/promtail-config.yml`
- Server identifier: `/etc/loki-server-number`
- File change logs: `/var/log/file-changes/changes.log`
- Audit rules: `/etc/audit/rules.d/file-changes.rules`

## 🤝 Contributing

Feel free to submit issues and pull requests to improve these scripts!

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

**Happy Monitoring! 🎯**

For questions or support, please open an issue in this repository.
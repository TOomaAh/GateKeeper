# GateKeeper

A security monitoring and IP blocking system written in Go that detects direct IP access attempts, checks them against AbuseIPDB, and automatically blocks malicious IPs in UniFi firewalls.

## Features

- 🔍 **Direct IP Access Detection** - Monitors and logs all direct IP access attempts
- 🛡️ **Automatic IP Blocking** - Integrates with UniFi controllers to block high-risk IPs
- 📊 **AbuseIPDB Integration** - Checks IP reputation against AbuseIPDB
- 🚨 **Telegram Notifications** - Real-time alerts via Telegram with customizable templates
- 💾 **Payload Saving** - Optional request payload capture for analysis
- ⚡ **Rate Limiting** - Configurable per-IP rate limiting
- 📈 **Web Dashboard** - Modern web interface to monitor blocked IPs and statistics
- 🗄️ **SQLite Database** - Persistent storage of IP information
- 🎯 **IP Exclusion** - Whitelist trusted IPs
- 🐌 **Tarpit Mode** - Slow down high-risk attackers

## Installation

### From Source

```bash
git clone https://github.com/TOomaAh/GateKeeper.git
cd GateKeeper
go build -o gatekeeper ./cmd/gatekeeper
```

### Using Docker

```bash
docker-compose up -d
```

### Using Pre-built Binaries

Download the latest release from the [releases page](https://github.com/TOomaAh/GateKeeper/releases).

## Configuration

Create a `config.yaml` file based on `config.yaml.example`:

```yaml
notifications:
  telegram:
    - chat_id: "YOUR_TELEGRAM_CHAT_ID"
      token: "YOUR_TELEGRAM_BOT_TOKEN"

abuseip:
  api_key: "YOUR_ABUSEIPDB_API_KEY"

unifi:
  - url: "https://192.168.1.1:8443"
    username: "admin"
    password: "your_unifi_password"

ratelimit:
  enabled: true
  requests_per_minute: 5

database:
  path: "./gatekeeper.db"

payload:
  enabled: true
  max_size: 1048576  # 1MB
  directory: "./payloads"

dashboard:
  enabled: true
  port: ":8080"

excluded_ips:
  - "192.168.1.10"
  - "10.0.0.5"
```

### Configuration Options

#### Notifications
- **telegram**: List of Telegram notification configurations
  - `chat_id`: Telegram chat ID for notifications
  - `token`: Telegram bot token
  - `template`: (Optional) Custom message template

#### AbuseIPDB
- **api_key**: Your AbuseIPDB API key (get one at https://www.abuseipdb.com)

#### UniFi
- **url**: UniFi controller URL
- **username**: UniFi admin username
- **password**: UniFi admin password

You can configure multiple UniFi controllers.

#### Rate Limiting
- **enabled**: Enable/disable rate limiting
- **requests_per_minute**: Maximum requests per IP per minute

#### Database
- **path**: Path to SQLite database file

#### Payload
- **enabled**: Enable/disable payload saving
- **max_size**: Maximum payload size in bytes
- **directory**: Directory to store captured payloads

#### Dashboard
- **enabled**: Enable/disable web dashboard
- **port**: HTTP port for dashboard (e.g., `:8080`)

#### IP Exclusion
- **excluded_ips**: List of IPs to whitelist (no checks performed)

## Usage

### Running the Application

```bash
./gatekeeper -config config.yaml
```

### Docker Compose

```bash
docker-compose up -d
```

### Accessing the Dashboard

Once running, access the dashboard at: `http://localhost:8080`

The dashboard displays:
- Total IPs tracked
- Active entries
- Blocked IPs count
- Database size
- System uptime
- Recent IP activity table with scores and status

## How It Works

1. **Detection**: GateKeeper listens on port 8888 and detects direct IP access attempts
2. **Rate Limiting**: Applies per-IP rate limiting if enabled
3. **IP Check**: Queries AbuseIPDB for IP reputation score
4. **Database**: Stores IP information in SQLite with TTL
5. **Blocking**: High-risk IPs (score ≥ 75) are automatically added to UniFi firewall groups
6. **Notification**: Sends alerts via Telegram with IP details
7. **Response**:
   - High-risk IPs: Tarpit mode (slow connection)
   - Other IPs: Drop connection immediately

## API Endpoints

### Dashboard API

- `GET /api/stats` - Returns system statistics
- `GET /api/ips` - Returns list of recent IPs (last 100)

Example response for `/api/stats`:
```json
{
  "database_stats": {
    "TotalEntries": 150,
    "ActiveEntries": 45,
    "BlockedEntries": 23,
    "DBSize": 49152
  },
  "uptime": "2h15m30s",
  "timestamp": "2025-11-05T10:30:00Z"
}
```

## Building from Source

### Requirements

- Go 1.21 or higher

### Build

```bash
go build -o gatekeeper ./cmd/gatekeeper
```

### Cross-compilation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o gatekeeper-linux-amd64 ./cmd/gatekeeper

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o gatekeeper-windows-amd64.exe ./cmd/gatekeeper

# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -o gatekeeper-darwin-arm64 ./cmd/gatekeeper
```

## Development

### Project Structure

```
.
├── cmd/
│   └── gatekeeper/
│       └── main.go           # Application entry point
├── internal/
│   ├── abuseip/             # AbuseIPDB client
│   ├── cache/               # Caching layer
│   ├── config/              # Configuration management
│   ├── dashboard/           # Web dashboard
│   ├── database/            # SQLite database
│   ├── domain/              # Domain types
│   ├── gatekeeper/          # Core logic
│   ├── notification/        # Notification system
│   ├── ratelimit/           # Rate limiting
│   └── unifi/               # UniFi controller client
├── config.yaml.example      # Example configuration
├── Dockerfile               # Docker image definition
├── docker-compose.yml       # Docker compose setup
└── .goreleaser.yml          # GoReleaser configuration
```

### Running Tests

```bash
go test ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Considerations

- Store your `config.yaml` securely and never commit it to version control
- Use strong passwords for UniFi controllers
- Keep your AbuseIPDB API key confidential
- Regularly review the excluded IPs list
- Monitor the dashboard for unusual activity
- Review captured payloads for security research only

## Acknowledgments

- [AbuseIPDB](https://www.abuseipdb.com) for IP reputation data
- [UniFi Network](https://www.ui.com) for network management
- [Telegram](https://telegram.org) for notification system

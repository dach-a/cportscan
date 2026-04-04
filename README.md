# cportscan-web

An online port scanner tool with a REST API and web UI. Scan ports on any host to check their status in real-time.

## Features

- ✅ Simple, intuitive web interface
- ✅ REST API for programmatic access
- ✅ Real-time scanning with progress updates
- ✅ Rate limiting and security controls
- ✅ Blocked ports and IPs protection
- ✅ JSON export of results
- ✅ Docker-ready deployment
- ✅ Input validation and error handling
- ✅ Concurrent scan management

## Quick Start

### Using Docker Compose (Recommended)

```bash
docker-compose up
```

Visit `http://localhost:3000` in your browser.

### Manual Installation

**Requirements:**
- Node.js 18+
- npm

```bash
# Install dependencies
npm install

# Start the server
npm start
```

Server will run on `http://localhost:3000`

## Usage

### Web Interface

1. Enter a hostname or IP address
2. Specify the port range (e.g., 80-443)
3. Click "Start Scan"
4. View real-time results as ports are scanned
5. Export results as JSON

### REST API

**Start a scan:**
```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "example.com",
    "startPort": 80,
    "endPort": 443
  }'
```

Response:
```json
{
  "scanId": "uuid-here",
  "status": "initiated",
  "message": "Scan started"
}
```

**Get scan status:**
```bash
curl http://localhost:3000/api/scan/uuid-here
```

**Get all scans:**
```bash
curl http://localhost:3000/api/scans
```

**Health check:**
```bash
curl http://localhost:3000/api/health
```

## Configuration

Edit `server.js` to modify:
- `MAX_PORTS`: Maximum ports per scan (default: 1000)
- `MAX_CONCURRENT_SCANS`: Concurrent scan limit (default: 5)
- `SCAN_TIMEOUT`: Timeout per port in ms (default: 30000)
- `RATE_LIMIT`: Rate limiting rules
- `BLOCKED_PORTS`: Restricted ports
- `BLOCKED_IPS`: Blocked IP addresses

## Security Considerations

⚠️ **Important:**
- Only scan hosts you own or have permission to scan
- Respect network policies and legal requirements
- The tool blocks scanning localhost and private ranges by default
- Rate limiting prevents abuse
- Always use HTTPS in production
- Implement proper authentication for production deployments

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start a new scan |
| GET | `/api/scan/:scanId` | Get scan status and results |
| GET | `/api/scans` | Get all scans |
| GET | `/api/health` | Health check |

## Deployment

### Production with Docker

```bash
docker build -t cportscan-web .
docker run -p 3000:3000 -e NODE_ENV=production cportscan-web
```

### With Nginx reverse proxy

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        
        # Rate limiting
        limit_req zone=api burst=10 nodelay;
    }
}
```

## License

MIT

## Author

dach-a

## Contributing

Contributions welcome! Please submit issues and pull requests.

## Disclaimer

This tool is provided as-is. Users are responsible for ensuring they have proper authorization before scanning any network or host. Unauthorized network scanning may be illegal in your jurisdiction.

# Network Scanner Docker Image

A powerful network scanner with intelligent device recognition and beautiful web interface.

## Quick Start

```bash
# Pull and run
docker run -d \
  --name network-scanner \
  --network host \
  --privileged \
  -p 5000:5000 \
  urkl/network-scanner:latest

# Open browser
open http://localhost:5000
```

## Docker Compose (Recommended)

```yaml
version: '3.8'

services:
  network-scanner:
    image: urosnet/network-scanner:latest
    container_name: network_scanner
    restart: unless-stopped
    network_mode: host
    privileged: true
    environment:
      # AI Configuration (optional)
      - AI_ENABLED=false
      - AI_API_KEY=${AI_API_KEY:-}
      - AI_PROVIDER=openai
      
      # Network Configuration
      - DEFAULT_NETWORK=192.168.1.0/24
      - PREFERRED_INTERFACE=
      
      # Scan Settings
      - SCAN_TIMEOUT=300
      - TOP_PORTS=200
      - AUTO_REFRESH=true
      - VIEW_MODE=table
      
      # Flask Configuration
      - FLASK_ENV=production
      - FLASK_DEBUG=false
      - SECRET_KEY=your-secure-secret-key-here
      
    volumes:
      - ./data:/app/data:rw
      - ./config.json:/app/config.json:rw
      - ./cache:/app/cache:rw
      
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/api/results"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

## Features

- 🌐 **Real-time network scanning** with continuous device discovery
- 🧠 **AI-powered device recognition** (optional OpenAI integration)
- 🔍 **Advanced network analysis** with OS fingerprinting and service detection
- 💻 **Modern responsive web interface** with dual view modes
- 🐳 **Full Docker support** with host networking
- 🔒 **Security hardened** with input validation and security headers

## Configuration

### Environment Variables

See [full documentation](https://github.com/urkl/network-scanner#configuration) for complete configuration options.

### Volumes

- `/app/data` - Persistent storage for device data and cache
- `/app/config.json` - Runtime configuration file
- `/app/cache` - Application cache directory

### Port Requirements

- Port `5000` - Web interface
- Host networking required for full scanning capabilities

## Security Notes

⚠️ **Important**: This container requires:
- `--privileged` flag for full nmap functionality
- `--network host` for network scanning capabilities
- Only use on trusted networks you own

## Tags

- `latest` - Latest stable release
- `v1.0` - Specific version tags
- `dev` - Development builds (not recommended for production)

## Health Check

The container includes health checks that verify the web interface is responding.

## License

MIT License - see [LICENSE](https://github.com/urkl/network-scanner/blob/main/LICENSE)
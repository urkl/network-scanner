# 🌐 Network Scanner

**Advanced real-time network scanner with intelligent device recognition and beautiful web interface**

[![Docker Pulls](https://img.shields.io/docker/pulls/urosknet/network-scanner?style=for-the-badge&logo=docker)](https://hub.docker.com/r/urosknet/network-scanner)
[![Docker Image Size](https://img.shields.io/docker/image-size/urosknet/network-scanner/latest?style=for-the-badge&logo=docker)](https://hub.docker.com/r/urosknet/network-scanner)

---

## 🚀 Quick Start

### One Command Setup
```bash
docker run -d \
  --name network-scanner \
  --network host \
  --privileged \
  -e AI_ENABLED=false \
  urosknet/network-scanner:latest
```

Then open: **http://localhost:5000**

### Docker Compose (Recommended)
```yaml
version: '3.8'
services:
  network-scanner:
    image: urosknet/network-scanner:latest
    container_name: network_scanner
    restart: unless-stopped
    network_mode: host
    privileged: true
    environment:
      - AI_ENABLED=false
      # Optional: Add your OpenAI key for AI features
      # - AI_API_KEY=sk-proj-your-key-here
```

---

## ✨ Key Features

### 🚀 **Real-time Discovery**
- Continuous 3-second scanning for instant device detection
- Combined ping + ARP + nmap scanning
- Enhanced mDNS/Bonjour and UPnP/SSDP discovery

### 🧠 **Smart Recognition** 
- Automatic device categorization (router, phone, printer, IoT...)
- AI-powered device naming (optional OpenAI integration)
- MAC address vendor identification
- OS fingerprinting and service detection

### 💻 **Modern Interface**
- Real-time updates with Bootstrap 5 design
- Multi-language support (8 languages with auto-detection)
- Table and Cards view modes
- Advanced search across all device properties

---

## 🔧 Configuration

### Environment Variables
- `AI_ENABLED`: Enable AI device analysis (default: false)
- `AI_API_KEY`: OpenAI API key (required if AI enabled)
- `DEFAULT_NETWORK`: Default network range (default: 192.168.1.0/24)
- `FLASK_ENV`: Set to development for debug mode
- `SECRET_KEY`: Flask session secret (change in production!)

### Why Privileged Mode?
- **Network scanning** requires raw socket access
- **OS detection** needs privileged nmap operations
- **MAC address collection** from system ARP tables
- **Enhanced discovery** with mDNS and UPnP protocols

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/api/scan` | GET | Trigger network scan |
| `/api/results` | GET | Get scan results |
| `/api/rescan-device` | POST | Rescan specific device |

### Example Usage
```bash
# Trigger scan
curl "http://localhost:5000/api/scan?network=192.168.1.0/24"

# Get results  
curl "http://localhost:5000/api/results"
```

---

## 🛠️ Troubleshooting

### No devices detected?
```bash
# Check if container has network access
docker logs network-scanner

# Verify nmap is working
docker exec network-scanner nmap --version
```

### Permission denied?
Make sure you're using `--privileged` and `--network host` flags.

---

## 📄 License & Links

**MIT License** - Copyright (c) 2024 Uroš Kristan (Urosk.NET)

- **🐳 Docker Hub**: [urosknet/network-scanner](https://hub.docker.com/r/urosknet/network-scanner)
- **📚 Full Documentation**: [GitHub Repository](https://github.com/urkl/network-scanner)
- **🐛 Issues**: [GitHub Issues](https://github.com/urkl/network-scanner/issues)
- **🌐 Website**: [Urosk.NET](https://www.urosk.net)

---

<p align="center">
  <strong>Made with ❤️ by <a href="https://www.urosk.net">Urosk.NET</a></strong><br>
  <em>ZEN Vibe Coding - Where technology meets elegance</em>
</p>
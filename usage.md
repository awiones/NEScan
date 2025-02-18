# NEScan 

# Installation

```bash
pip install -r requirements.txt
```

### Optional Dependencies
```bash
pip install vulners shodan  # For vulnerability scanning features
```

## Features
- **Network Scanning**: CIDR range support (`192.168.1.0/24`)
- **Port Scanning**: TCP/UDP with service detection
- **Vulnerability Assessment**: Integration with Vulners/NVD APIs
- **RTSP Scanning**: Camera discovery and analysis
- **WiFi Scanning**: Nearby network detection (requires root)
- **Report Generation**: HTML/JSON/TXT outputs
- **Rate Limiting**: Customizable scanning speeds

## Basic Usage
```bash
python3 NEScan.py [OPTIONS]
```

## Command Line Options
| Option | Description |
|--------|-------------|
| `-t/--target` | Target IP, domain, or CIDR range |
| `--tcp` | TCP ports only |
| `--udp` | UDP ports only |
| `-o/--output` | Save results to file |
| `-v/--verbose` | Enable verbose output |
| `--rtsp-scan` | Enable RTSP stream scanning |
| `--wifiscan` | Scan nearby WiFi networks |
| `--api-vulners` | Vulners API key |
| `--api-nvd` | NVD API key |

## Examples

### Basic Network Scan
```bash
python3 NEScan.py -t 192.168.1.1
```

### Full Network Range Scan
```bash
python3 NEScan.py -t 10.0.0.0/24 --limit 50
```

### TCP Port Scan with Vulnerability Check
```bash
python3 NEScan.py -t example.com --tcp --api-vulners YOUR_VULNERS_KEY
```

### UDP Scan with Verbose Output
```bash
python3 NEScan.py -t 192.168.1.100 --udp -v
```

### RTSP Camera Discovery
```bash
python3 NEScan.py -t 203.0.113.5 --rtsp-scan --rtsp-depth 2
```

### WiFi Network Scan (Requires sudo)
```bash
sudo python3 NEScan.py --wifiscan
```

## API Key Configuration
1. **Vulners**: Get free API key at [vulners.com](https://vulners.com)
2. **NVD**: Get API key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)

```bash
python3 NEScan.py -t example.com --api-vulners YOUR_KEY --api-nvd YOUR_NVD_KEY
```

## Report Generation
Reports are automatically saved to:
```
results/
├── scans/
├── logs/
└── reports/
```

Sample report command:
```bash
python3 NEScan.py -t 192.168.1.1 -o scan_report.html
```

## Advanced Features

### Rate Limiting Control
```bash
python3 NEScan.py -t 10.0.0.0/24 --rate-limit-global 200 --rate-limit-host 20
```

### Custom User Agents
```bash
python3 NEScan.py -t example.com --random-user-agent
```

### Targeted WiFi Scan
```bash
sudo python3 NEScan.py --wt "HomeWiFi"
```

## Notes
1. Always get proper authorization before scanning networks
2. RTSP scanning works best with depth level 2-3
3. Vulnerability scanning requires valid API keys
4. WiFi features require Linux and root privileges

[!] LEGAL DISCLAIMER: Use this tool only on networks you own or have explicit permission to scan.

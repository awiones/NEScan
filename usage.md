# NEScan Usage Guide

## Installation

```bash
# Install required dependencies
pip install -r requirements.txt

# Optional but recommended dependencies
pip install vulners shodan dnspython python-whois

# System dependencies (Debian/Ubuntu)
sudo apt-get install nmap wireless-tools
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

| Option                     | Description                      | Example                   |
| -------------------------- | -------------------------------- | ------------------------- |
| `-t, --target`             | Target IP, domain, or CIDR range | `--target example.com`    |
| `--tcp`                    | TCP ports only                   | `--tcp`                   |
| `--udp`                    | UDP ports only                   | `--udp`                   |
| `-o, --output`             | Save results to file             | `--output scan.txt`       |
| `-v, --verbose`            | Enable verbose output            | `--verbose`               |
| `-ua, --random-user-agent` | Use random User-Agent            | `--random-user-agent`     |
| `--api-vulners`            | Vulners API key                  | `--api-vulners YOUR_KEY`  |
| `--api-nvd`                | NVD API key                      | `--api-nvd YOUR_KEY`      |
| `--rate-limit-global`      | Global rate limit (req/sec)      | `--rate-limit-global 100` |
| `--rate-limit-host`        | Per-host rate limit (req/sec)    | `--rate-limit-host 10`    |
| `--rtsp-scan`              | Enable RTSP scanning             | `--rtsp-scan`             |
| `--rtsp-port`              | RTSP port to scan                | `--rtsp-port 554`         |
| `--rtsp-depth`             | RTSP scan depth (1-3)            | `--rtsp-depth 2`          |
| `--wifiscan`               | Scan nearby WiFi networks        | `--wifiscan`              |
| `--wt`                     | Target specific WiFi SSID        | `--wt "Network_Name"`     |
| `--bypass`                 | Attempt CDN/WAF bypass           | `--bypass`                |
| `-l, --limit`              | Limit number of results          | `--limit 50`              |

## Usage Examples

### 1. Basic Scanning

```bash
# Single IP scan
python3 NEScan.py -t 192.168.1.1

# Domain scan
python3 NEScan.py -t example.com

# Network range scan
python3 NEScan.py -t 192.168.1.0/24

# Scan with output file
python3 NEScan.py -t 192.168.1.1 -o scan_results.txt

# Verbose scan with random User-Agent
python3 NEScan.py -t example.com -v --random-user-agent
```

### 2. Protocol-Specific Scanning

```bash
# TCP only scan
python3 NEScan.py -t 192.168.1.1 --tcp

# UDP only scan
python3 NEScan.py -t 192.168.1.1 --udp

# TCP scan with rate limiting
python3 NEScan.py -t 192.168.1.0/24 --tcp --rate-limit-global 50 --rate-limit-host 5
```

### 3. Vulnerability Scanning

```bash
# Scan with Vulners API
python3 NEScan.py -t example.com --api-vulners YOUR_VULNERS_KEY

# Scan with both Vulners and NVD
python3 NEScan.py -t example.com --api-vulners YOUR_VULNERS_KEY --api-nvd YOUR_NVD_KEY

# Full vulnerability scan with output
python3 NEScan.py -t example.com --api-vulners YOUR_KEY --api-nvd YOUR_KEY -o vulns.txt
```

### 4. RTSP Camera Scanning

```bash
# Basic RTSP scan
python3 NEScan.py -t 192.168.1.1 --rtsp-scan

# RTSP scan with custom port and depth
python3 NEScan.py -t 192.168.1.0/24 --rtsp-scan --rtsp-port 554 --rtsp-depth 3

# RTSP scan with limits
python3 NEScan.py -t 192.168.1.0/24 --rtsp-scan --limit 10
```

### 5. WiFi Network Scanning

```bash
# Scan all nearby networks
sudo python3 NEScan.py --wifiscan

# Scan specific network
sudo python3 NEScan.py --wt "MyNetwork"

# Save WiFi scan results
sudo python3 NEScan.py --wifiscan -o wifi_results.txt
```

### 6. CDN/WAF Bypass

```bash
# Attempt bypass for domain
python3 NEScan.py -t example.com --bypass

# Bypass with vulnerability scanning
python3 NEScan.py -t example.com --bypass --api-vulners YOUR_KEY
```

### 7. Advanced Usage

```bash
# Full scan with all features
python3 NEScan.py -t example.com \
    --api-vulners YOUR_VULNERS_KEY \
    --api-nvd YOUR_NVD_KEY \
    --bypass \
    --random-user-agent \
    -v \
    -o full_scan.txt

# Network range scan with limits and rate control
python3 NEScan.py -t 192.168.1.0/24 \
    --limit 50 \
    --rate-limit-global 100 \
    --rate-limit-host 10 \
    -o network_scan.txt

# RTSP and service scan combination
python3 NEScan.py -t 192.168.1.0/24 \
    --rtsp-scan \
    --rtsp-depth 2 \
    --tcp \
    --limit 20
```

## Output Formats

Results are saved in the `results/` directory:

```
results/
├── scans/          # Raw scan data
├── logs/           # Scan logs
└── reports/        # Formatted reports
```

## Important Notes

1. **Permissions**

   - WiFi scanning requires root privileges
   - Some ports may require root privileges for scanning

2. **Rate Limiting**

   - Adjust rate limits based on network capacity
   - Higher rates may trigger IDS/IPS systems

3. **API Keys**

   - Store API keys securely
   - Free API keys have usage limits

4. **Legal Considerations**

   - Only scan networks you own or have permission to test
   - Some scanning techniques may be restricted in your region

5. **Performance Tips**
   - Use `--limit` for large networks
   - Adjust rate limits for slower networks
   - Use protocol-specific scans when possible

## Error Handling

Common error messages and solutions:

```bash
# Permission denied
sudo python3 NEScan.py --wifiscan

# Rate limit exceeded
python3 NEScan.py -t example.com --rate-limit-global 20

# API key errors
python3 NEScan.py -t example.com --api-vulners INVALID_KEY
```

[!] LEGAL DISCLAIMER: Use this tool responsibly and only on networks you own or have explicit permission to test.

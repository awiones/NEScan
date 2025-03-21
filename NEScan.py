# =============================================================================
# Author      : awiones
# Created     : 2025-02-18
# License     : GNU General Public License v3.0
# Description : This code was developed by awiones. It is a comprehensive network
#               scanning tool designed to enumerate hosts, scan for open TCP and UDP
#               ports, retrieve DNS and HTTP information, and generate detailed reports
#               on network security and potential vulnerabilities.
# =============================================================================


import readline
import socket
import subprocess
import ssl
import os
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
import whois
import requests
import nmap
from colorama import Fore, Style, init
import time
import sys
import concurrent.futures
from typing import Dict, List, Tuple, Optional, Counter
import logging
from datetime import datetime
import pathlib
from tqdm import tqdm
import validators
import OpenSSL.SSL
from assets.user_agent.user_agent import UserAgentManager
import argparse
import ipaddress
import json
import re 
import warnings
import threading
from collections import defaultdict
from assets.udp_ports import (
    UDP_SERVICE_PORTS,
    ALL_UDP_PORTS,
    HIGH_RISK_UDP_PORTS,
    COMMON_UDP_PORTS,
    UDP_PROBES,
    UDP_RESPONSE_PATTERNS,
    get_service_ports,
    get_service_name,
    is_high_risk_port,
    get_probe_for_port,
    get_response_pattern
)
from assets.tcp_ports import (
    TCP_SERVICE_PORTS,
    HIGH_RISK_TCP_PORTS,
    COMMON_TCP_PORTS,
    TCP_SERVICE_PATTERNS,
    TCP_PROBES,
    get_service_ports as get_tcp_service_ports,
    get_service_name as get_tcp_service_name,
    is_high_risk_port as is_tcp_high_risk_port,
    get_probe_for_port as get_tcp_probe_for_port,
    get_service_pattern as get_tcp_service_pattern,
    is_common_port as is_tcp_common_port
)
from assets.rtsp_scanner import RTSPScanner, format_rtsp_results
from assets.wifi_scanner import WiFiScanner, format_wifi_results

try:
    from vulners import VulnersApi
    VULNERS_AVAILABLE = True
except ImportError:
    VULNERS_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

# Suppress the asyncore deprecation warning
warnings.filterwarnings('ignore', category=DeprecationWarning, module='pysnmp.carrier.asyncore.base')

# Initialize colorama and logging
init(autoreset=True)

# Create results directory if it doesn't exist
RESULTS_DIR = pathlib.Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

class MultipleIPScanner:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def validate_domain(self, domain: str) -> bool:
        return bool(validators.domain(domain))

    def resolve_domain_ips(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            logging.error(f"Error resolving domain {domain}: {e}")
            return []

    def display_resolved_ips(self, domain: str, ips: List[str]) -> List[str]:
        if not ips:
            print(f"{Fore.RED}[!] No IPs found for {domain}{Style.RESET_ALL}")
            return []
        
        print(f"\n{Fore.CYAN}[*] Found {len(ips)} IP(s) for {domain}:{Style.RESET_ALL}")
        for i, ip in enumerate(ips, 1):
            print(f"{i}. {ip}")
        return ips

    def ask_for_scan(self, ips: List[str]) -> List[str]:
        if not ips:
            return []
            
        while True:
            print(f"\n{Fore.YELLOW}Select IPs to scan (comma-separated numbers or 'all'):{Style.RESET_ALL}")
            try:
                choice = input("> ").strip().lower()
                if choice == 'all':
                    return ips
                    
                selected = []
                for num in choice.split(','):
                    num = int(num.strip())
                    if 1 <= num <= len(ips):
                        selected.append(ips[num-1])
                    else:
                        print(f"{Fore.RED}Invalid selection: {num}{Style.RESET_ALL}")
                        break
                else:
                    return selected
            except ValueError:
                print(f"{Fore.RED}Invalid input. Please enter numbers or 'all'{Style.RESET_ALL}")
            except KeyboardInterrupt:
                return []

# Setup logging to write to results directory
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=RESULTS_DIR / f'network_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
)

class RateLimiter:
    """Rate limiter implementation using token bucket algorithm"""
    def __init__(self, max_tokens: int, refill_rate: float):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.tokens = max_tokens
        self.last_update = time.monotonic()
        self.lock = threading.Lock()
        self.host_buckets = defaultdict(lambda: max_tokens)
        self.host_last_update = defaultdict(lambda: time.monotonic())

    def _refill_tokens(self):
        """Refill tokens based on elapsed time"""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_update = now

    def _refill_host_tokens(self, host: str):
        """Refill tokens for a specific host"""
        now = time.monotonic()
        elapsed = now - self.host_last_update[host]
        self.host_buckets[host] = min(
            self.max_tokens,
            self.host_buckets[host] + elapsed * self.refill_rate
        )
        self.host_last_update[host] = now

    def acquire(self, host: str = None) -> bool:
        """Acquire a token, returns False if no tokens available"""
        with self.lock:
            self._refill_tokens()
            if host:
                self._refill_host_tokens(host)
                
            if self.tokens < 1 or (host and self.host_buckets[host] < 1):
                return False
                
            self.tokens -= 1
            if host:
                self.host_buckets[host] -= 1
            return True

    def wait(self, host: str = None):
        """Wait until a token is available"""
        while not self.acquire(host):
            time.sleep(0.1)

class PortScanner:
    def __init__(self, rate_limiter, timeout=10):
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.service_cache = {}
        self.scan_cache = {}
        self.MAX_RETRIES = 2
        self.CHUNK_SIZE = 100  # Number of ports to scan in parallel
        self.service_patterns = {
            'http': rb'HTTP|html|<!DOCTYPE|<title',
            'ssh': rb'SSH-\d\.\d',
            'ftp': rb'FTP|FileZilla',
            'smtp': rb'SMTP|ESMTP',
            'imap': rb'IMAP|CAPABILITY',
            'pop3': rb'\+OK',
            'mysql': rb'mysql|MariaDB',
            'redis': rb'ERR|DENIED|redis',
            'mongodb': rb'MongoDB',
            'telnet': rb'Telnet|login:|password:',
            'vnc': rb'RFB \d{3}\.\d{3}',
            'dns': rb'BIND|named|dnsmasq'
        }
        # Add new service probes
        self.service_probes = {
            'http': [
                b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
                b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n'
            ],
            'https': [
                b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
            ],
            'ftp': [b'USER anonymous\r\n', b'HELP\r\n'],
            'ssh': [b'SSH-2.0-OpenSSH_8.2p1\r\n'],
            'smtp': [b'EHLO test\r\n', b'HELO test\r\n'],
            'pop3': [b'CAPA\r\n', b'USER test\r\n'],
            'imap': [b'A001 CAPABILITY\r\n'],
            'telnet': [b'\r\n', b'\x1b[A'],
            'mysql': [b'\x0c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'],
            'redis': [b'PING\r\n', b'INFO\r\n'],
            'mongodb': [b'\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff'],
            'postgresql': [b'\x00\x00\x00\x08\x04\xd2\x16\x2f'],
            'dns': [b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'],
            'rdp': [b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'],
            'vnc': [b'RFB 003.008\n']
        }

    def scan_ports_parallel(self, ip: str, ports: List[int], protocol: str = 'tcp') -> List[Tuple[int, str, str]]:
        """Scan ports in parallel with efficiency"""
        cache_key = f"{ip}:{protocol}"
        if cache_key in self.scan_cache:
            return self.scan_cache[cache_key]

        results = []
        port_chunks = [ports[i:i + self.CHUNK_SIZE] for i in range(0, len(ports), self.CHUNK_SIZE)]

        for chunk in tqdm(port_chunks, desc=f"Scanning {protocol.upper()} ports", unit="chunk"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.CHUNK_SIZE) as executor:
                future_to_port = {
                    executor.submit(
                        self._scan_single_port, ip, port, protocol
                    ): port for port in chunk
                }
                for future in concurrent.futures.as_completed(future_to_port):
                    try:
                        port, state, service = future.result()
                        if state == "open":
                            results.append((port, state, service))
                    except Exception as e:
                        logging.debug(f"Error scanning port: {e}")

        self.scan_cache[cache_key] = results
        return results

    def _scan_single_port(self, ip: str, port: int, protocol: str) -> Tuple[int, str, str]:
        """Scan a single port with service detection"""
        self.rate_limiter.wait()
        
        for _ in range(self.MAX_RETRIES):
            try:
                if protocol.lower() == 'tcp':
                    return self._scan_tcp_port(ip, port)
                else:
                    return self._scan_udp_port(ip, port)
            except socket.timeout:
                continue
            except Exception as e:
                logging.debug(f"Error scanning {protocol} port {port}: {e}")
                break

        return port, "closed", "unknown"

    def _scan_tcp_port(self, ip: str, port: int) -> Tuple[int, str, str]:
        """Enhanced TCP port scanning with better service detection"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = self._grab_banner(sock, port)
                service = self._detect_service(sock, port)
                if banner and banner != "Banner grab failed":
                    return port, "open", f"{service} - {banner}"
                return port, "open", service
            return port, "closed", "unknown"
        finally:
            sock.close()

    def _scan_udp_port(self, ip: str, port: int) -> Tuple[int, str, str]:
        """UDP port scanning with better accuracy"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout / 2)  # Shorter timeout for UDP
        
        try:
            # Send appropriate probe for the port
            probe = self._get_udp_probe(port)
            sock.sendto(probe, (ip, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                service = self._detect_udp_service(data, port)
                return port, "open", service
            except socket.timeout:
                # Additional verification for filtered ports
                if self._verify_udp_port(ip, port, sock):
                    return port, "open|filtered", "unknown"
                return port, "filtered", "unknown"
        finally:
            sock.close()

    def _detect_service(self, sock: socket.socket, port: int) -> str:
        """Enhanced service detection with banner grabbing"""
        cache_key = f"{sock.getpeername()[0]}:{port}"
        if cache_key in self.service_cache:
            return self.service_cache[cache_key]

        try:
            # Try SSL wrap for potential HTTPS
            if port in {443, 8443}:
                banner = self._grab_banner(sock, port, ssl_wrap=True)
            else:
                banner = self._grab_banner(sock, port)

            if banner and banner != "Banner grab failed":
                return banner

            return self._get_default_service(port)
        except:
            return self._get_default_service(port)

    def _grab_banner(self, sock: socket.socket, port: int, ssl_wrap: bool = False) -> str:
        """Enhanced banner grabbing with multiple probes and SSL support"""
        try:
            if ssl_wrap:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)
                except ssl.SSLError:
                    return "SSL handshake failed"

            # First try reading without sending anything
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner
            except socket.timeout:
                pass

            # Try service-specific probes
            service = self._get_default_service(port)
            probes = self.service_probes.get(service, [b'\r\n'])
            
            for probe in probes:
                try:
                    sock.send(probe)
                    response = sock.recv(1024)
                    banner = response.decode('utf-8', errors='ignore').strip()
                    if banner:
                        # Extract version information using regex patterns
                        version_info = self._extract_version_info(banner, service)
                        if version_info:
                            return version_info
                        return banner
                except (socket.timeout, socket.error):
                    continue

            return "No banner received"
        except Exception as e:
            logging.debug(f"Banner grabbing error: {e}")
            return "Banner grab failed"

    def _extract_version_info(self, banner: str, service: str) -> str:
        """Extract version information from banner using regex patterns"""
        patterns = {
            'http': r'Server: ([^\r\n]+)',
            'https': r'Server: ([^\r\n]+)',
            'ssh': r'SSH-\d+\.\d+-([\w._-]+)',
            'ftp': r'220[\w\W]*(FileZilla|ProFTPD|Pure-FTPd|vsftpd)[\w\W]*?([\d.]+)',
            'smtp': r'220[\w\W]*(Postfix|Exim|Sendmail)[\w\W]*?([\d.]+)',
            'pop3': r'\+OK[\w\W]*(Dovecot|Cyrus)[\w\W]*?([\d.]+)',
            'imap': r'\*[\w\W]*(Dovecot|Cyrus)[\w\W]*?([\d.]+)',
            'mysql': r'([.\w-]+)-(\d+\.\d+\.\d+)',
            'postgresql': r'PostgreSQL ([\d.]+)',
            'redis': r'redis_version:(\d+\.\d+\.\d+)',
            'mongodb': r'MongoDB ([\d.]+)',
            'vnc': r'RFB (\d{3}\.\d{3})',
            'telnet': r'([.\w-]+) telnetd'
        }

        if service in patterns:
            match = re.search(patterns[service], banner)
            if match:
                return f"{service} {' '.join(match.groups())}"

        return banner

    def _scan_tcp_port(self, ip: str, port: int) -> Tuple[int, str, str]:
        """TCP port scanning with better service detection"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = self._detect_service(sock, port)
                return port, "open", service
            return port, "closed", "unknown"
        finally:
            sock.close()

    def _get_service_probes(self, port: int) -> List[bytes]:
        """Get appropriate probes for service detection"""
        common_probes = {
            80: [b'GET / HTTP/1.0\r\n\r\n'],
            443: [b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'],
            22: [b'SSH-2.0-OpenSSH_8.2p1\r\n'],
            25: [b'EHLO test\r\n'],
            110: [b'CAPA\r\n'],
            143: [b'A001 CAPABILITY\r\n'],
            3306: [b'\x0c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'],
            6379: [b'PING\r\n']
        }
        return common_probes.get(port, [b'\r\n'])

    def _get_udp_probe(self, port: int) -> bytes:
        """Get appropriate UDP probe for the port"""
        udp_probes = {
            53: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x28\xf3\x17\x95\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
        }
        return udp_probes.get(port, b'\x00' * 8)

    def _verify_udp_port(self, ip: str, port: int, sock: socket.socket) -> bool:
        """Additional verification for UDP ports"""
        try:
            if port in HIGH_RISK_UDP_PORTS:
                # Send multiple probes for high-risk ports
                probes = self._get_udp_verification_probes(port)
                for probe in probes:
                    sock.sendto(probe, (ip, port))
                    try:
                        sock.recvfrom(1024)
                        return True
                    except socket.timeout:
                        continue
            return False
        except:
            return False

    def _get_default_service(self, port: int) -> str:
        """Get default service name based on port number"""
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

# Update NetworkScanner class to use the new PortScanner
from assets.ip_scanner import scan_target
from assets.whois import WhoisInfo
from assets.bypass import BypassScanner

class NetworkScanner:
    def __init__(self, verbose=False, random_ua=False, vulners_api=None, nvd_api=None, shodan_api=None,
                 rate_limit_global=100, rate_limit_host=10):
        self.nmap_scanner = nmap.PortScanner()
        self.session = requests.Session()
        self.session.timeout = 10
        self.user_agent_manager = UserAgentManager()
        self.session.headers.update({'User-Agent': self.user_agent_manager.get_random_agent()})
        
        # Create subdirectories for different types of results
        self.scans_dir = RESULTS_DIR / "scans"
        self.logs_dir = RESULTS_DIR / "logs"
        self.reports_dir = RESULTS_DIR / "reports"
        
        # Create all subdirectories
        self.scans_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)

        self.DEFAULT_TIMEOUT = 10
        self.UDP_TIMEOUT = 5  # UDP needs shorter timeout
        self.MAX_WORKERS = 50
        self.DEFAULT_PORT_RANGE = "1-1000"
        self.COMMON_TCP_PORTS = COMMON_TCP_PORTS  # Use imported TCP ports
        self.COMMON_UDP_PORTS = COMMON_UDP_PORTS
        self.verbose = verbose
        self.random_ua = random_ua
        
        # Setup logging based on verbosity
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.getLogger().setLevel(log_level)
        
        if self.random_ua:
            self.user_agent_manager = UserAgentManager()
            self.session.headers.update({'User-Agent': self.user_agent_manager.get_random_agent()})
        
        # Validate API keys before assigning
        self.vulners_api = self._validate_vulners_api(vulners_api)
        self.nvd_api = self._validate_nvd_api(nvd_api)
        self.shodan_api = self._validate_shodan_api(shodan_api)
        
        # Initialize API clients
        self.vulners_client = None
        if self.vulners_api and VULNERS_AVAILABLE:
            try:
                self.vulners_client = VulnersApi(api_key=self.vulners_api)
            except Exception as e:
                logging.warning(f"Failed to initialize Vulners API: {e}")
                self.vulners_api = None

        self.cpe_cache = {}
        self.exploit_cache = {}

        # Initialize rate limiters
        self.global_limiter = RateLimiter(max_tokens=rate_limit_global, refill_rate=rate_limit_global/2)
        self.host_limiter = RateLimiter(max_tokens=rate_limit_host, refill_rate=rate_limit_host/2)
        
        # Add rate limit parameters to instance
        self.rate_limit_global = rate_limit_global
        self.rate_limit_host = rate_limit_host

        # Add DNS availability flag
        self.dns_available = DNS_AVAILABLE

        self.port_scanner = PortScanner(self.global_limiter)

        # Add new session for IP info requests
        self.ip_info_session = requests.Session()
        self.ip_info_session.headers.update({
            'User-Agent': 'NEScan/2.1',
            'Accept': 'application/json'
        })

        self.whois_scanner = WhoisInfo()
        self.bypass_scanner = BypassScanner()
        self.force_scan = False  # Add this line

        # Add GeoIP2 availability check
        self.ip_info_session = requests.Session()
        self.ip_info_session.headers.update({
            'User-Agent': 'NEScan/2.2',
            'Accept': 'application/json'
        })

    def create_scan_directory(self, domain: str) -> pathlib.Path:
        """Create a timestamped directory for this scan's results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = self.scans_dir / f"{domain}_{timestamp}"
        scan_dir.mkdir(exist_ok=True)
        return scan_dir

    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        self.clear_screen()
        print(f"{Fore.CYAN}")
        print("╔═══════════════════════════════════════════════════════════════════════════╗")
        print("║  ███▄▄▄▄      ▄████████    ▄████████  ▄████████    ▄████████ ███▄▄▄▄      ║")
        print("║  ███▀▀▀██▄   ███    ███   ███    ███ ███    ███   ███    ███ ███▀▀▀██▄    ║")
        print("║  ███   ███   ███    █▀    ███    █▀  ███    █▀    ███    ███ ███   ███    ║")
        print("║  ███   ███  ▄███▄▄▄       ███        ███          ███    ███ ███   ███    ║")
        print("║  ███   ███ ▀▀███▀▀▀     ▀███████████ ███        ▀███████████ ███   ███    ║")
        print("║  ███   ███   ███    █▄           ███ ███    █▄    ███    ███ ███   ███    ║")
        print("║  ███   ███   ███    ███    ▄█    ███ ███    ███   ███    ███ ███   ███    ║")
        print("║   ▀█   █▀    ██████████  ▄████████▀  ████████▀    ███    █▀   ▀█   █▀     ║")
        print("╚═══════════════════════════════════════════════════════════════════════════╝")
        print(f"{Style.RESET_ALL}")
        logging.info("Starting new scan session")

    def animate_spinner(self, duration: int, message: str = "Processing"):
        end_time = time.time() + duration
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        i = 0
        while time.time() < end_time:
            sys.stdout.write(f'\r{Fore.YELLOW}{spinner[i]} {message}')
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % len(spinner)
        sys.stdout.write('\r' + ' ' * (len(message) + 2) + '\r')

    def get_ip_from_website(self, website: str) -> Optional[str]:
        try:
            ip = socket.gethostbyname(website)
            logging.info(f"Resolved {website} to {ip}")
            return ip
        except socket.gaierror as e:
            logging.error(f"Failed to resolve {website}: {e}")
            print(Fore.RED + f"Error resolving IP for {website}: {e}" + Style.RESET_ALL)
            return None

    def validate_domain(self, domain: str) -> bool:
        """Validate domain name format"""
        return bool(validators.domain(domain))

    def scan_single_port(self, ip: str, port: int, protocol: str = 'tcp') -> Tuple[int, str, Optional[str]]:
        """Scan a single port with rate limiting"""
        # Apply rate limiting
        self.global_limiter.wait()
        self.host_limiter.wait(ip)
        
        if protocol.lower() == 'tcp':
            return self._scan_tcp_port(ip, port)
        else:
            return self._scan_udp_port(ip, port)

    def _scan_tcp_port(self, ip: str, port: int) -> Tuple[int, str, Optional[str]]:
        """TCP port scanning with better service detection"""
        retries = 2
        for attempt in range(retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.DEFAULT_TIMEOUT)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        # Try to detect service
                        service = None
                        
                        # First try getting service name from our mappings
                        service_category = get_tcp_service_name(port)
                        if service_category != "Unknown":
                            service = f"{service_category} Service"
                        
                        # Then try banner grabbing if no service was identified
                        if not service:
                            service = self.get_service_banner(sock, port)
                        
                        return port, "open", service or f"{service_category} Port"
                    elif result in [111, 113]:  # Connection refused
                        return port, "closed", None
            except socket.timeout:
                if attempt == retries - 1:
                    return port, "filtered", None
            except Exception as e:
                logging.debug(f"Error scanning TCP port {port}: {e}")
                
        return port, "closed", None

    def _probe_service(self, sock: socket.socket, port: int) -> Optional[str]:
        """Send multiple probes to identify service"""
        probes = {
            'http': b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
            'ssh': b'SSH-2.0-OpenSSH_8.2p1\r\n',
            'ftp': b'USER anonymous\r\n',
            'smtp': b'EHLO test\r\n',
            'mysql': b'\x14\x00\x00\x00\x03SELECT @@version'
        }
        
        for service, probe in probes.items():
            try:
                sock.send(probe)
                response = sock.recv(1024)
                if response:
                    return response.decode('utf-8', errors='ignore').strip()
            except:
                continue
        return None

    def _get_nmap_service_info(self, ip: str, port: int) -> Optional[str]:
        """Use nmap for service detection"""
        try:
            self.nmap_scanner.scan(ip, str(port), arguments="-sV -T4 --version-intensity 5")
            service_info = self.nmap_scanner[ip]['tcp'][port]
            if service_info['name'] != 'unknown':
                return f"{service_info['name']} {service_info.get('version', '')}"
        except:
            pass
        return None

    def _scan_udp_port(self, ip: str, port: int) -> Tuple[int, str, Optional[str]]:
        """UDP port scanning with accuracy"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.UDP_TIMEOUT)
                
                # Get service details first
                service_name = get_service_name(port)
                probe = get_probe_for_port(port)
                response_pattern = get_response_pattern(service_name)
                
                sock.sendto(probe, (ip, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    if data and re.match(response_pattern, data):
                        return port, "open", f"{service_name} Service"
                    return port, "open", f"{service_name} Port"
                except socket.timeout:
                    if is_high_risk_port(port):
                        verified_port = self._verify_high_risk_udp_port(ip, port)
                        if verified_port[1] == "open":
                            return port, "open", f"{service_name} Service (High Risk)"
                    return port, "filtered", None
                    
        except Exception as e:
            logging.debug(f"Error scanning UDP port {port}: {e}")
            return port, "closed", None

    def _verify_high_risk_udp_port(self, ip: str, port: int) -> Tuple[int, str, Optional[str]]:
        """Additional verification for high-risk UDP ports"""
        try:
            # Additional probes for high-risk ports
            probes = UDP_PROBES.get(port, [b'\x00' * 8])
            if not isinstance(probes, list):
                probes = [probes]
            
            for probe in probes:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.UDP_TIMEOUT)
                    sock.sendto(probe, (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024)
                        if data:
                            return port, "open", f"High-risk port response verified"
                    except socket.timeout:
                        continue
            
            return port, "filtered", None
        except Exception as e:
            logging.debug(f"Error verifying high-risk UDP port {port}: {e}")
            return port, "closed", None

    def get_service_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Attempt to get service banner"""
        try:
            if port == 443:
                return self.get_ssl_info(sock)
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception:
            return None

    def get_ssl_info(self, sock: socket.socket) -> str:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                return f"SSL: {x509.get_subject().CN}, Expires: {x509.get_notAfter().decode()}"
        except Exception as e:
            logging.debug(f"SSL error: {e}")
            return "SSL information unavailable"

    def scan_ports(self, ip: str, port_range: str = None, protocol: str = 'tcp') -> List[Tuple[int, str]]:
        """Scan ports using concurrent execution"""
        if port_range is None:
            port_range = self.DEFAULT_PORT_RANGE
        
        try:
            start_port, end_port = map(int, port_range.split('-'))
            if (protocol.lower() == 'tcp'):
                ports = list(self.COMMON_TCP_PORTS) + list(range(start_port, end_port + 1))
            else:
                # For UDP, only scan well-known UDP ports to reduce false positives
                ports = list(self.COMMON_UDP_PORTS)
            ports = sorted(set(ports))  # Remove duplicates
        except ValueError:
            logging.error(f"Invalid port range: {port_range}")
            return []

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            future_to_port = {
                executor.submit(self.scan_single_port, ip, port, protocol): port 
                for port in ports
            }
            
            with tqdm(total=len(ports), desc=f"Scanning {protocol.upper()} ports", unit="port") as pbar:
                for future in concurrent.futures.as_completed(future_to_port):
                    port, status, banner = future.result()
                    if status == "open":
                        open_ports.append((port, banner if banner else "unknown"))
                    pbar.update(1)

        return sorted(open_ports)

    def fetch_domain_info(self, domain: str) -> Dict:
        """Fetch comprehensive domain information with rate limiting"""
        self.global_limiter.wait()
        self.host_limiter.wait(domain)
        
        results = {
            'basic_info': {},
            'dns_records': {},
            'whois_info': {},
            'security_info': {},
            'web_info': {},
            'ssl_info': {}
        }
        
        tasks = [
            ("Basic Info", self._fetch_basic_info),
            ("DNS Records", self._fetch_dns_records),
            ("WHOIS Info", self._fetch_whois_info),
            ("Security Headers", self._fetch_security_headers),
            ("Web Info", self._fetch_web_info),
            ("SSL Certificate", self._fetch_ssl_info)
        ]

        with tqdm(total=len(tasks), desc="Gathering domain info", unit="task") as pbar:
            for task_name, task_func in tasks:
                try:
                    category = task_name.lower().replace(" ", "_")
                    results[category] = task_func(domain)
                    pbar.write(f"{Fore.GREEN}✓ {task_name} collected{Style.RESET_ALL}")
                except Exception as e:
                    logging.error(f"Error in {task_name}: {e}")
                    pbar.write(f"{Fore.RED}✗ {task_name} failed: {str(e)}{Style.RESET_ALL}")
                    results[category] = None
                pbar.update(1)

        return results

    def _fetch_basic_info(self, domain: str) -> Dict:
        """Fetch basic domain information"""
        info = {
            'domain': domain,
            'created': None,
            'expires': None,
            'registrar': None,
            'status': [],
            'nameservers': []
        }
        
        try:
            w = whois.whois(domain)
            info['created'] = w.creation_date
            info['expires'] = w.expiration_date
            info['registrar'] = w.registrar
            info['status'] = w.status if isinstance(w.status, list) else [w.status] if w.status else []
            info['nameservers'] = w.name_servers if w.name_servers else []
        except Exception as e:
            logging.error(f"Error fetching basic info: {e}")
        
        return info

    def _fetch_dns_records(self, domain: str) -> Dict:
        """Fetch comprehensive DNS records"""
        records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': [],
            'CAA': [],
            'PTR': [],
            'SRV': []
        }
        
        if not self.dns_available:
            return {"error": "DNS module not available"}
        
        try:
            for record_type in records.keys():
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NXDOMAIN:
                    continue
        except Exception as e:
            logging.error(f"DNS lookup failed: {e}")
        
        return records

    def _fetch_security_headers(self, domain: str) -> Dict:
        """Fetch and analyze security headers"""
        security_headers = {
            'headers': {},
            'missing_headers': [],
            'security_score': 0,
            'recommendations': []
        }
        
        important_headers = {
            'Strict-Transport-Security': 'Enforces HTTPS connections',
            'Content-Security-Policy': 'Controls resources the browser is allowed to load',
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME-type sniffing',
            'X-XSS-Protection': 'Enables browser XSS filtering',
            'Referrer-Policy': 'Controls how much referrer information should be included',
            'Permissions-Policy': 'Controls browser features and APIs',
            'Access-Control-Allow-Origin': 'Controls cross-origin resource sharing'
        }
        
        try:
            response = self.session.head(f'https://{domain}', allow_redirects=True)
            headers = dict(response.headers)
            
            # Check for important security headers
            for header, description in important_headers.items():
                if (header in headers) and (header.lower() != 'content-security-policy'):
                    security_headers['headers'][header] = headers[header]
                    security_headers['security_score'] += 1
                else:
                    security_headers['missing_headers'].append({
                        'header': header,
                        'description': description,
                        'recommendation': f"Implement {header} header"
                    })
            
            # Normalize score to 0-100
            security_headers['security_score'] = (security_headers['security_score'] / len(important_headers)) * 100
            
        except Exception as e:
            logging.error(f"Security headers fetch failed: {e}")
        
        return security_headers

    def _fetch_web_info(self, domain: str) -> Dict:
        """Fetch web server information"""
        web_info = {
            'server': None,
            'powered_by': None,
            'technologies': [],
            'redirects': [],
            'response_time': None
        }
        
        try:
            start_time = time.time()
            response = self.session.get(f'https://{domain}', allow_redirects=True)
            web_info['response_time'] = round(time.time() - start_time, 3)
            
            headers = response.headers
            web_info['server'] = headers.get('Server')
            web_info['powered_by'] = headers.get('X-Powered-By')
            
            # Track redirects
            if response.history:
                web_info['redirects'] = [
                    {
                        'status_code': r.status_code,
                        'url': r.url,
                        'type': 'Permanent' if r.status_code == 301 else 'Temporary'
                    }
                    for r in response.history
                ]
            
        except Exception as e:
            logging.error(f"Web info fetch failed: {e}")
        
        return web_info

    def _fetch_ssl_info(self, domain: str) -> Dict:
        """Fetch SSL certificate information"""
        ssl_info = {
            'issued_to': None,
            'issued_by': None,
            'valid_from': None,
            'valid_until': None,
            'version': None,
            'serial_number': None,
            'signature_algorithm': None,
            'key_bits': None,
            'has_expired': None
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['issued_to'] = cert.get('subject')[0][0][1]
                    ssl_info['issued_by'] = cert.get('issuer')[0][0][1]
                    ssl_info['valid_from'] = cert.get('notBefore')
                    ssl_info['valid_until'] = cert.get('notAfter')
                    ssl_info['has_expired'] = ssl.cert_time_to_seconds(cert['notAfter']) < time.time()
                    
                    # Get additional cert info using OpenSSL
                    cert_bin = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    ssl_info['version'] = x509.get_version()
                    ssl_info['serial_number'] = hex(x509.get_serial_number())
                    ssl_info['signature_algorithm'] = x509.get_signature_algorithm().decode()
                    ssl_info['key_bits'] = x509.get_pubkey().bits()
                    
        except Exception as e:
            logging.error(f"SSL info fetch failed: {e}")
        
        return ssl_info

    def _print_ip_info(self, ip_info: Dict) -> None:
        """Print formatted IP information with enhanced details"""
        print(f"\n{Fore.CYAN}IP INFORMATION{Style.RESET_ALL}")
        print("=" * 70)

        # Basic IP info
        print(f"{Fore.YELLOW}Basic Information:{Style.RESET_ALL}")
        print(f"IP Address: {ip_info['ip']}")
        if ip_info.get('hostname'):
            print(f"Hostname: {ip_info['hostname']}")

        # Geolocation with more details
        geo = ip_info.get('geo_location', {})
        if geo:
            print(f"\n{Fore.YELLOW}Location Information:{Style.RESET_ALL}")
            print(f"Country: {geo.get('country', 'N/A')}")
            print(f"Region: {geo.get('region', 'N/A')}")
            print(f"City: {geo.get('city', 'N/A')}")
            print(f"Coordinates: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
            print(f"Timezone: {geo.get('timezone', 'N/A')}")

        # Network Information with enhanced details
        asn = ip_info.get('asn_info', {})
        if asn:
            print(f"\n{Fore.YELLOW}Network Information:{Style.RESET_ALL}")
            print(f"ASN: {asn.get('asn', 'N/A')}")
            print(f"Organization: {asn.get('org', 'N/A')}")
            print(f"ISP: {asn.get('isp', 'N/A')}")
            if asn.get('route'):
                print(f"Route: {asn['route']}")
            if asn.get('network_type'):
                print(f"Network Type: {asn['network_type']}")

        # Security Information
        security = ip_info.get('security_info', {})
        if security:
            print(f"\n{Fore.YELLOW}Security Information:{Style.RESET_ALL}")
            if security.get('blacklists'):
                print("Blacklist Status:")
                for bl, status in security['blacklists'].items():
                    status_color = Fore.GREEN if status == 'clean' else Fore.RED
                    print(f"• {bl}: {status_color}{status}{Style.RESET_ALL}")
            
            if security.get('threats'):
                print("\nThreat Intelligence:")
                for threat in security['threats']:
                    print(f"• {Fore.RED}{threat}{Style.RESET_ALL}")

        # CDN Information
        cdn = ip_info.get('cdn_info', {})
        if cdn.get('detected'):
            print(f"\n{Fore.YELLOW}CDN Information:{Style.RESET_ALL}")
            print(f"Provider: {cdn['provider']}")
            print(f"{Fore.RED}! Warning: Target is behind a CDN/WAF{Style.RESET_ALL}")
            if cdn.get('services'):
                print("CDN Services:")
                for service in cdn['services']:
                    print(f"• {service}")

        # DNS Information with more context
        if ip_info.get('reverse_dns'):
            print(f"\n{Fore.YELLOW}DNS Information:{Style.RESET_ALL}")
            print("Reverse DNS Records:")
            for record in ip_info['reverse_dns']:
                print(f"• {record}")
            
            if ip_info.get('dns_config'):
                print("\nDNS Configuration:")
                for config, value in ip_info['dns_config'].items():
                    print(f"• {config}: {value}")

        print("\n" + "=" * 70)

    def _format_ports(self, ports: List[Tuple[int, str]]) -> str:
        if not ports:
            return "No open ports found"
        return "\n".join([f"- Port {port}: {service}" for port, service in ports])

    def _format_ssl_info(self, ssl_info: Dict) -> str:
        if not ssl_info:
            return "No SSL information available"
        return "\n".join([
            f"- Issuer: {ssl_info.get('issuer', 'N/A')}",
            f"- Valid Until: {ssl_info.get('valid_until', 'N/A')}",
        ])

    def _format_dns_records(self, records: List[str]) -> str:
        if not records:
            return "No DNS records found"
        return "\n".join([f"- {record}" for record in records])

    def _format_headers(self, headers: Dict) -> str:
        if not headers:
            return "No HTTP headers found"
        # Fix the string formatting
        return "\n".join([f"- {k}: {v}" for k, v in headers.items()])

    def _format_section_header(self, title: str) -> str:
        """Create a formatted section header with styling"""
        width = 70
        padding = (width - len(title) - 2) // 2
        return f"""
{Fore.CYAN}╔{'═' * width}╗
║{' ' * padding}{title}{' ' * (width - len(title) - padding)}║
╚{'═' * width}╝{Style.RESET_ALL}"""

    def _format_subsection(self, title: str) -> str:
        """Create a formatted subsection header with styling"""
        return f"""
{Fore.BLUE}┌{'─' * 68}┐
│ {title:<66} │
└{'─' * 68}┘{Style.RESET_ALL}"""

    def generate_report(self, domain: str, scan_results: Dict) -> str:
        """report generation"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Get scan results
        open_ports = scan_results.get('open_ports', [])
        dns_records = scan_results.get('domain_info', {}).get('dns', [])
        headers = scan_results.get('domain_info', {}).get('headers', {})
        vulns = scan_results.get('vulnerabilities', {})
        
        # Calculate statistics
        stats = {
            'Total Open Ports': len(open_ports),
            'High-Risk Ports': sum(1 for port, _ in open_ports if port in HIGH_RISK_TCP_PORTS),
            'DNS Records': len(dns_records),
            'Security Headers': len([h for h in headers if h.lower().startswith('strict-transport-security')])
        }

        # Initialize issues dictionary
        issues = {
            'high': [],
            'medium': [],
            'low': []
        }

        # Check for security headers
        if not any(h.lower().startswith('strict-transport-security') for h in headers):
            issues['medium'].append("HSTS header not found")

        return issues

    def _format_security_analysis(self, issues: Dict) -> str:
        """Format security analysis results"""
        if not any(issues.values()):
            return "No significant security issues found.\n"

        result = []
        for severity, items in issues.items():
            if items:
                result.append(f"\n{severity.upper()} Severity Issues:")
                for item in items:
                    result.append(f"- {item}")
        
        return "\n".join(result)

    def _format_whois_info(self, whois_info: Dict) -> str:
        if not whois_info:
            return "No WHOIS information available"
        
        # Handle potentially complex date objects
        def format_date(date):
            if isinstance(date, (list, tuple)):
                date = date[0]  # Take the first date if it's a list
            return str(date) if date else 'N/A'

        return "\n".join([
            f"- Registrar: {whois_info.get('registrar', 'N/A')}",
            f"- Creation Date: {format_date(whois_info.get('creation_date', 'N/A'))}",
            f"- Expiration Date: {format_date(whois_info.get('expiration_date', 'N/A'))}",
            f"- Name Servers: {', '.join(whois_info.get('name_servers', ['N/A']))}"
        ])

    def save_scan_results(self, domain: str, scan_results: Dict, report: str) -> None:
        """Save scan results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = self.create_scan_directory(domain)
        
        # Save files with progress bar
        with tqdm(total=3, desc="Saving results", unit="file") as pbar:
            # Save main report
            report_file = self.reports_dir / f"{domain}_{timestamp}.txt"
            report_file.write_text(report)
            pbar.update(1)

            # Save raw data
            raw_data = scan_results.copy()
            raw_data['timestamp'] = raw_data['timestamp'].isoformat()
            raw_data_file = scan_dir / "raw_scan_data.json"
            with raw_data_file.open('w') as f:
                json.dump(raw_data, f, indent=4, default=str)
            pbar.update(1)

            # Save component data
            for name, data in {
                'ports': scan_results.get('open_ports', []),
                'dns': scan_results.get('domain_info', {}).get('dns', []),
                'whois': scan_results.get('domain_info', {}).get('whois', {})
            }.items():
                component_file = scan_dir / f"{name}_data.txt"
                with component_file.open('w') as f:
                    if isinstance(data, (list, dict)):
                        json.dump(data, f, indent=4, default=str)
                    else:
                        f.write(str(data))
            pbar.update(1)

        # Show save confirmation
        print(format_save_confirmation(report_file, scan_dir))

    def scan_network(self, target: str, tcp_only: bool = False, udp_only: bool = False, rtsp_scan: bool = False, rtsp_port: int = 554, rtsp_depth: int = 1, bypass: bool = False, limit: Optional[int] = None) -> List[Dict]:
        """Scan a network range or single IP with protocol options"""
        try:
            # Initialize MultipleIPScanner instance
            multiple_scanner = MultipleIPScanner()

            if bypass and validators.domain(target):
                print(f"\n{Fore.YELLOW}[*] Attempting to bypass CDN/WAF...{Style.RESET_ALL}")
                origin_ip = self.bypass_scanner.find_origin_ip(target)
                if origin_ip:
                    print(f"{Fore.GREEN}[+] Found origin IP: {origin_ip}{Style.RESET_ALL}")
                    # Only scan the origin IP when bypass is successful
                    result = self.scan_single_target(origin_ip, tcp_only, udp_only, rtsp_scan, rtsp_port, rtsp_depth)
                    if result:
                        result['domain'] = target  # Keep original domain for reference
                        result['origin_ip'] = origin_ip
                        result['bypassed'] = True
                        return [result]
                else:
                    print(f"{Fore.RED}[!] Could not find origin IP, falling back to normal scan{Style.RESET_ALL}")

            # Check if target is a domain name that needs resolution
            if multiple_scanner.validate_domain(target):
                print(f"\n{Fore.CYAN}[*] Resolving IPs for domain: {target}{Style.RESET_ALL}")
                resolved_ips = multiple_scanner.resolve_domain_ips(target)
                all_ips = multiple_scanner.display_resolved_ips(target, resolved_ips)
                
                if all_ips:
                    # Ask user which IPs to scan
                    selected_ips = multiple_scanner.ask_for_scan(all_ips)
                    if selected_ips:
                        results = []
                        for ip in tqdm(selected_ips, desc="Scanning IPs"):
                            result = self.scan_single_target(ip, tcp_only, udp_only, rtsp_scan, rtsp_port, rtsp_depth)
                            if result:
                                results.append(result)
                            if limit and len(results) >= limit:
                                break
                        return results
                    return [{'error': 'No IPs selected for scanning'}]
                return [{'error': 'No IPs found for the domain'}]

            # Network/IP scanning logic
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                results = []
                for ip in tqdm(network.hosts(), desc="Scanning network"):
                    result = self.scan_single_target(str(ip), tcp_only, udp_only, rtsp_scan, rtsp_port, rtsp_depth)
                    if result:
                        results.append(result)
                    if limit and len(results) >= limit:
                        break
                return results if results else [{'error': 'No valid results found'}]
            else:
                # Single IP scan
                result = self.scan_single_target(target, tcp_only, udp_only, rtsp_scan, rtsp_port, rtsp_depth)
                return [result] if result else [{'error': f'Scan failed for target: {target}'}]

        except ValueError as e:
            logging.error(f"Invalid target format: {e}")
            return [{'error': f'Invalid target format: {str(e)}'}]
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            return [{'error': f'Scan failed: {str(e)}'}]

    def scan_single_target(self, target: str, tcp_only: bool = False, udp_only: bool = False,
                          rtsp_scan: bool = False, rtsp_port: int = 554, rtsp_depth: int = 1) -> Dict:
        """single target scanning with automatic host detection and RTSP support"""
        try:
            # First check if the target is responsive
            ip_scan_result = scan_target(target, self.force_scan)
            
            # Get IP details first and display them
            ip_details = self.get_ip_details(target)
            self.whois_scanner.print_ip_info(ip_details)  # Print IP info immediately
            
            # Initialize scan results
            scan_results = {
                'timestamp': datetime.now(),
                'scan_type': [],
                'host_detection': ip_scan_result,
                'ip': target,
                'domain': None,
                'ip_info': ip_details
            }

            if not ip_scan_result['should_scan']:
                print(f"\n{Fore.YELLOW}[!] Host {target} appears to be down or blocking our scans")
                retry = input(f"Would you like to force scan anyway? (y/N): {Style.RESET_ALL}").lower()
                if retry == 'y':
                    self.force_scan = True
                    ip_scan_result = scan_target(target, True)
                    scan_results['host_detection'] = ip_scan_result
                else:
                    return {'error': f'Host {target} is down or blocking scans'}

            # If doing RTSP scan only
            if rtsp_scan and not (tcp_only or udp_only):
                scan_results['scan_type'].append('RTSP')
                rtsp_results = self.scan_rtsp(target, rtsp_port, rtsp_depth)
                scan_results['rtsp_scan'] = rtsp_results
                return scan_results

            # Perform regular port scanning if requested
            if not rtsp_scan or tcp_only or udp_only:
                scan_results['open_ports'] = {}
                
                if tcp_only:
                    scan_results['scan_type'].append('TCP')
                    tcp_ports = self.scan_ports(target, protocol='tcp')
                    if tcp_ports:
                        scan_results['open_ports']['tcp'] = tcp_ports
                elif udp_only:
                    scan_results['scan_type'].append('UDP')
                    udp_ports = self.scan_ports(target, protocol='udp')
                    if udp_ports:
                        scan_results['open_ports']['udp'] = udp_ports
                else:  # Full scan
                    scan_results['scan_type'].extend(['TCP', 'UDP'])
                    tcp_ports = self.scan_ports(target, protocol='tcp')
                    udp_ports = self.scan_ports(target, protocol='udp')
                    if tcp_ports:
                        scan_results['open_ports']['tcp'] = tcp_ports
                    if udp_ports:
                        scan_results['open_ports']['udp'] = udp_ports

            # Additional RTSP scan if requested alongside other scans
            if rtsp_scan:
                scan_results['scan_type'].append('RTSP')
                rtsp_results = self.scan_rtsp(target, rtsp_port, rtsp_depth)
                scan_results['rtsp_scan'] = rtsp_results

            return scan_results

        except Exception as e:
            logging.error(f"Error scanning {target}: {e}")
            return {'error': f'Scan failed for {target}: {str(e)}'}

    def save_results(self, results: List[Dict], output_file: str) -> None:
        """Save scan results to a file in the results/reports directory using target name"""
        try:
            # Get the target name from the first result
            if results and len(results) > 0:
                target_name = results[0].get('domain', results[0].get('ip', 'scan'))
            else:
                target_name = 'scan'

            # Create filename from target name and timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{target_name}_{timestamp}.txt"
            
            # Clean the filename to remove invalid characters
            filename = "".join(c for c in filename if c.isalnum() or c in '.-_')
            
            # Create full path in results/reports directory
            output_path = self.reports_dir / filename
            
            # Ensure directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:

                json.dump(results, f, indent=4, default=str)  # Fixed: removed default.str
            
            print(Fore.GREEN + f"\nResults saved to: {output_path}" + Style.RESET_ALL)
        except Exception as e:
            logging.error(f"Error saving results: {e}")
            print(Fore.RED + f"Error saving results: {e}" + Style.RESET_ALL)

    def check_vulnerabilities(self, service_info: List[Tuple[int, str]]) -> Dict:
        """vulnerability checking with better error handling"""
        vulnerabilities = {
            'summary': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'findings': [],
            'correlated_results': {},
            'exploits_available': 0,
            'status': 'No vulnerabilities found'  # Default status
        }

        if not any([self.vulners_api, self.nvd_api, self.shodan_api]):
            vulnerabilities['status'] = 'No API keys provided for vulnerability scanning'
            print(f"{Fore.YELLOW}[!] No vulnerability scanning APIs available. Please provide at least one API key.{Style.RESET_ALL}")
            return vulnerabilities

        try:
            apis_status = []
            if self.vulners_api:
                apis_status.append("Vulners")
            if self.nvd_api:
                apis_status.append("NVD")
            if self.shodan_api:
                apis_status.append("Shodan")
            
            print(f"{Fore.BLUE}[*] Using APIs for vulnerability scanning: {', '.join(apis_status)}{Style.RESET_ALL}")
            
            for port, banner in service_info:
                service_details = self._detect_service_details(port, banner)
                vuln_sources = []

                if self.vulners_client:
                    vulners_results = self._check_vulners(port, service_details)
                    if vulners_results:
                        vuln_sources.append(('vulners', vulners_results))

                if self.nvd_api:
                    nvd_results = self._check_nvd(port, service_details)
                    if nvd_results:
                        vuln_sources.append(('nvd', nvd_results))

                if vuln_sources:
                    correlated = self._correlate_vulnerabilities(vuln_sources)
                    vulnerabilities['correlated_results'][port] = correlated
                    vulnerabilities['findings'].extend(correlated)

                    # Update summary
                    for vuln in correlated:
                        if vuln.get('cvss'):
                            vulnerabilities['summary']['total'] += 1
                            if vuln['cvss'] >= 9.0:
                                vulnerabilities['summary']['critical'] += 1
                            elif vuln['cvss'] >= 7.0:
                                vulnerabilities['summary']['high'] += 1
                            elif vuln['cvss'] >= 4.0:
                                vulnerabilities['summary']['medium'] += 1
                            else:
                                vulnerabilities['summary']['low'] += 1

            # Update final status
            if vulnerabilities['summary']['total'] > 0:
                vulnerabilities['status'] = f"Found {vulnerabilities['summary']['total']} vulnerabilities"
            
            return vulnerabilities

        except Exception as e:
            logging.error(f"Error in vulnerability check: {e}")
            vulnerabilities['status'] = f"Error during vulnerability scan: {str(e)}"
            return vulnerabilities

    def _validate_vulners_api(self, api_key):
        """Validate Vulners API key with better error handling and testing"""
        if not api_key:
            return None
        try:
            print(f"{Fore.BLUE}[*] Testing Vulners API connection...{Style.RESET_ALL}")
            logging.info("Initializing Vulners API...")
            
            # Initialize VulnersApi instead of Vulners
            vulners_api = VulnersApi(
                api_key=api_key,
            )
            
            # Test with a known CVE using new method
            test_cve = "CVE-2021-44228"  # Log4Shell as test case
            test_results = vulners_api.get_bulletin(test_cve)
            
            if test_results and isinstance(test_results, dict):
                print(f"{Fore.GREEN}[✓] Vulners API key validated successfully{Style.RESET_ALL}")
                logging.info("Vulners API initialized successfully")
                return api_key
            else:
                print(f"{Fore.RED}[!] Vulners API key validation failed - Invalid response{Style.RESET_ALL}")
                return None
                
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initialize Vulners API: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Failed to initialize Vulners API: {e}")
            return None

    def _validate_nvd_api(self, api_key):
        """Validate NVD API key with improved error handling and rate limiting"""
        if not api_key:
            return None
        try:
            print(f"{Fore.BLUE}[*] Testing NVD API connection...{Style.RESET_ALL}")
            logging.info("Testing NVD API connection...")
            
            headers = {
                'apiKey': api_key,
                'Content-Type': 'application/json'
            }
            
            # Test with specific CVE to verify full access
            test_cve = "CVE-2021-44228"  # Using Log4Shell as test case
            url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
            params = {
                'cveId': test_cve,
            }
            
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    print(f"{Fore.GREEN}[✓] NVD API key validated successfully{Style.RESET_ALL}")
                    logging.info("NVD API initialized successfully")
                    # Store rate limit info
                    self.nvd_rate_limit = int(response.headers.get('X-RateLimit-Limit', 50))
                    self.nvd_rate_remaining = int(response.headers.get('X-RateLimit-Remaining', 49))
                    return api_key
                else:
                    print(f"{Fore.RED}[!] NVD API returned empty response{Style.RESET_ALL}")
            elif response.status_code == 403:
                print(f"{Fore.RED}[!] Invalid NVD API key or API key has expired{Style.RESET_ALL}")
                logging.error("Invalid NVD API key - Access denied")
            elif response.status_code == 429:
                print(f"{Fore.RED}[!] NVD API rate limit exceeded{Style.RESET_ALL}")
                logging.error("NVD API rate limit exceeded")
            else:
                print(f"{Fore.RED}[!] NVD API error: Status {response.status_code}{Style.RESET_ALL}")
                logging.error(f"NVD API error: Status {response.status_code}")
            
            return None
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Failed to connect to NVD API: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Failed to validate NVD API key: {e}")
            return None

    def _validate_shodan_api(self, api_key):
        """Validate Shodan API key"""
        if not api_key or not SHODAN_AVAILABLE:
            return None
        try:
            api = shodan.Shodan(api_key)
            api.info()
            return api_key
        except Exception as e:
            logging.error(f"Invalid Shodan API key: {e}")
            return None

    def _check_vulners(self, port: int, service_details: Dict) -> List[Dict]:
        """Check vulnerabilities using Vulners API with improved reliability"""
        self.global_limiter.wait()
        
        if not self.vulners_client:
            return []

        try:
            search_terms = []
            if service_details['name']:
                search_terms.append(service_details['name'])
            if service_details['version']:
                search_terms.append(service_details['version'])
            
            if not search_terms:
                return []
            
            search_query = ' '.join(search_terms)
            logging.debug(f"Searching Vulners for: {search_query}")
            
            vulnerabilities = []
            seen_cves = set()
            
            try:
                # Search by software name and version
                results = self.vulners_client.find_exploit_all(search_query)
                
                # Also search by CPE if available
                if service_details.get('cpe'):
                    cpe_results = self.vulners_client.find_exploit_all(
                        f'affectedSoftware.cpe23:{service_details["cpe"]}'
                    )
                    results.extend(cpe_results)
                
                # Search for bulletins
                bulletin_results = self.vulners_client.find_exploit_all(
                    f'type:bulletin AND affectedSoftware.name:"{service_details["name"]}"'
                )
                results.extend(bulletin_results)
                
                for vuln in results:
                    cve_ids = vuln.get('cvelist', [])
                    if not cve_ids:
                        continue
                    
                    for cve_id in cve_ids:
                        if cve_id in seen_cves:
                            continue
                            
                        seen_cves.add(cve_id)
                        
                        # Try to get CVSS scoring
                        cvss_score = None
                        if vuln.get('cvss', {}).get('score'):
                            cvss_score = float(vuln['cvss']['score'])
                        elif vuln.get('cvss3', {}).get('baseScore'):
                            cvss_score = float(vuln['cvss3']['baseScore'])
                        elif vuln.get('cvss2', {}).get('baseScore'):
                            cvss_score = float(vuln['cvss2']['baseScore'])
                        
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'cvss': cvss_score,
                            'description': vuln.get('description', ''),
                            'references': vuln.get('references', []),
                            'port': port,
                            'service_name': service_details['name'],
                            'version': service_details['version'],
                            'source': 'vulners',
                            'exploit_available': bool(vuln.get('exploit')),
                            'published': vuln.get('published'),
                            'type': vuln.get('type', 'unknown')
                        })
                
                print(f"{Fore.GREEN}[+] Found {len(vulnerabilities)} vulnerabilities for {service_details['name']}{Style.RESET_ALL}")
                
            except Exception as e:
                logging.error(f"Error searching Vulners: {e}")
            
            return vulnerabilities
                
        except Exception as e:
            logging.error(f"Vulners API error: {e}")
            return []

    def _check_nvd(self, port: int, service_details: Dict) -> List[Dict]:
        """Check vulnerabilities using NVD API with improved reliability and rate limiting"""
        self.global_limiter.wait()
        
        if not self.nvd_api:
            return []

        try:
            # Build search query based on CPE or service details
            if service_details['cpe']:
                search_term = service_details['cpe']
            elif service_details['name'] and service_details['version']:
                search_term = f"{service_details['name']} {service_details['version']}"
            else:
                return []

            headers = {
                'apiKey': self.nvd_api,
                'Content-Type': 'application/json'
            }
            
            # Use CPE match if available, otherwise keyword search
            if service_details['cpe']:
                params = {
                    'cpeName': service_details['cpe'],
                    'resultsPerPage': 20
                }
            else:
                params = {
                    'keywordSearch': search_term,
                    'resultsPerPage': 20
                }
            
            response = requests.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0',
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                logging.error(f"NVD API error: Status {response.status_code}")
                return []

            # Update rate limit tracking
            self.nvd_rate_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
            
            data = response.json()
            vulnerabilities = []
            
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                
                # Try to get CVSS score from v3.1, v3.0, or v2.0 in that order
                cvss_score = 0.0
                metrics = cve.get('metrics', {})
                if metrics.get('cvssMetricV31'):
                    cvss_score = float(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
                elif metrics.get('cvssMetricV30'):
                    cvss_score = float(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
                elif metrics.get('cvssMetricV2'):
                    cvss_score = float(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
                
                vulnerabilities.append({
                    'cve_id': cve.get('id'),
                    'cvss': cvss_score,
                    'description': next((desc['value'] for desc in cve.get('descriptions', []) 
                                      if desc.get('lang') == 'en'), ''),
                    'references': [ref['url'] for ref in cve.get('references', [])],
                    'port': port,
                    'service_name': service_details['name'],
                    'version': service_details['version'],
                    'source': 'nvd',
                    'published': cve.get('published'),
                    'lastModified': cve.get('lastModified'),
                    'weaknesses': [w['description'][0]['value'] 
                                 for w in cve.get('weaknesses', [])
                                 if w.get('description')]
                })
            
            return vulnerabilities

        except requests.exceptions.RequestException as e:
            logging.error(f"NVD API request error: {e}")
            return []
        except Exception as e:
            logging.error(f"NVD API error: {e}")
            return []

    def _check_shodan(self, port: int, service_details: Dict) -> List[Dict]:
        """Check vulnerabilities using Shodan API"""
        if not self.shodan_api or not SHODAN_AVAILABLE:
            return []

        try:
            api = shodan.Shodan(self.shodan_api)
            
            # Search for vulnerabilities based on service and version
            search_query = f"port:{port}"
            if service_details['name']:
                search_query += f" {service_details['name']}"
            if service_details['version']:
                search_query += f" {service_details['version']}"
                
            results = api.search(search_query)
            vulnerabilities = []
            
            for result in results['matches']:
                if 'vulns' in result:
                    for cve_id, vuln_info in result['vulns'].items():
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'cvss': float(vuln_info.get('cvss', 0)),
                            'description': vuln_info.get('summary', ''),
                            'references': [],
                            'port': port,
                            'service_name': service_details['name'],
                            'version': service_details['version'],
                            'source': 'shodan'
                        })
            
            return vulnerabilities
            
        except Exception as e:
            logging.error(f"Shodan API error: {e}")
            return []

    def _check_exploit_availability(self, cve_id: str) -> bool:
        """Check if exploits are available for a CVE"""
        if cve_id in self.exploit_cache:
            return self.exploit_cache[cve_id]

        try:
            # Check multiple sources for exploit availability
            sources = [
                self._check_exploit_db,
                self._check_metasploit,
                self._check_vulners_exploits
            ]

            for check_source in sources:
                if check_source(cve_id):
                    self.exploit_cache[cve_id] = True
                    return True

            self.exploit_cache[cve_id] = False
            return False

        except Exception as e:
            logging.error(f"Error checking exploit availability for {cve_id}: {e}")
            return False

    def _correlate_vulnerabilities(self, vuln_sources: List[Tuple[str, List[Dict]]]) -> List[Dict]:
        """Correlate vulnerability findings from multiple sources"""
        correlated = {}

        for source, findings in vuln_sources:
            for vuln in findings:
                cve_id = vuln.get('cve_id')
                if not cve_id:
                    continue

                if cve_id not in correlated:
                    correlated[cve_id] = {
                        'cve_id': cve_id,
                        'sources': [],
                        'cvss_scores': [],
                        'descriptions': [],
                        'references': set()
                    }

                correlated[cve_id]['sources'].append(source)
                if vuln.get('cvss'):
                    correlated[cve_id]['cvss_scores'].append(vuln['cvss'])
                if vuln.get('description'):
                    correlated[cve_id]['descriptions'].append(vuln['description'])
                if vuln.get('references'):
                    correlated[cve_id]['references'].update(vuln.get('references'))

        # Consolidate findings
        consolidated = []
        for cve_data in correlated.values():
            consolidated.append({
                'cve_id': cve_data['cve_id'],
                'sources': cve_data['sources'],
                'cvss': max(cve_data['cvss_scores']) if cve_data['cvss_scores'] else None,
                'description': max(cve_data['descriptions'], key=len) if cve_data['descriptions'] else None,
                'references': list(cve_data['references']),
                'confidence': len(cve_data['sources']) / len(vuln_sources)
            })

        return sorted(consolidated, key=lambda x: (x.get('cvss', 0) or 0, x['confidence']), reverse=True)

    def _detect_service_details(self, port: int, banner: str) -> Dict:
        """service detection with CPE matching"""
        service_info = {
            'name': None,
            'version': None,
            'cpe': None,
            'extra_info': {}
        }

        if not banner or banner == "unknown":
            return service_info

        # Common service patterns
        patterns = {
            'apache': r'Apache(?:/(\d+[\d.]*[^ ]*))?',
            'nginx': r'nginx(?:/(\d+[\d.]*[^ ]*))?',
            'ssh': r'SSH-(\d+[\d.]*[^ ]*)',
            'mysql': r'MySQL(?:/(\d+[\d.]*[^ ]*))?',
            'postgres': r'PostgreSQL(?:/(\d+[\d.]*[^ ]*))?'
        }

        for service, pattern in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                service_info['name'] = service
                service_info['version'] = match.group(1) if match.groups() else None
                break

        # Generate CPE if we have both name and version
        if service_info['name'] and service_info['version']:
            service_info['cpe'] = f"cpe:2.3:a:{service_info['name']}:{service_info['name']}:{service_info['version']}:*:*:*:*:*:*:*"

        return service_info

    def _check_exploit_db(self, cve_id: str) -> bool:
        """Check if exploit exists in Exploit-DB"""
        try:
            response = requests.get(
                f'https://www.exploit-db.com/search?cve={cve_id}',
                headers={'User-Agent': self.session.headers['User-Agent']}
            )
            return 'No results found' not in response.text
        except Exception:
            return False

    def _check_metasploit(self, cve_id: str) -> bool:
        """Check if exploit exists in Metasploit Framework"""
        try:
            response = requests.get(
                f'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json'
            )
            modules = response.json()
            return any(cve_id in str(module.get('references', [])) for module in modules)
        except Exception:
            return False

    def _check_vulners_exploits(self, cve_id: str) -> bool:
        """Check if exploit exists in Vulners database"""
        if not self.vulners_api or not VULNERS_AVAILABLE:
            return False

        try:
            vulners_api = VulnersApi(api_key=self.vulners_api)
            # Use new method to search for exploits
            exploits = vulners_api.find_exploit_all(cve_id)
            return len(exploits) > 0
        except Exception:
            return False

    def scan_rtsp(self, ip: str, port: int = 554, depth: int = 1) -> Dict:
        """Perform RTSP scanning using RTSPScanner directly"""
        try:
            scanner = RTSPScanner(ip, port)
            results = scanner.scan(use_auth=True, priority_level=depth)
            
            return {
                'status': 'success',
                'results': results,
                'formatted_results': format_rtsp_results(results)
            }
        except Exception as e:
            logging.error(f"RTSP scan error: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def get_ip_details(self, ip: str) -> Dict:
        """Get comprehensive IP information"""
        return self.whois_scanner.get_ip_details(ip)

    def _print_ip_info(self, ip_info: Dict) -> None:
        """Print formatted IP information with enhanced details"""
        print(f"\n{Fore.CYAN}IP INFORMATION{Style.RESET_ALL}")
        print("=" * 70)

        # Basic IP info
        print(f"{Fore.YELLOW}Basic Information:{Style.RESET_ALL}")
        print(f"IP Address: {ip_info['ip']}")
        if ip_info.get('hostname'):
            print(f"Hostname: {ip_info['hostname']}")

        # Geolocation with more details
        geo = ip_info.get('geo_location', {})
        if geo:
            print(f"\n{Fore.YELLOW}Location Information:{Style.RESET_ALL}")
            print(f"Country: {geo.get('country', 'N/A')}")
            print(f"Region: {geo.get('region', 'N/A')}")
            print(f"City: {geo.get('city', 'N/A')}")
            print(f"Coordinates: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
            print(f"Timezone: {geo.get('timezone', 'N/A')}")

        # Network Information with enhanced details
        asn = ip_info.get('asn_info', {})
        if asn:
            print(f"\n{Fore.YELLOW}Network Information:{Style.RESET_ALL}")
            print(f"ASN: {asn.get('asn', 'N/A')}")
            print(f"Organization: {asn.get('org', 'N/A')}")
            print(f"ISP: {asn.get('isp', 'N/A')}")
            if asn.get('route'):
                print(f"Route: {asn['route']}")
            if asn.get('network_type'):
                print(f"Network Type: {asn['network_type']}")

        # Security Information
        security = ip_info.get('security_info', {})
        if security:
            print(f"\n{Fore.YELLOW}Security Information:{Style.RESET_ALL}")
            if security.get('blacklists'):
                print("Blacklist Status:")
                for bl, status in security['blacklists'].items():
                    status_color = Fore.GREEN if status == 'clean' else Fore.RED
                    print(f"• {bl}: {status_color}{status}{Style.RESET_ALL}")
            
            if security.get('threats'):
                print("\nThreat Intelligence:")
                for threat in security['threats']:
                    print(f"• {Fore.RED}{threat}{Style.RESET_ALL}")

        # CDN Information
        cdn = ip_info.get('cdn_info', {})
        if cdn.get('detected'):
            print(f"\n{Fore.YELLOW}CDN Information:{Style.RESET_ALL}")
            print(f"Provider: {cdn['provider']}")
            print(f"{Fore.RED}! Warning: Target is behind a CDN/WAF{Style.RESET_ALL}")
            if cdn.get('services'):
                print("CDN Services:")
                for service in cdn['services']:
                    print(f"• {service}")

        # DNS Information with more context
        if ip_info.get('reverse_dns'):
            print(f"\n{Fore.YELLOW}DNS Information:{Style.RESET_ALL}")
            print("Reverse DNS Records:")
            for record in ip_info['reverse_dns']:
                print(f"• {record}")
            
            if ip_info.get('dns_config'):
                print("\nDNS Configuration:")
                for config, value in ip_info['dns_config'].items():
                    print(f"• {config}: {value}")

        print("\n" + "=" * 70)

    def _fetch_whois_info(self, domain: str) -> Dict:
        """Fetch detailed WHOIS information for a domain"""
        whois_info = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'last_updated': None,
            'status': [],
            'name_servers': [],
            'emails': [],
            'dnssec': None,
            'registrant': {},
            'admin': {},
            'tech': {}
        }
        
        try:
            w = whois.whois(domain)
            
            # Basic information
            whois_info['registrar'] = w.registrar
            whois_info['creation_date'] = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            whois_info['expiration_date'] = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            whois_info['last_updated'] = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date
            
            # Status codes
            if w.status:
                whois_info['status'] = w.status if isinstance(w.status, list) else [w.status]
            
            # Name servers
            if w.name_servers:
                whois_info['name_servers'] = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                whois_info['name_servers'] = [ns.lower() for ns in whois_info['name_servers']]
            
            # Emails
            if w.emails:
                whois_info['emails'] = w.emails if isinstance(w.emails, list) else [w.emails]
            
            # DNSSEC
            whois_info['dnssec'] = getattr(w, 'dnssec', None)
            
            # Contact information
            contact_fields = ['name', 'organization', 'street', 'city', 'state', 'postal_code', 'country']
            
            for contact_type in ['registrant', 'admin', 'tech']:
                for field in contact_fields:
                    key = f'{contact_type}_{field}'
                    if hasattr(w, key):
                        value = getattr(w, key)
                        if value:
                            whois_info[contact_type][field] = value
            
            # Additional parsing for specific TLDs
            if hasattr(w, 'raw'):
                raw = w.raw[0] if isinstance(w.raw, list) else w.raw
                if 'Registry Domain ID' in raw:
                    whois_info['domain_id'] = raw.split('Registry Domain ID:')[1].split('\n')[0].strip()
            
        except Exception as e:
            logging.error(f"Error fetching WHOIS info for {domain}: {e}")
            if "Connection reset by peer" in str(e):
                logging.info("Retrying WHOIS query with delay...")
                time.sleep(2)
                try:
                    return self._fetch_whois_info(domain)  # Retry once
                except:
                    pass
        
        return whois_info

def parse_arguments():
    """Parse and validate command line arguments with help display"""
    parser = argparse.ArgumentParser(
        description=f'''{Fore.CYAN}
█▄░█ █▀▀ █▀ █▀▀ ▄▀█ █▄░█
█░▀█ ██▄ ▄█ █▄▄ █▀█ █░▀█  v2.2
{Style.RESET_ALL}
Network Enumeration Scanner - A powerful network reconnaissance tool''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Target argument now uses nargs='?' to make it optional for manual handling
    parser.add_argument(
        '--target', '-t',
        nargs='?',
        const=None,
        help=f'Target IP, domain, or network range (CIDR). Use -- before targets starting with -'
    )

    # Protocol selection group
    protocol_group = parser.add_mutually_exclusive_group()
    protocol_group.add_argument(
        '--tcp',
        action='store_true',
        help='Scan TCP ports only'
    )
    protocol_group.add_argument(
        '--udp',
        action='store_true',
        help='Scan UDP ports only'
    )

    # Other optional arguments
    parser.add_argument(
        '--output', '-o',
        help='Save results to file'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--random-user-agent', '-ua',
        action='store_true',
        help='Use random User-Agent for requests'
    )

    # Add API key arguments
    parser.add_argument(
        '--api-vulners',
        help='Vulners API key for vulnerability scanning'
    )
    parser.add_argument(
        '--api-nvd',
        help='NVD API key for vulnerability scanning'
    )

    # Add rate limiting arguments
    parser.add_argument(
        '--rate-limit-global',
        type=int,
        default=100,
        help='Global rate limit (requests per second)'
    )
    parser.add_argument(
        '--rate-limit-host',
        type=int,
        default=10,
        help='Per-host rate limit (requests per second)'
    )

    # Add limit argument
    parser.add_argument(
        '--limit', '-l',
        type=int,
        help='Limit the number of results'
    )

    parser.add_argument(
        '--rtsp-scan',
        action='store_true',
        help='Scan for RTSP streams'
    )
    parser.add_argument(
        '--rtsp-port',
        type=int,
        default=554,
        help='RTSP port to scan (default: 554)'
    )
    parser.add_argument(
        '--rtsp-depth',
        type=int,
        choices=[1, 2, 3],
        default=1,
        help='RTSP scan depth (1: Common, 2: Standard, 3: All paths)'
    )

    # Add WiFi scanning arguments
    wifi_group = parser.add_mutually_exclusive_group()
    wifi_group.add_argument(
        '--wifiscan',
        action='store_true',
        help='Scan for nearby WiFi networks'
    )
    wifi_group.add_argument(
        '--wt',
        metavar='SSID',
        help='Scan a specific WiFi network by SSID'
    )

    # Add bypass option
    parser.add_argument(
        '--bypass',
        action='store_true',
        help='Attempt to bypass CDN/WAF for direct scanning'
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # If no target is provided through --target/-t, check for positional argument
    if args.target is None and not (args.wifiscan or args.wt):
        # Get all arguments that don't start with '-' or follow '--'
        possible_targets = [arg for i, arg in enumerate(sys.argv[1:]) 
                          if (not arg.startswith('-') or 
                              (i > 0 and sys.argv[i] == '--')) and 
                          not sys.argv[i].startswith('-')]
        
        if possible_targets:
            args.target = possible_targets[0]

    # Modified target validation - only require target if not doing WiFi scan
    if not args.target and not (args.wifiscan or args.wt):
        parser.error('Target is required unless using WiFi scanning options (--wifiscan or --wt)')

    return args

from assets.banner_results import format_scan_error, format_scan_success, format_save_confirmation

def format_results_for_display(results: List[Dict]) -> str:
    """Format scan results for display"""
    if not results:
        return f"{Fore.RED}[!] No scan results available{Style.RESET_ALL}"

    output = []
    for result in results:
        if 'error' in result:
            output.append(format_scan_error(result['error']))
        else:
            output.append(format_scan_success(result))

    return '\n'.join(output)

def handle_wifi_scan(args) -> None:
    """Handle WiFi scanning with error checking and sudo verification"""
    try:
        # Check if running as root/sudo
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Error: WiFi scanning requires root privileges")
            print(f"[*] Please run with sudo: sudo python3 NEScan.py --wifiscan{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}[*] Initializing WiFi Scanner...{Style.RESET_ALL}")
        wifi_scanner = WiFiScanner()
        
        try:
            if args.wt:  # Scan specific network
                print(f"{Fore.YELLOW}[+] Scanning for WiFi network: {args.wt}{Style.RESET_ALL}")
                network = wifi_scanner.scan_specific_network(args.wt)
                print(format_wifi_results([network], args.wt))
            else:  # Scan all networks
                print(f"{Fore.YELLOW}[+] Scanning for nearby WiFi networks...{Style.RESET_ALL}")
                networks = wifi_scanner.scan_networks()
                print(format_wifi_results(networks))
        except Exception as e:
            print(f"\n{Fore.RED}[!] WiFi scan failed: {str(e)}")
            print("\nTroubleshooting steps:")
            print("1. Ensure you have WiFi hardware available")
            print("2. Check if WiFi is enabled (rfkill list)")
            print("3. Verify WiFi drivers are installed")
            print(f"4. Try running: sudo rfkill unblock wifi{Style.RESET_ALL}")
            return

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}")
        print("[*] Please ensure:")
        print("    - You are running with sudo")
        print("    - WiFi hardware is available and enabled")
        print(f"    - Required packages are installed (wireless-tools){Style.RESET_ALL}")

from assets.hints import print_hint

def main():
    try:
        # Check for required dependencies before starting
        missing_deps = []
        if not VULNERS_AVAILABLE:
            missing_deps.append("vulners")
        if not SHODAN_AVAILABLE:
            missing_deps.append("shodan")
            
        if missing_deps:
            print_hint('missing_dependencies')
            
        args = parse_arguments()
        
        # Print header first
        scanner = NetworkScanner(verbose=False)  # Initialize with minimal settings first
        scanner.print_header()
        
        # Handle WiFi scanning first, before other validations
        if (args.wifiscan or args.wt):
            handle_wifi_scan(args)
            sys.exit(0)

        # Continue with normal network scanning if we get here
        # Validate APIs before showing scan information
        print("")  # Add a blank line for spacing
        if args.api_vulners or args.api_nvd:
            scanner = NetworkScanner(verbose=args.verbose, random_ua=args.random_user_agent, 
                                  vulners_api=args.api_vulners, nvd_api=args.api_nvd,
                                  rate_limit_global=args.rate_limit_global, 
                                  rate_limit_host=args.rate_limit_host)
        
        # Now show scan information
        print(f"\n{Fore.CYAN}[*] Target: {args.target}{Style.RESET_ALL}")
        
        # Only show TCP/UDP mode if RTSP scan is not exclusive
        if not args.rtsp_scan or args.tcp or args.udp:
            if args.tcp:
                print(f"{Fore.BLUE}[*] TCP scan mode{Style.RESET_ALL}")
            elif args.udp:
                print(f"{Fore.BLUE}[*] UDP scan mode{Style.RESET_ALL}")
            elif not args.rtsp_scan:  # Only show full scan mode if not RTSP-only
                print(f"{Fore.BLUE}[*] Full scan mode (TCP + UDP){Style.RESET_ALL}")
            
        if args.verbose:
            print(f"{Fore.BLUE}[*] Verbose mode enabled{Style.RESET_ALL}")
            
        if args.random_user_agent:
            print(f"{Fore.BLUE}[*] Using random User-Agent{Style.RESET_ALL}")
        if args.output:
            print(f"{Fore.BLUE}[*] Output will be saved to: {args.output}{Style.RESET_ALL}")

        if args.limit:
            print(f"{Fore.BLUE}[*] Limit is set to {args.limit}{Style.RESET_ALL}")

        if args.rtsp_scan:
            print(f"{Fore.BLUE}[*] RTSP scan mode enabled on port {args.rtsp_port} with depth {args.rtsp_depth}{Style.RESET_ALL}")

        if not args.target:
            raise ValueError("No target specified")

        # Handle WiFi scanning
        if args.wifiscan or args.wt:
            try:
                wifi_scanner = WiFiScanner()
                if args.wifiscan:
                    print(f"\n{Fore.YELLOW}[+] Scanning for nearby WiFi networks...{Style.RESET_ALL}")
                    networks = wifi_scanner.scan_networks()
                    print(format_wifi_results(networks))
                elif args.wt:
                    print(f"\n{Fore.YELLOW}[+] Scanning for WiFi network: {args.wt}{Style.RESET_ALL}")
                    network = wifi_scanner.scan_specific_network(args.wt)
                    print(format_wifi_results(network, args.wt))
                sys.exit(0)
            except Exception as e:
                print(f"\n{Fore.RED}[!] WiFi scan failed: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)

        print(f"\n{Fore.YELLOW}[+] Starting scan...{Style.RESET_ALL}")
        
        # Add usage hints for common errors
        if args.rtsp_scan and not args.target:
            print_hint('rtsp_no_target')
            sys.exit(1)
            
        if args.rtsp_port and (args.rtsp_port < 1 or args.rtsp_port > 65535):
            print_hint('invalid_port')
            sys.exit(1)
            
        if (args.api_vulners and len(args.api_vulners) < 32) or \
           (args.api_nvd and len(args.api_nvd) < 32):
            print_hint('api_key_format')
            sys.exit(1)
            
        if (args.wifiscan or args.wt) and os.geteuid() != 0:
            print_hint('wifi_sudo')
            sys.exit(1)
            
        if args.target and '/' in args.target:
            try:
                ipaddress.ip_network(args.target)
            except ValueError:
                print_hint('invalid_range')
                sys.exit(1)

        results = scanner.scan_network(
            args.target,
            tcp_only=args.tcp,
            udp_only=args.udp,
            rtsp_scan=args.rtsp_scan,
            rtsp_port=args.rtsp_port,
            rtsp_depth=args.rtsp_depth,
            bypass=args.bypass,
            limit=args.limit
        )
        
        if not results:
            print(f"\n{Fore.RED}[!] No results found{Style.RESET_ALL}")
            sys.exit(1)
        
        formatted_results = format_results_for_display(results)
        print(formatted_results)
        
        if args.output:
            scanner.save_results(results, args.output)
            
    except KeyboardInterrupt:
        print_hint('scan_interrupted')
        sys.exit(1)
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        print_hint('general', f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
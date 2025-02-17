# =============================================================================
# Author      : awiones
# Created     : 2025-02-16
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
import dns.resolver
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

try:
    import vulners
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
                self.vulners_client = vulners.VulnersApi(api_key=self.vulners_api)
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
        """Enhanced TCP port scanning with better service detection"""
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
        """Enhanced UDP port scanning with improved accuracy"""
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
        """Fetch domain information with rate limiting"""
        self.global_limiter.wait()
        self.host_limiter.wait(domain)
        
        results = {}
        tasks = [
            ("DNS Records", self._fetch_dns_records),
            ("WHOIS Info", self._fetch_whois_info),
            ("HTTP Headers", self._fetch_http_headers)
        ]

        with tqdm(total=len(tasks), desc="Gathering domain info", unit="task") as pbar:
            for task_name, task_func in tasks:
                try:
                    results[task_name.lower().replace(" ", "_")] = task_func(domain)
                except Exception as e:
                    logging.error(f"Error in {task_name}: {e}")
                    results[task_name.lower().replace(" ", "_")] = None
                pbar.update(1)

        return results

    def _fetch_dns_records(self, domain: str) -> List[str]:
        try:
            records = []
            for qtype in ['A', 'MX', 'NS', 'TXT']:
                answers = dns.resolver.resolve(domain, qtype)
                records.extend([str(rdata) for rdata in answers])
            logging.info(f"Retrieved DNS records for {domain}")
            return records
        except Exception as e:
            logging.error(f"DNS lookup failed for {domain}: {e}")
            return []

    def _fetch_whois_info(self, domain: str) -> Dict:
        try:
            w = whois.whois(domain)
            logging.info(f"Retrieved WHOIS info for {domain}")
            return {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
        except Exception as e:
            logging.error(f"WHOIS lookup failed for {domain}: {e}")
            return {}

    def _fetch_http_headers(self, domain: str) -> Dict:
        try:
            # Rotate user agent for each request
            self.session.headers.update({
                'User-Agent': self.user_agent_manager.rotate_user_agent(
                    self.session.headers.get('User-Agent')
                )
            })
            response = self.session.head(f'https://{domain}', allow_redirects=True)
            logging.info(f"Retrieved HTTP headers for {domain}")
            return dict(response.headers)
        except Exception as e:
            logging.error(f"HTTP header fetch failed for {domain}: {e}")
            return {}

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
        return "\n".join([f"- {k}: {v}" for k, v in headers.items()])

    def _format_section_header(self, title: str) -> str:
        """Create a formatted section header with improved styling"""
        width = 70
        padding = (width - len(title) - 2) // 2
        return f"""
{Fore.CYAN}╔{'═' * width}╗
║{' ' * padding}{title}{' ' * (width - len(title) - padding)}║
╚{'═' * width}╝{Style.RESET_ALL}"""

    def _format_subsection(self, title: str) -> str:
        """Create a formatted subsection header with improved styling"""
        return f"""
{Fore.BLUE}┌{'─' * 68}┐
│ {title:<66} │
└{'─' * 68}┘{Style.RESET_ALL}"""

    def generate_report(self, domain: str, scan_results: Dict) -> str:
        """Generate a detailed, well-formatted scan report"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Calculate statistics
        open_ports = scan_results.get('open_ports', [])
        dns_records = scan_results.get('domain_info', {}).get('dns', [])
        headers = scan_results.get('domain_info', {}).get('headers', {})
        
        stats = {
            'Total Open Ports': len(open_ports),
            'High-Risk Ports': sum(1 for port, _ in open_ports if port in {21, 23, 3389}),
            'DNS Records': len(dns_records),
            'Security Headers': sum(1 for h in headers if h.lower() in {
                'strict-transport-security',
                'x-xss-protection',
                'x-frame-options',
                'x-content-type-options'
            })
        }

        # Generate security analysis
        security_analysis = self.analyze_security_issues(scan_results)
        risk_score = self._calculate_risk_score(security_analysis, stats)
        
        report = f"""
{Fore.CYAN}╔{'═'*68}╗
║{' '*25}NETWORK SCAN REPORT{' '*25}║
╚{'═'*68}╝{Style.RESET_ALL}

{Fore.YELLOW}Target Information:{Style.RESET_ALL}
• Domain: {domain}
• IP Address: {scan_results.get('ip', 'N/A')}
• Scan Date: {timestamp}
• Risk Score: {self._format_risk_score(risk_score)}

{self._format_section_header('SCAN STATISTICS')}
• Open Ports: {stats['Total Open Ports']}
• High-Risk Ports: {stats['High-Risk Ports']}
• DNS Records Found: {stats['DNS Records']}
• Security Headers: {stats['Security Headers']}

{self._format_section_header('PORT SCAN RESULTS')}
{self._format_port_scan_results(open_ports)}

{self._format_section_header('DNS INFORMATION')}
{self._format_dns_info(dns_records)}

{self._format_section_header('SECURITY ANALYSIS')}
{self._format_security_analysis(security_analysis)}

{self._format_section_header('RECOMMENDATIONS')}
{self._generate_recommendations(security_analysis, stats)}
"""
        return report

    def _format_port_scan_results(self, ports: List[Tuple[int, str]]) -> str:
        if not ports:
            return f"{Fore.GREEN}[✓] No open ports found{Style.RESET_ALL}"
        
        result = []
        for port, service in sorted(ports):
            risk_level = self._get_port_risk_level(port)
            
            # Get service category and description
            if isinstance(port, int):
                tcp_service = get_tcp_service_name(port)
                udp_service = get_service_name(port)
                service_name = tcp_service if tcp_service != "Unknown" else udp_service
                
                # If service banner is "unknown", use our port mappings
                if service == "unknown" or not service:
                    if tcp_service != "Unknown":
                        service = f"{tcp_service} Service"
                    elif udp_service != "Unknown":
                        service = f"{udp_service} Service"
                    else:
                        service = "Unknown Service"
            
            color = {
                'HIGH': Fore.RED,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.GREEN
            }.get(risk_level, Fore.WHITE)
            
            icon = {
                'HIGH': '⚠',
                'MEDIUM': '•',
                'LOW': '✓'
            }.get(risk_level, '•')
            
            result.append(f"{color}{icon} Port {port:<6} │ Risk: {risk_level:<8} │ {service}{Style.RESET_ALL}")
        
        return '\n'.join([
            f"{Fore.BLUE}┌{'─' * 68}┐{Style.RESET_ALL}",
            *result,
            f"{Fore.BLUE}└{'─' * 68}┘{Style.RESET_ALL}"
        ])

    def _get_port_risk_level(self, port: int) -> str:
        """Get port risk level using the new TCP risk definitions"""
        if is_tcp_high_risk_port(port):
            return 'HIGH'
        elif is_tcp_common_port(port):
            return 'MEDIUM'
        return 'LOW'

    def _calculate_risk_score(self, security_analysis: Dict, stats: Dict) -> float:
        score = 100.0  # Start with perfect score
        
        # Deduct points for security issues
        deductions = {
            'critical': 25.0,
            'high': 15.0,
            'medium': 10.0,
            'low': 5.0
        }
        
        for severity, issues in security_analysis.items():
            score -= len(issues) * deductions[severity]
        
        # Deduct for high-risk ports
        score -= stats['High-Risk Ports'] * 10.0
        
        # Bonus for security headers
        score += stats['Security Headers'] * 5.0
        
        return max(0.0, min(100.0, score))

    def _format_risk_score(self, score: float) -> str:
        color = (Fore.RED if score < 50 else 
                Fore.YELLOW if score < 80 else 
                Fore.GREEN)
        bars = int(score / 10)
        bar_str = f"[{'█' * bars}{'░' * (10-bars)}]"
        return f"{color}{bar_str} {score:.1f}/100{Style.RESET_ALL}"

    def _generate_recommendations(self, security_analysis: Dict, stats: Dict) -> str:
        recommendations = []
        
        if security_analysis['critical'] or security_analysis['high']:
            recommendations.append(f"{Fore.RED}[!] URGENT ACTIONS REQUIRED:{Style.RESET_ALL}")
            for issue in security_analysis['critical'] + security_analysis['high']:
                recommendations.append(f"{Fore.RED}▶ {issue}{Style.RESET_ALL}")
        
        if stats['High-Risk Ports'] > 0:
            recommendations.append(f"\n{Fore.YELLOW}[!] PORT SECURITY:{Style.RESET_ALL}")
            recommendations.append(f"{Fore.YELLOW}▶ Consider closing or restricting access to high-risk ports")
            recommendations.append(f"▶ Implement firewall rules to limit access to necessary IPs only{Style.RESET_ALL}")
        
        if stats['Security Headers'] < 4:
            recommendations.append(f"\n{Fore.YELLOW}[!] WEB SECURITY:{Style.RESET_ALL}")
            recommendations.append(f"{Fore.YELLOW}▶ Implement missing security headers")
            recommendations.append(f"▶ Enable HSTS for HTTPS enforcement{Style.RESET_ALL}")
        
        return '\n'.join(recommendations) if recommendations else f"{Fore.GREEN}[✓] No immediate actions required.{Style.RESET_ALL}"

    def _format_dns_info(self, records: List[str]) -> str:
        if not records:
            return f"{Fore.YELLOW}[!] No DNS records found{Style.RESET_ALL}"
        
        formatted = []
        record_types = Counter(r.split()[3] for r in records)
        
        # Summary box
        formatted.append(f"{Fore.BLUE}┌{'─' * 68}┐{Style.RESET_ALL}")
        formatted.append(f"{Fore.BLUE}│ {'Record Distribution':^66} │{Style.RESET_ALL}")
        formatted.append(f"{Fore.BLUE}├{'─' * 68}┤{Style.RESET_ALL}")
        
        for rtype, count in record_types.items():
            formatted.append(f"{Fore.BLUE}│ {Style.RESET_ALL}{rtype:<15}: {count:>3} records {' ' * 43}{Fore.BLUE}│{Style.RESET_ALL}")
        
        formatted.append(f"{Fore.BLUE}└{'─' * 68}┘{Style.RESET_ALL}")
        
        # Detailed records
        formatted.append(f"\n{Fore.YELLOW}Detailed Records:{Style.RESET_ALL}")
        for record in records:
            formatted.append(f"▶ {record}")
        
        return '\n'.join(formatted)

    def analyze_security_issues(self, scan_results: Dict) -> Dict:
        """Analyze scan results for security issues"""
        issues = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        # Check for common security issues
        open_ports = scan_results.get('open_ports', [])
        for port, service in open_ports:
            if port in {21, 23, 3389}:
                issues['high'].append(f"Potentially dangerous port {port} ({service}) is open")
            elif port in {80, 443}:
                if not any(h.lower().startswith('strict-transport-security') 
                          for h in scan_results.get('domain_info', {}).get('headers', {})):
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
        """Save all scan results to appropriate directories with visual feedback"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = self.create_scan_directory(domain)

        # Progress animation
        with tqdm(total=5, desc="Saving results", unit="file") as pbar:
            # Save the main report
            report_file = self.reports_dir / f"{domain}_{timestamp}.txt"
            report_file.write_text(report)
            pbar.update(1)

            # Save raw scan data
            scan_results_copy = scan_results.copy()
            scan_results_copy['timestamp'] = scan_results_copy['timestamp'].isoformat()
            raw_data_file = scan_dir / "raw_scan_data.json"
            with raw_data_file.open('w') as f:
                json.dump(scan_results_copy, f, indent=4, default=str)
            pbar.update(1)

            # Save component results
            components = {
                'ports': scan_results.get('open_ports', []),
                'dns': scan_results.get('domain_info', {}).get('dns', []),
                'headers': scan_results.get('domain_info', {}).get('headers', {}),
                'whois': scan_results.get('domain_info', {}).get('whois', {})
            }

            for component, data in components.items():
                component_file = scan_dir / f"{component}_data.txt"
                with component_file.open('w') as f:
                    if isinstance(data, (list, dict)):
                        f.write(json.dumps(data, indent=4, default=str))
                    else:
                        f.write(str(data))
                pbar.update(1)

        # Show save summary
        print(f"\n{Fore.GREEN}╔{'═' * 68}╗")
        print(f"║ {'Scan Results Saved Successfully':^66} ║")
        print(f"╠{'═' * 68}╣")
        print(f"║ Report: {str(report_file):<58} ║")
        print(f"║ Details: {str(scan_dir):<57} ║")
        print(f"╚{'═' * 68}╝{Style.RESET_ALL}") 
    def scan_network(self, target: str, tcp_only: bool = False, udp_only: bool = False, limit: Optional[int] = None) -> List[Dict]:
        """Scan a network range or single IP with protocol options"""
        try:
            # Check if target is a network range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                results = []
                for ip in tqdm(network.hosts(), desc="Scanning network"):
                    result = self.scan_single_target(str(ip), tcp_only, udp_only)
                    if result:  # Only append if we got valid results
                        results.append(result)
                    if limit and len(results) >= limit:
                        break
                return results if results else [{'error': 'No valid results found'}]
            else:
                # Single IP or domain scan
                result = self.scan_single_target(target, tcp_only, udp_only)
                return [result] if result else [{'error': f'Scan failed for target: {target}'}]
        except ValueError as e:
            logging.error(f"Invalid target format: {e}")
            return [{'error': f'Invalid target format: {str(e)}'}]
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            return [{'error': f'Scan failed: {str(e)}'}]

    def scan_single_target(self, target: str, tcp_only: bool = False, udp_only: bool = False) -> Dict:
        """Scan a single IP or domain with protocol options"""
        try:
            if validators.domain(target):
                ip = self.get_ip_from_website(target)
                if not ip:
                    return {'error': f'Could not resolve IP for {target}'}
                domain = target
            else:
                ip = target
                try:
                    domain = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    domain = ip

            # Initialize scan results with default values
            scan_results = {
                'ip': ip,
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'open_ports': {},
                'domain_info': {},
                'vulnerabilities': {
                    'vulners': [],
                    'nvd': [],
                    'status': 'No vulnerabilities found'
                }
            }

            # Scan based on protocol selection
            if tcp_only:
                tcp_ports = self.scan_ports(ip, protocol='tcp')
                if tcp_ports:  # Only add if ports were found
                    scan_results['open_ports']['tcp'] = tcp_ports
            elif udp_only:
                udp_ports = self.scan_ports(ip, protocol='udp')
                if udp_ports:  # Only add if ports were found
                    scan_results['open_ports']['udp'] = udp_ports
            else:
                # Default: scan both TCP and UDP
                tcp_ports = self.scan_ports(ip, protocol='tcp')
                udp_ports = self.scan_ports(ip, protocol='udp')
                if tcp_ports:
                    scan_results['open_ports']['tcp'] = tcp_ports
                if udp_ports:
                    scan_results['open_ports']['udp'] = udp_ports

            # Fetch domain info if it's a valid domain
            if validators.domain(domain):
                domain_info = self.fetch_domain_info(domain)
                if domain_info:
                    scan_results['domain_info'] = domain_info

            # Add vulnerability check results for open ports
            all_ports = []
            if 'tcp' in scan_results['open_ports']:
                all_ports.extend(scan_results['open_ports']['tcp'])
            if 'udp' in scan_results['open_ports']:
                all_ports.extend(scan_results['open_ports']['udp'])

            if all_ports:
                vuln_results = self.check_vulnerabilities(all_ports)
                if vuln_results:
                    scan_results['vulnerabilities'] = vuln_results

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
        """Enhanced vulnerability checking with better error handling"""
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
        """Validate Vulners API key"""
        if not api_key:
            return None
        try:
            # Test the API key with a simple query
            logging.info(f"Initializing Vulners API...")
            print(f"{Fore.BLUE}[*] Initializing Vulners API...{Style.RESET_ALL}")
            
            client = vulners.VulnersApi(api_key=api_key)
            # Test API with a simple search
            test_results = client.find_exploit("apache")
            
            if test_results:
                logging.info("Vulners API initialized successfully")
                print(f"{Fore.GREEN}[✓] Vulners API key validated successfully{Style.RESET_ALL}")
                return api_key
            else:
                logging.error("Invalid Vulners API response")
                print(f"{Fore.RED}[!] Invalid Vulners API response{Style.RESET_ALL}")
                return None
                
        except Exception as e:
            logging.error(f"Invalid Vulners API key: {e}")
            print(f"{Fore.RED}[!] Vulners API validation failed: {e}{Style.RESET_ALL}")
            return None

    def _validate_nvd_api(self, api_key):
        """Validate NVD API key"""
        if not api_key:
            return None
        try:
            print(f"{Fore.BLUE}[*] Initializing NVD API...{Style.RESET_ALL}")
            logging.info("Testing NVD API connection...")
            
            headers = {
                'apiKey': api_key,
                'Content-Type': 'application/json'
            }
            
            # Test the API with a simple query
            response = requests.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0',
                params={'resultsPerPage': 1},
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"{Fore.GREEN}[✓] NVD API key validated successfully{Style.RESET_ALL}")
                logging.info("NVD API initialized successfully")
                return api_key
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
        """Check vulnerabilities using Vulners API with rate limiting"""
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
            
            results = self.vulners_client.find_exploit(search_query)
            
            vulnerabilities = []
            for vuln in results:
                if not vuln.get('cvelist'):
                    continue
                    
                for cve_id in vuln.get('cvelist', []):
                    vulnerabilities.append({
                        'cve_id': cve_id,
                        'cvss': float(vuln.get('cvss', {}).get('score', 0)),
                        'description': vuln.get('description', ''),
                        'references': vuln.get('references', []),
                        'port': port,
                        'service_name': service_details['name'],
                        'version': service_details['version'],
                        'source': 'vulners'
                    })
            
            return vulnerabilities
            
        except Exception as e:
            logging.error(f"Vulners API error: {e}")
            return []

    def _check_nvd(self, port: int, service_details: Dict) -> List[Dict]:
        """Check vulnerabilities using NVD API with rate limiting"""
        self.global_limiter.wait()
        
        if not self.nvd_api:
            return []

        try:
            # Build search query based on CPE or service details
            search_term = service_details.get('cpe')
            if not search_term and service_details['name']:
                search_term = f"{service_details['name']}"
                if service_details['version']:
                    search_term += f" {service_details['version']}"

            if not search_term:
                return []

            headers = {
                'apiKey': self.nvd_api,
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0',
                params={
                    'keywordSearch': search_term,
                    'resultsPerPage': 20
                },
                headers=headers
            )
            
            if response.status_code != 200:
                return []

            data = response.json()
            vulnerabilities = []
            
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
                
                vulnerabilities.append({
                    'cve_id': cve.get('id'),
                    'cvss': float(metrics.get('baseScore', 0)),
                    'description': next((desc['value'] for desc in cve.get('descriptions', []) 
                                      if desc.get('lang') == 'en'), ''),
                    'references': [ref['url'] for ref in cve.get('references', [])],
                    'port': port,
                    'service_name': service_details['name'],
                    'version': service_details['version'],
                    'source': 'nvd'
                })
                
            return vulnerabilities

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
        """Enhanced service detection with CPE matching"""
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
            vulners_api = vulners.Vulners(api_key=self.vulners_api)
            exploits = vulners_api.searchExploit(cve_id)
            return len(exploits) > 0
        except Exception:
            return False

def parse_arguments():
    """Parse and validate command line arguments with improved help display"""
    parser = argparse.ArgumentParser(
        description=f'''{Fore.CYAN}
█▄░█ █▀▀ █▀ █▀▀ ▄▀█ █▄░█
█░▀█ ██▄ ▄█ █▄▄ █▀█ █░▀█  v2.0
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

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # If no target is provided through --target/-t, check for positional argument
    if args.target is None:
        # Get all arguments that don't start with '-' or follow '--'
        possible_targets = [arg for i, arg in enumerate(sys.argv[1:]) 
                          if (not arg.startswith('-') or 
                              (i > 0 and sys.argv[i] == '--')) and 
                          not sys.argv[i].startswith('-')]
        
        if possible_targets:
            args.target = possible_targets[0]
        else:
            parser.error('Target is required. For targets starting with -, use: -- -example.com')

    return args

def format_results_for_display(results: List[Dict]) -> str:
    """Format scan results for display with improved UI"""
    def _get_port_risk_level(port: int) -> str:
        """Determine risk level of a port"""
        high_risk = {21, 23, 3389, 445, 135, 139}
        medium_risk = {80, 443, 8080, 8443, 3306, 5432}
        return 'HIGH' if port in high_risk else 'MEDIUM' if port in medium_risk else 'LOW'

    if not results:
        return f"{Fore.RED}[!] No scan results available{Style.RESET_ALL}"

    output = []
    
    for result in results:
        # Handle error results
        if 'error' in result:
            output.append(f"{Fore.RED}╔{'═' * 68}╗")
            output.append(f"║{' '*25}SCAN ERROR{' '*34}║")
            output.append(f"╚{'═' * 68}╝{Style.RESET_ALL}")
            output.append(f"\n{Fore.RED}[!] {result['error']}{Style.RESET_ALL}\n")
            continue

        # Basic information section
        output.append(f"{Fore.CYAN}╔{'═' * 68}╗")
        output.append(f"║{' '*25}SCAN RESULTS{' '*32}║")
        output.append(f"╚{'═' * 68}╝{Style.RESET_ALL}")
        
        output.append(f"\n{Fore.YELLOW}Target Information:{Style.RESET_ALL}")
        output.append(f"• IP Address: {result.get('ip', 'N/A')}")
        output.append(f"• Domain: {result.get('domain', 'N/A')}")
        output.append(f"• Scan Time: {result.get('timestamp', 'N/A')}")

        # Port Scan Results
        if result.get('open_ports'):
            output.append(f"\n{Fore.YELLOW}[*] PORT SCAN RESULTS:{Style.RESET_ALL}")
            
            # TCP Ports
            tcp_ports = result['open_ports'].get('tcp', [])
            if tcp_ports:
                output.append(f"\n{Fore.BLUE}┌{'─' * 68}┐")
                output.append(f"│ {'TCP PORTS':^66} │")
                output.append(f"└{'─' * 68}┘{Style.RESET_ALL}")
                for port, banner in tcp_ports:
                    risk_level = _get_port_risk_level(port)
                    color = {
                        'HIGH': Fore.RED,
                        'MEDIUM': Fore.YELLOW,
                        'LOW': Fore.GREEN
                    }.get(risk_level, Fore.WHITE)
                    icon = {'HIGH': '⚠', 'MEDIUM': '•', 'LOW': '✓'}.get(risk_level, '•')
                    banner_text = banner[:50] + '...' if banner and len(banner) > 50 else (banner or 'No banner')
                    output.append(f"{color}{icon} Port {port:<6} │ Risk: {risk_level:<8} │ {banner_text}{Style.RESET_ALL}")

            # UDP Ports
            udp_ports = result['open_ports'].get('udp', [])
            if udp_ports:
                output.append(f"\n{Fore.BLUE}┌{'─' * 68}┐")
                output.append(f"│ {'UDP PORTS':^66} │")
                output.append(f"└{'─' * 68}┘{Style.RESET_ALL}")
                for port, banner in udp_ports:
                    output.append(f"{Fore.GREEN}• Port {port:<6} │ {banner or 'No banner'}{Style.RESET_ALL}")

        # DNS Information
        if result.get('domain_info', {}).get('dns_records'):
            output.append(f"\n{Fore.BLUE}┌{'─' * 68}┐")
            output.append(f"│ {'DNS INFORMATION':^66} │")
            output.append(f"└{'─' * 68}┘{Style.RESET_ALL}")
            for record in result['domain_info']['dns_records']:
                output.append(f"  ▶ {record}")

        # Vulnerability Information
        if result.get('vulnerabilities'):
            output.append(f"\n{Fore.BLUE}┌{'─' * 68}┐")
            output.append(f"│ {'VULNERABILITY SCAN RESULTS':^66} │")
            output.append(f"└{'─' * 68}┘{Style.RESET_ALL}")
            
            output.append(f"\n{Fore.YELLOW}Status: {result['vulnerabilities'].get('status', 'N/A')}{Style.RESET_ALL}")
            
            for source in ['vulners', 'nvd']:
                vulns = result['vulnerabilities'].get(source, [])
                if vulns:
                    output.append(f"\n{Fore.YELLOW}[*] {source.upper()} Results:{Style.RESET_ALL}")
                    for vuln in vulns:
                        try:
                            cvss = float(vuln.get('cvss', 0)) if vuln.get('cvss') is not None else 0
                        except (ValueError, TypeError):
                            cvss = 0
                            
                        color = (Fore.RED if cvss >= 7.0 else 
                                Fore.YELLOW if cvss >= 4.0 else 
                                Fore.GREEN)
                        
                        output.append(f"\n{color}⚠ {vuln.get('cve_id', 'N/A')} (CVSS: {cvss:.1f}){Style.RESET_ALL}")
                        output.append(f"  Service: {vuln.get('service_name', 'N/A')} {vuln.get('version', '')}")
                        output.append(f"  Port: {vuln.get('port', 'N/A')}")
                        desc = vuln.get('description', 'No description available')
                        if desc:
                            output.append(f"  Description: {desc[:200]}...")
                        else:
                            output.append(f"  Description: No description available")

        output.append(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
    
    return '\n'.join(output)

def main():
    try:
        # Check for required dependencies before starting
        missing_deps = []
        if not VULNERS_AVAILABLE:
            missing_deps.append("vulners")
        if not SHODAN_AVAILABLE:
            missing_deps.append("shodan")
            
        if missing_deps:
            print(f"{Fore.YELLOW}[!] Optional dependencies not found: {', '.join(missing_deps)}")
            print(f"[*] Install them using: pip install {' '.join(missing_deps)}{Style.RESET_ALL}")
            
        args = parse_arguments()
        
        # Print header first
        scanner = NetworkScanner(verbose=False)  # Initialize with minimal settings first
        scanner.print_header()
        
        # Validate APIs before showing scan information
        print("")  # Add a blank line for spacing
        if args.api_vulners or args.api_nvd:
            scanner = NetworkScanner(verbose=args.verbose, random_ua=args.random_user_agent, 
                                  vulners_api=args.api_vulners, nvd_api=args.api_nvd,
                                  rate_limit_global=args.rate_limit_global, 
                                  rate_limit_host=args.rate_limit_host)
        
        # Now show scan information
        print(f"\n{Fore.CYAN}[*] Target: {args.target}{Style.RESET_ALL}")
        if args.tcp:
            print(f"{Fore.BLUE}[*] TCP scan mode{Style.RESET_ALL}")
        elif args.udp:
            print(f"{Fore.BLUE}[*] UDP scan mode{Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}[*] Full scan mode (TCP + UDP){Style.RESET_ALL}")
            
        if args.verbose:
            print(f"{Fore.BLUE}[*] Verbose mode enabled{Style.RESET_ALL}")
            
        if args.random_user_agent:
            print(f"{Fore.BLUE}[*] Using random User-Agent{Style.RESET_ALL}")
        if args.output:
            print(f"{Fore.BLUE}[*] Output will be saved to: {args.output}{Style.RESET_ALL}")

        if args.limit:
            print(f"{Fore.BLUE}[*] Limit is set to {args.limit}{Style.RESET_ALL}")

        if not args.target:
            raise ValueError("No target specified")

        print(f"\n{Fore.YELLOW}[+] Starting scan...{Style.RESET_ALL}")
        
        results = scanner.scan_network(args.target, tcp_only=args.tcp, udp_only=args.udp, limit=args.limit)
        
        if not results:
            print(f"\n{Fore.RED}[!] No results found{Style.RESET_ALL}")
            sys.exit(1)
        
        formatted_results = format_results_for_display(results)
        print(formatted_results)
        
        if args.output:
            scanner.save_results(results, args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        print(f"\n{Fore.RED}[!] Scan failed: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
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

class NetworkScanner:
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.session = requests.Session()
        self.session.timeout = 10
        
        # Create subdirectories for different types of results
        self.scans_dir = RESULTS_DIR / "scans"
        self.logs_dir = RESULTS_DIR / "logs"
        self.reports_dir = RESULTS_DIR / "reports"
        
        # Create all subdirectories
        self.scans_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)

        self.DEFAULT_TIMEOUT = 10
        self.MAX_WORKERS = 50
        self.DEFAULT_PORT_RANGE = "1-1000"
        self.COMMON_PORTS = {80, 443, 21, 22, 23, 25, 53, 110, 135, 139, 445, 3306, 3389}

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
        print(Fore.CYAN + "="*69)
        print(Fore.CYAN + "███▄▄▄▄      ▄████████    ▄████████  ▄████████    ▄████████ ███▄▄▄▄   ")
        print(Fore.CYAN + "███▀▀▀██▄   ███    ███   ███    ███ ███    ███   ███    ███ ███▀▀▀██▄ ")
        print(Fore.CYAN + "███   ███   ███    █▀    ███    █▀  ███    █▀    ███    ███ ███   ███ ")
        print(Fore.CYAN + "███   ███  ▄███▄▄▄       ███        ███          ███    ███ ███   ███ ")
        print(Fore.CYAN + "███   ███ ▀▀███▀▀▀     ▀███████████ ███        ▀███████████ ███   ███ ")
        print(Fore.CYAN + "███   ███   ███    █▄           ███ ███    █▄    ███    ███ ███   ███ ")
        print(Fore.CYAN + "███   ███   ███    ███    ▄█    ███ ███    ███   ███    ███ ███   ███ ")
        print(Fore.CYAN + " ▀█   █▀    ██████████  ▄████████▀  ████████▀    ███    █▀   ▀█   █▀  ")
        print(Fore.CYAN + "="*69 + Style.RESET_ALL)
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

    def scan_single_port(self, ip: str, port: int) -> Tuple[int, str, Optional[str]]:
        """Scan a single port with service detection and banner grabbing"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.DEFAULT_TIMEOUT)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = self.get_service_banner(sock, port)
                    return port, "open", service
        except Exception as e:
            logging.debug(f"Error scanning port {port}: {e}")
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

    def scan_ports(self, ip: str, port_range: str = None) -> List[Tuple[int, str]]:
        """Scan ports using concurrent execution"""
        if port_range is None:
            port_range = self.DEFAULT_PORT_RANGE
        
        try:
            start_port, end_port = map(int, port_range.split('-'))
            ports = list(self.COMMON_PORTS) + list(range(start_port, end_port + 1))
            ports = sorted(set(ports))  # Remove duplicates
        except ValueError:
            logging.error(f"Invalid port range: {port_range}")
            return []

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            future_to_port = {
                executor.submit(self.scan_single_port, ip, port): port 
                for port in ports
            }
            
            with tqdm(total=len(ports), desc="Scanning ports", unit="port") as pbar:
                for future in concurrent.futures.as_completed(future_to_port):
                    port, status, banner = future.result()
                    if status == "open":
                        open_ports.append((port, banner if banner else "unknown"))
                    pbar.update(1)

        return sorted(open_ports)

    def fetch_domain_info(self, domain: str) -> Dict:
        """Fetch domain information with progress indication"""
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
        """Create a formatted section header"""
        return f"\n{Fore.CYAN}{'═'*50}\n╔{'═'*48}╗\n║ {title:<46} ║\n╚{'═'*48}╝{Style.RESET_ALL}\n"

    def _format_subsection(self, title: str) -> str:
        """Create a formatted subsection header"""
        return f"\n{Fore.BLUE}▶ {title}{Style.RESET_ALL}\n{'─'*50}\n"

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
            return f"{Fore.GREEN}No open ports found{Style.RESET_ALL}"
        
        result = []
        for port, service in sorted(ports):
            risk_level = self._get_port_risk_level(port)
            color = {
                'HIGH': Fore.RED,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.GREEN
            }.get(risk_level, Fore.WHITE)
            
            result.append(f"{color}[{risk_level}] Port {port:<6} {service}{Style.RESET_ALL}")
        
        return '\n'.join(result)

    def _get_port_risk_level(self, port: int) -> str:
        high_risk = {21, 23, 3389, 445, 135, 139}
        medium_risk = {80, 443, 8080, 8443, 3306, 5432}
        return 'HIGH' if port in high_risk else 'MEDIUM' if port in medium_risk else 'LOW'

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
        return f"{color}{score:.1f}/100{Style.RESET_ALL}"

    def _generate_recommendations(self, security_analysis: Dict, stats: Dict) -> str:
        recommendations = []
        
        if security_analysis['critical'] or security_analysis['high']:
            recommendations.append(f"{Fore.RED}URGENT ACTIONS REQUIRED:{Style.RESET_ALL}")
            for issue in security_analysis['critical'] + security_analysis['high']:
                recommendations.append(f"• {issue}")
        
        if stats['High-Risk Ports'] > 0:
            recommendations.append(f"\n{Fore.YELLOW}PORT SECURITY:{Style.RESET_ALL}")
            recommendations.append("• Consider closing or restricting access to high-risk ports")
            recommendations.append("• Implement firewall rules to limit access to necessary IPs only")
        
        if stats['Security Headers'] < 4:
            recommendations.append(f"\n{Fore.YELLOW}WEB SECURITY:{Style.RESET_ALL}")
            recommendations.append("• Implement missing security headers")
            recommendations.append("• Enable HSTS for HTTPS enforcement")
        
        return '\n'.join(recommendations) if recommendations else "No immediate actions required."

    def _format_dns_info(self, records: List[str]) -> str:
        if not records:
            return "No DNS records found"
        
        formatted = []
        record_types = Counter(r.split()[3] for r in records)
        
        formatted.append(f"{Fore.YELLOW}Record Distribution:{Style.RESET_ALL}")
        for rtype, count in record_types.items():
            formatted.append(f"• {rtype}: {count} records")
        
        formatted.append(f"\n{Fore.YELLOW}Detailed Records:{Style.RESET_ALL}")
        for record in records:
            formatted.append(f"• {record}")
        
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
        """Save all scan results to appropriate directories"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = self.create_scan_directory(domain)

        # Save the main report
        report_file = self.reports_dir / f"scan_report_{domain}_{timestamp}.txt"
        report_file.write_text(report)

        # Save raw scan data as JSON for potential future use
        import json
        # Convert datetime objects to strings for JSON serialization
        scan_results_copy = scan_results.copy()
        scan_results_copy['timestamp'] = scan_results_copy['timestamp'].isoformat()
        raw_data_file = scan_dir / "raw_scan_data.json"
        with raw_data_file.open('w') as f:
            json.dump(scan_results_copy, f, indent=4, default=str)

        # Save individual component results
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

        print(Fore.GREEN + f"\nResults saved in:")
        print(Fore.GREEN + f"- Report: {report_file}")
        print(Fore.GREEN + f"- Detailed results: {scan_dir}")
        
        # Create a README in the scan directory
        readme_content = f"""Scan Results for {domain}
Timestamp: {timestamp}

Directory Contents:
- raw_scan_data.json: Complete scan results in JSON format
- ports_data.txt: Details of open ports and services
- dns_data.txt: DNS records and information
- headers_data.txt: HTTP headers from the target
- whois_data.txt: WHOIS lookup results

The complete scan report can be found in:
{report_file}
"""
        (scan_dir / "README.txt").write_text(readme_content)

    def main(self):
        while True:
            self.print_header()
            domain = input(Fore.CYAN + "Enter the domain to scan (e.g., example.com): " + Style.RESET_ALL).strip()
            
            if not domain:
                print(Fore.RED + "Please enter a valid domain." + Style.RESET_ALL)
                continue

            if not self.validate_domain(domain):
                print(Fore.RED + "Invalid domain format." + Style.RESET_ALL)
                continue

            try:
                ip = self.get_ip_from_website(domain)
                if not ip:
                    continue

                scan_results = {
                    'ip': ip,
                    'domain': domain,
                    'timestamp': datetime.now(),
                    'open_ports': self.scan_ports(ip),
                    'domain_info': self.fetch_domain_info(domain)
                }

                report = self.generate_report(domain, scan_results)
                print(report)
                
                self.save_scan_results(domain, scan_results, report)

            except KeyboardInterrupt:
                print(Fore.YELLOW + "\nScan interrupted by user." + Style.RESET_ALL)
                break
            except Exception as e:
                logging.error(f"Scan failed: {e}")
                print(Fore.RED + f"Scan failed: {e}" + Style.RESET_ALL)

            if input(Fore.CYAN + "\nScan another domain? (y/n): " + Style.RESET_ALL).lower() != 'y':
                break

if __name__ == "__main__":
    scanner = NetworkScanner()
    scanner.main()
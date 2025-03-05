import socket
import dns.resolver
import requests
import logging
from typing import Optional, List
from colorama import Fore, Style

class BypassScanner:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def find_origin_ip(self, domain: str) -> Optional[str]:
        """Try multiple methods to find origin IP behind CDN/WAF"""
        methods = [
            self._try_zone_transfer,
            self._try_subdomain_enumeration,
            self._try_historical_dns,
            self._try_ssl_fingerprint,
            self._try_email_records
        ]

        print(f"{Fore.YELLOW}[*] Attempting to bypass CDN/WAF for {domain}...{Style.RESET_ALL}")
        
        for method in methods:
            try:
                result = method(domain)
                if result:
                    if self._verify_origin_ip(result, domain):
                        print(f"{Fore.GREEN}[+] Found potential origin IP: {result}{Style.RESET_ALL}")
                        return result
            except Exception as e:
                logging.debug(f"Bypass method failed: {e}")
                continue

        return None

    def _try_zone_transfer(self, domain: str) -> Optional[str]:
        """Attempt DNS zone transfer"""
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    axfr = dns.query.xfr(str(ns), domain)
                    for transfer in axfr:
                        for record in transfer:
                            if record.rdtype == dns.rdatatype.A:
                                return str(record[0])
                except:
                    continue
        except:
            pass
        return None

    def _try_subdomain_enumeration(self, domain: str) -> Optional[str]:
        """Try common subdomains to find origin IP"""
        common_subdomains = [
            'direct', 'direct-connect', 'origin', 'origin-www',
            'cpanel', 'webmail', 'email', 'mail', 'remote',
            'ftp', 'sftp', 'admin', 'administration'
        ]

        for sub in common_subdomains:
            try:
                hostname = f"{sub}.{domain}"
                answers = self.resolver.resolve(hostname, 'A')
                return str(answers[0])
            except:
                continue
        return None

    def _try_historical_dns(self, domain: str) -> Optional[str]:
        """Check historical DNS records"""
        try:
            response = self.session.get(
                f'https://securitytrails.com/domain/{domain}/history/a',
                timeout=10
            )
            # Basic parsing, in real implementation would need more sophisticated parsing
            if response.status_code == 200:
                # Look for IP patterns in the response
                import re
                ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                ips = re.findall(ip_pattern, response.text)
                for ip in ips:
                    if self._verify_origin_ip(ip, domain):
                        return ip
        except:
            pass
        return None

    def _try_ssl_fingerprint(self, domain: str) -> Optional[str]:
        """Try to find origin IP through SSL certificate information"""
        try:
            import ssl
            import socket
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    # Extract IP from certificate if available
                    if cert:
                        return sock.getpeername()[0]
        except:
            pass
        return None

    def _try_email_records(self, domain: str) -> Optional[str]:
        """Try to find origin IP through email records"""
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                mx_hostname = str(mx.exchange).rstrip('.')
                try:
                    answers = self.resolver.resolve(mx_hostname, 'A')
                    return str(answers[0])
                except:
                    continue
        except:
            pass
        return None

    def _verify_origin_ip(self, ip: str, domain: str) -> bool:
        """Verify if the IP is likely the origin server"""
        try:
            # Try connecting to common ports
            ports = [80, 443, 8080, 8443]
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        # Found an open port, do additional verification
                        if port in [80, 8080]:
                            try:
                                response = requests.get(
                                    f"http://{ip}",
                                    headers={'Host': domain},
                                    timeout=5,
                                    allow_redirects=False
                                )
                                if response.status_code in [200, 301, 302, 403]:
                                    return True
                            except:
                                pass
                        elif port in [443, 8443]:
                            try:
                                response = requests.get(
                                    f"https://{ip}",
                                    headers={'Host': domain},
                                    timeout=5,
                                    verify=False,
                                    allow_redirects=False
                                )
                                if response.status_code in [200, 301, 302, 403]:
                                    return True
                            except:
                                pass
                except:
                    continue
                finally:
                    sock.close()
        except:
            pass
        return False

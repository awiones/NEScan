import socket
import dns.resolver
import dns.zone
import dns.query
import requests
import logging
import time
import re
import ssl
import OpenSSL
from typing import List, Dict, Optional, Set
import concurrent.futures
from functools import lru_cache
import ipaddress

class BypassScanner:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Enhanced CDN patterns
        self.cdn_patterns = {
            'cloudflare': [
                r'cloudflare',
                r'103\.',
                r'104\.',
                r'108\.',
                r'131\.',
                r'162\.',
                r'172\.'
            ],
            'akamai': [
                r'akamai',
                r'23\.',
                r'104\.',
                r'184\.',
                r'2\.16\.',
                r'23\.[\d]+\.[\d]+\.[\d]+'
            ],
            'cloudfront': [
                r'cloudfront',
                r'd\d+\.cloudfront\.net',
                r'54\.',
                r'52\.',
                r'13\.'
            ],
            'fastly': [
                r'fastly',
                r'151\.',
                r'199\.',
                r'fastly\.net'
            ],
            'sucuri': [
                r'sucuri',
                r'192\.124\.',
                r'66\.248\.'
            ]
        }
        
        # Common bypass techniques
        self.bypass_techniques = [
            self._bypass_via_headers,
            self._bypass_via_origin_dns,
            self._bypass_via_mail_server,
            self._bypass_via_ssl_info,
            self._bypass_via_historical_dns,
            self._bypass_via_subdomain_scan,
            self._bypass_via_txt_records,
            self._bypass_via_staging_servers,
            self._bypass_via_ftp_dns,
            self._bypass_via_dev_servers
        ]

    @lru_cache(maxsize=128)
    def find_origin_ip(self, domain: str) -> Optional[str]:
        """Enhanced CDN/WAF bypass with multiple techniques"""
        discovered_ips: Set[str] = set()
        origin_ip = None

        print(f"[*] Starting CDN/WAF bypass attempts for {domain}")
        
        # Run bypass techniques in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_technique = {
                executor.submit(technique, domain): technique.__name__
                for technique in self.bypass_techniques
            }

            for future in concurrent.futures.as_completed(future_to_technique):
                technique_name = future_to_technique[future]
                try:
                    result = future.result()
                    if result:
                        if isinstance(result, list):
                            discovered_ips.update(result)
                        else:
                            discovered_ips.add(result)
                        print(f"[+] Found potential IP(s) via {technique_name}")
                except Exception as e:
                    logging.debug(f"Bypass technique {technique_name} failed: {e}")

        # Verify discovered IPs
        if discovered_ips:
            print(f"[*] Verifying {len(discovered_ips)} potential origin IPs...")
            for ip in discovered_ips:
                if self._verify_origin_ip(domain, ip):
                    origin_ip = ip
                    print(f"[+] Verified origin IP: {ip}")
                    break

        return origin_ip

    def _verify_origin_ip(self, domain: str, ip: str) -> bool:
        """Verify if an IP is likely the origin server"""
        try:
            # Skip obvious CDN IPs
            if self._is_cdn_ip(ip):
                return False

            # Check if IP responds with expected website content
            response = requests.get(
                f"https://{ip}",
                headers={'Host': domain},
                verify=False,
                timeout=10
            )

            # Get baseline content from domain
            domain_response = requests.get(
                f"https://{domain}",
                timeout=10
            )

            # Compare response characteristics
            return self._compare_responses(domain_response, response)

        except Exception as e:
            logging.debug(f"IP verification failed for {ip}: {e}")
            return False

    def _compare_responses(self, domain_resp: requests.Response, ip_resp: requests.Response) -> bool:
        """Compare responses to verify if they're from the same origin"""
        # Compare status codes
        if domain_resp.status_code != ip_resp.status_code:
            return False

        # Compare content length (allow small differences)
        domain_len = len(domain_resp.content)
        ip_len = len(ip_resp.content)
        if not (0.8 <= ip_len/domain_len <= 1.2):
            return False

        # Compare specific headers
        headers_to_compare = ['server', 'x-powered-by']
        for header in headers_to_compare:
            if (header in domain_resp.headers) != (header in ip_resp.headers):
                return False

        return True

    def _bypass_via_headers(self, domain: str) -> Optional[str]:
        """Bypass using various HTTP headers"""
        headers_to_try = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'X-Forwarded-Host': domain},
            {'X-Host': domain},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-Server': domain}
        ]

        for custom_headers in headers_to_try:
            try:
                response = self.session.get(
                    f"https://{domain}",
                    headers=custom_headers,
                    allow_redirects=False,
                    timeout=10
                )
                if response.raw._connection:
                    ip = response.raw._connection.sock.getpeername()[0]
                    if not self._is_cdn_ip(ip):
                        return ip
            except:
                continue
        return None

    def _bypass_via_origin_dns(self, domain: str) -> List[str]:
        """Find origin IP through various DNS techniques"""
        results = []
        dns_prefixes = ['origin', 'origin-www', 'direct', 'direct-connect', 
                       'backend', 'api', 'staging', 'dev']
        
        for prefix in dns_prefixes:
            try:
                hostname = f"{prefix}.{domain}"
                answers = self.resolver.resolve(hostname, 'A')
                results.extend([str(rdata) for rdata in answers])
            except:
                continue
        return results

    def _bypass_via_mail_server(self, domain: str) -> List[str]:
        """Find origin IP through mail server records"""
        results = []
        try:
            # Check MX records
            mx_records = self.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                mail_server = str(mx.exchange).rstrip('.')
                try:
                    answers = self.resolver.resolve(mail_server, 'A')
                    results.extend([str(rdata) for rdata in answers])
                except:
                    continue

            # Check SPF records for IP addresses
            txt_records = self.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                txt = str(record)
                if 'v=spf1' in txt:
                    ip_matches = re.findall(r'ip[46]:([\d\./]+)', txt)
                    results.extend(ip_matches)
        except:
            pass
        return results

    def _bypass_via_ssl_info(self, domain: str) -> List[str]:
        """Extract IPs from SSL certificate information"""
        results = []
        try:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if ext.get_short_name() == b'subjectAltName':
                    alt_names = str(ext)
                    # Extract IPs and domains
                    ips = re.findall(r'IP:([\d\.]+)', alt_names)
                    domains = re.findall(r'DNS:([\w\.-]+)', alt_names)
                    results.extend(ips)
                    
                    # Resolve found domains
                    for d in domains:
                        try:
                            if d != domain:
                                answers = self.resolver.resolve(d, 'A')
                                results.extend([str(rdata) for rdata in answers])
                        except:
                            continue
        except:
            pass
        return results

    def _bypass_via_subdomain_scan(self, domain: str) -> List[str]:
        """Scan common subdomains for origin IPs"""
        results = []
        subdomains = [
            'admin', 'dev', 'development', 'stage', 'staging', 'app',
            'api', 'internal', 'test', 'remote', 'git', 'ssh', 'ftp',
            'direct', 'direct-connect', 'origin', 'real'
        ]
        
        for sub in subdomains:
            try:
                hostname = f"{sub}.{domain}"
                answers = self.resolver.resolve(hostname, 'A')
                ips = [str(rdata) for rdata in answers]
                results.extend([ip for ip in ips if not self._is_cdn_ip(ip)])
            except:
                continue
        return results

    def _bypass_via_txt_records(self, domain: str) -> List[str]:
        """Extract IPs from TXT records"""
        results = []
        try:
            txt_records = self.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                txt = str(record)
                # Look for IP addresses in TXT records
                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', txt)
                results.extend([ip for ip in ips if not self._is_cdn_ip(ip)])
        except:
            pass
        return results

    def _bypass_via_staging_servers(self, domain: str) -> List[str]:
        """Find origin through staging/testing servers"""
        results = []
        staging_patterns = [
            f"stage.{domain}", f"staging.{domain}",
            f"test.{domain}", f"testing.{domain}",
            f"dev.{domain}", f"development.{domain}",
            f"uat.{domain}", f"qa.{domain}"
        ]
        
        for pattern in staging_patterns:
            try:
                answers = self.resolver.resolve(pattern, 'A')
                results.extend([str(rdata) for rdata in answers])
            except:
                continue
        return results

    def _bypass_via_historical_dns(self, domain: str) -> List[str]:
        """Check historical DNS records"""
        results = []
        try:
            # Query SecurityTrails API (if you have API key)
            headers = {'apikey': 'your-api-key'}  # Optional
            response = requests.get(
                f'https://api.securitytrails.com/v1/history/{domain}/dns/a',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                for record in data.get('records', []):
                    ip = record.get('values', [{}])[0].get('ip')
                    if ip and not self._is_cdn_ip(ip):
                        results.append(ip)
        except:
            pass
        return results

    def _bypass_via_dev_servers(self, domain: str) -> List[str]:
        """Find origin through development servers"""
        results = []
        dev_patterns = [
            f"dev-{domain}", f"development-{domain}",
            f"dev.{domain}", f"development.{domain}",
            f"staging-{domain}", f"stage-{domain}",
            f"test-{domain}", f"testing-{domain}"
        ]
        
        for pattern in dev_patterns:
            try:
                answers = self.resolver.resolve(pattern, 'A')
                results.extend([str(rdata) for rdata in answers])
            except:
                continue
        return results

    def _bypass_via_ftp_dns(self, domain: str) -> List[str]:
        """Find origin IP through FTP server records"""
        results = []
        ftp_patterns = [
            f"ftp.{domain}",
            f"ftp-{domain}",
            f"sftp.{domain}",
            f"files.{domain}",
            f"upload.{domain}",
            f"download.{domain}"
        ]
        
        for pattern in ftp_patterns:
            try:
                # Try A record
                answers = self.resolver.resolve(pattern, 'A')
                results.extend([str(rdata) for rdata in answers])
                
                # Try CNAME and follow it
                try:
                    cname_answers = self.resolver.resolve(pattern, 'CNAME')
                    for rdata in cname_answers:
                        cname = str(rdata).rstrip('.')
                        try:
                            cname_ips = self.resolver.resolve(cname, 'A')
                            results.extend([str(ip) for ip in cname_ips])
                        except:
                            continue
                except:
                    pass
            except:
                continue

        # Filter out CDN IPs
        return [ip for ip in results if not self._is_cdn_ip(ip)]

    @lru_cache(maxsize=1024)
    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to a CDN"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check against CDN IP patterns
            for cdn, patterns in self.cdn_patterns.items():
                for pattern in patterns:
                    if re.match(pattern, ip):
                        return True
            
            # Additional checks for specific CDN ranges
            cdn_ranges = [
                '103.21.244.0/22',  # Cloudflare
                '103.22.200.0/22',  # Cloudflare
                '103.31.4.0/22',    # Cloudflare
                '104.16.0.0/12',    # Cloudflare
                '131.0.72.0/22',    # Cloudflare
                '141.101.64.0/18',  # Cloudflare
                '162.158.0.0/15',   # Cloudflare
                '172.64.0.0/13',    # Cloudflare
                '173.245.48.0/20',  # Cloudflare
                '188.114.96.0/20',  # Cloudflare
                '190.93.240.0/20',  # Cloudflare
                '197.234.240.0/22', # Cloudflare
                '198.41.128.0/17',  # Cloudflare
                '23.32.0.0/11',     # Akamai
                '23.192.0.0/11',    # Akamai
                '2.16.0.0/13',      # Akamai
                '204.246.128.0/17', # CloudFront
                '54.230.0.0/16',    # CloudFront
                '54.192.0.0/16',    # CloudFront
                '199.27.128.0/21',  # Fastly
                '151.101.0.0/16',   # Fastly
            ]
            
            for cdn_range in cdn_ranges:
                if ip_obj in ipaddress.ip_network(cdn_range):
                    return True
                    
            return False
            
        except ValueError:
            return False

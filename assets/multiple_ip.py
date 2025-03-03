import socket
import dns.resolver
import ipaddress
from typing import List, Dict, Set, Optional
import requests
from colorama import Fore, Style
import time
import whois
import concurrent.futures
from tqdm import tqdm

class MultipleIPScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; NEScanBot/1.0; +http://example.com/bot)'
        })

    def resolve_domain_ips(self, domain: str) -> Dict[str, Set[str]]:
        """
        Resolves all possible IPs related to a domain using multiple methods
        """
        ips = {
            'direct': set(),
            'dns_a': set(),
            'dns_aaaa': set(),
            'mx': set(),
            'subdomains': set(),
            'related': set()
        }

        try:
            # Direct resolution
            try:
                direct_ip = socket.gethostbyname(domain)
                ips['direct'].add(direct_ip)
            except socket.gaierror:
                pass

            # DNS A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ips['dns_a'].update(str(rdata) for rdata in answers)
            except Exception:
                pass

            # DNS AAAA records (IPv6)
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                ips['dns_aaaa'].update(str(rdata) for rdata in answers)
            except Exception:
                pass

            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    mx_domain = str(mx.exchange).rstrip('.')
                    try:
                        mx_ip = socket.gethostbyname(mx_domain)
                        ips['mx'].add(mx_ip)
                    except socket.gaierror:
                        continue
            except Exception:
                pass

            # Common subdomains
            common_subdomains = ['www', 'mail', 'smtp', 'pop', 'imap', 'blog', 
                               'api', 'dev', 'stage', 'test', 'admin']
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    ip = socket.gethostbyname(full_domain)
                    ips['subdomains'].add(ip)
                except socket.gaierror:
                    continue

            # Try to find related IPs through reverse DNS
            for ip_set in ips.values():
                for ip in ip_set.copy():
                    try:
                        hostnames = socket.gethostbyaddr(ip)
                        if hostnames and hostnames[0] != domain:
                            try:
                                related_ip = socket.gethostbyname(hostnames[0])
                                if related_ip != ip:
                                    ips['related'].add(related_ip)
                            except socket.gaierror:
                                continue
                    except socket.herror:
                        continue

        except Exception as e:
            print(f"{Fore.RED}[!] Error resolving IPs for {domain}: {str(e)}{Style.RESET_ALL}")

        return ips

    def display_resolved_ips(self, domain: str, ips: Dict[str, Set[str]]) -> List[str]:
        """
        Displays resolved IPs and returns a list of all unique IPs
        """
        all_ips = set()
        
        print(f"\n{Fore.CYAN}╔{'═' * 60}╗")
        print(f"║ {'Resolved IPs for ' + domain:<58} ║")
        print(f"╚{'═' * 60}╝{Style.RESET_ALL}")

        categories = {
            'direct': 'Direct Resolution',
            'dns_a': 'DNS A Records',
            'dns_aaaa': 'DNS AAAA Records',
            'mx': 'Mail Servers',
            'subdomains': 'Subdomains',
            'related': 'Related IPs'
        }

        for category, name in categories.items():
            if ips[category]:
                print(f"\n{Fore.YELLOW}{name}:{Style.RESET_ALL}")
                for ip in sorted(ips[category]):
                    print(f"  • {ip}")
                    all_ips.add(ip)

        total_ips = len(all_ips)
        print(f"\n{Fore.GREEN}Total unique IPs found: {total_ips}{Style.RESET_ALL}")

        return sorted(list(all_ips))

    def ask_for_scan(self, ips: List[str]) -> Optional[List[str]]:
        """
        Asks user if they want to scan the discovered IPs
        """
        if not ips:
            print(f"{Fore.RED}[!] No IPs found to scan{Style.RESET_ALL}")
            return None

        while True:
            choice = input(f"\n{Fore.YELLOW}[?] Do you want to scan all discovered IPs? (Y/N): {Style.RESET_ALL}").strip().upper()
            
            if choice == 'Y':
                return ips
            elif choice == 'N':
                # Let user select specific IPs
                print(f"\n{Fore.CYAN}Available IPs:{Style.RESET_ALL}")
                for i, ip in enumerate(ips, 1):
                    print(f"{i}. {ip}")
                
                while True:
                    selection = input(f"\n{Fore.YELLOW}Enter IP numbers to scan (comma-separated) or 'all' for all IPs: {Style.RESET_ALL}").strip()
                    
                    if selection.lower() == 'all':
                        return ips
                    
                    try:
                        indices = [int(x.strip()) - 1 for x in selection.split(',')]
                        selected_ips = [ips[i] for i in indices if 0 <= i < len(ips)]
                        if selected_ips:
                            return selected_ips
                        print(f"{Fore.RED}[!] No valid IPs selected{Style.RESET_ALL}")
                    except (ValueError, IndexError):
                        print(f"{Fore.RED}[!] Invalid selection. Please try again{Style.RESET_ALL}")
            
            print(f"{Fore.RED}[!] Please enter Y or N{Style.RESET_ALL}")

    def validate_domain(self, domain: str) -> bool:
        """
        Validates if the input is a valid domain name
        """
        try:
            # Check if it's an IP address
            try:
                ipaddress.ip_address(domain)
                return False
            except ValueError:
                pass

            # Basic domain validation
            if len(domain) > 255:
                return False
            if not all(part.isalnum() or part == '-' for part in domain.split('.')):
                return False
            if not all(len(part) <= 63 for part in domain.split('.')):
                return False

            # Try WHOIS lookup
            try:
                whois.whois(domain)
                return True
            except Exception:
                return False

        except Exception:
            return False

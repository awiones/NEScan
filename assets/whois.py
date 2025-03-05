import socket
import requests
import json
import dns.resolver
import re
import logging
from colorama import Fore, Style
from typing import Dict, List, Optional

class WhoisInfo:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NEScan/2.1',
            'Accept': 'application/json'
        })
        self.ip_cache = {}
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    def get_ip_details(self, ip: str) -> Dict:
        """Get comprehensive IP and geolocation information"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]

        ip_details = {
            'ip': ip,
            'hostname': None,
            'geo_location': {},
            'asn_info': {},
            'security_info': {},
            'cdn_info': {
                'detected': False,
                'provider': None
            },
            'reverse_dns': [],
            'organization': None
        }

        try:
            # Get reverse DNS
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                ip_details['hostname'] = hostname
            except socket.herror:
                pass

            # Get IP geolocation and ASN info using multiple providers
            try:
                # Try ipapi.co first
                geo_response = self.session.get(f'https://ipapi.co/{ip}/json/', timeout=5)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    ip_details['geo_location'] = {
                        'country': geo_data.get('country_name'),
                        'region': geo_data.get('region'),
                        'city': geo_data.get('city'),
                        'latitude': geo_data.get('latitude'),
                        'longitude': geo_data.get('longitude'),
                        'timezone': geo_data.get('timezone')
                    }
                    ip_details['asn_info'] = {
                        'asn': geo_data.get('asn'),
                        'org': geo_data.get('org'),
                        'isp': geo_data.get('isp')
                    }
                    ip_details['organization'] = geo_data.get('org')
                else:
                    # Fallback to ip-api.com
                    fallback_response = self.session.get(f'http://ip-api.com/json/{ip}', timeout=5)
                    if fallback_response.status_code == 200:
                        fb_data = fallback_response.json()
                        ip_details['geo_location'] = {
                            'country': fb_data.get('country'),
                            'region': fb_data.get('regionName'),
                            'city': fb_data.get('city'),
                            'latitude': fb_data.get('lat'),
                            'longitude': fb_data.get('lon'),
                            'timezone': fb_data.get('timezone')
                        }
                        ip_details['asn_info'] = {
                            'asn': fb_data.get('as'),
                            'org': fb_data.get('org'),
                            'isp': fb_data.get('isp')
                        }
                        ip_details['organization'] = fb_data.get('org')
            except Exception as e:
                logging.debug(f"Error getting geolocation: {e}")

            # Check for CDN
            cdn_patterns = {
                'Cloudflare': r'cloudflare',
                'Akamai': r'akamai',
                'Fastly': r'fastly',
                'CloudFront': r'cloudfront',
                'Imperva': r'imperva',
                'Sucuri': r'sucuri',
                'MaxCDN': r'maxcdn',
                'KeyCDN': r'keycdn'
            }

            if ip_details['organization']:
                for cdn, pattern in cdn_patterns.items():
                    if re.search(pattern, ip_details['organization'].lower()):
                        ip_details['cdn_info'] = {
                            'detected': True,
                            'provider': cdn
                        }
                        break

            # Get reverse DNS records
            try:
                ptr_records = self.resolver.resolve_address(ip)
                ip_details['reverse_dns'] = [str(r) for r in ptr_records]
            except Exception:
                pass

            # Cache the results
            self.ip_cache[ip] = ip_details
            return ip_details

        except Exception as e:
            logging.error(f"Error getting IP details: {e}")
            return {'ip': ip, 'error': str(e)}

    def print_ip_info(self, ip_info: Dict) -> None:
        """Print formatted IP information"""
        print("\nIP INFORMATION")
        print("=" * 70)

        # Basic IP info
        print("Basic Information:")
        print(f"IP Address: {ip_info['ip']}")
        if ip_info.get('hostname'):
            print(f"Hostname: {ip_info['hostname']}")
        print()

        # Geolocation info
        geo = ip_info.get('geo_location', {})
        if any(geo.values()):
            print("Location Information:")
            if geo.get('country'):
                print(f"Country: {geo['country']}")
            if geo.get('region'):
                print(f"Region: {geo['region']}")
            if geo.get('city'):
                print(f"City: {geo['city']}")
            if geo.get('latitude') and geo.get('longitude'):
                print(f"Coordinates: {geo['latitude']}, {geo['longitude']}")
            if geo.get('timezone'):
                print(f"Timezone: {geo['timezone']}")
            print()

        # Network info
        asn = ip_info.get('asn_info', {})
        if any(asn.values()):
            print("Network Information:")
            if asn.get('asn'):
                print(f"ASN: {asn['asn']}")
            if asn.get('org'):
                print(f"Organization: {asn['org']}")
            if asn.get('isp'):
                print(f"ISP: {asn['isp']}")
            print()

        # CDN info if detected
        cdn = ip_info.get('cdn_info', {})
        if cdn.get('detected'):
            print("CDN Information:")
            print(f"Provider: {cdn['provider']}")
            print(f"Warning: Target is behind a CDN/WAF")
            print()

        print("=" * 70 + "\n")

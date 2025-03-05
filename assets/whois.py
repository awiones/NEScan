import socket
import struct
import ipaddress
import re
import logging
import subprocess
import platform
import json
import requests
from typing import Dict, List, Optional, Any

class WhoisInfo:
    def __init__(self):
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.ip_cache = {}
        self.asn_cache = {}
        self.geo_cache = {}

    def get_ip_details(self, ip: str) -> Dict[str, Any]:
        """Comprehensive IP information gathering without external APIs"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]

        ip_details = {
            'basic_info': self._get_basic_info(ip),
            'network_info': self._get_network_info(ip),
            'routing_info': self._get_routing_info(ip),
            'reverse_dns': self._get_reverse_dns(ip),
            'network_range': self._get_network_range(ip),
            'technical_details': self._get_technical_details(ip),
            'geo_location': self._get_geo_location(ip),  # New
            'asn_info': self._get_asn_info(ip),         # New
            'security_info': self._get_security_info(ip) # New
        }

        self.ip_cache[ip] = ip_details
        return ip_details

    def _get_basic_info(self, ip: str) -> Dict[str, Any]:
        """Get basic IP information"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network_class = self._get_network_class(ip)
            
            return {
                'ip_address': ip,
                'ip_version': ip_obj.version,
                'network_class': network_class,
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_loopback': ip_obj.is_loopback,
                'is_link_local': ip_obj.is_link_local,
                'binary': self._ip_to_binary(ip),
                'hexadecimal': self._ip_to_hex(ip),
                'integer': int(ip_obj),
                'hostname': self._get_hostname(ip)
            }
        except Exception as e:
            logging.error(f"Error in basic info: {e}")
            return {'error': str(e)}

    def _get_network_info(self, ip: str) -> Dict[str, Any]:
        """Get detailed network information"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            
            return {
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'netmask': str(network.netmask),
                'prefix_length': network.prefixlen,
                'num_addresses': network.num_addresses,
                'subnet_bits': self._get_subnet_bits(network.prefixlen),
                'subnet_type': self._get_subnet_type(network.prefixlen),
                'address_range': {
                    'first': str(network.network_address + 1),
                    'last': str(network.broadcast_address - 1)
                }
            }
        except Exception as e:
            logging.error(f"Error in network info: {e}")
            return {'error': str(e)}

    def _get_routing_info(self, ip: str) -> Dict[str, Any]:
        """Get routing information"""
        try:
            route_info = {
                'hops': self._trace_route(ip),
                'rtt': self._get_rtt(ip),
                'path_mtu': self._get_path_mtu(ip)
            }
            return route_info
        except Exception as e:
            logging.error(f"Error in routing info: {e}")
            return {'error': str(e)}

    def _get_technical_details(self, ip: str) -> Dict[str, Any]:
        """Get technical details about the IP"""
        try:
            return {
                'decimal_format': self._ip_to_decimal(ip),
                'hex_format': self._ip_to_hex(ip),
                'binary_format': self._ip_to_binary(ip),
                'octal_format': self._ip_to_octal(ip),
                'reversed_ip': self._reverse_ip(ip),
                'ip_segments': self._get_ip_segments(ip),
                'special_ranges': self._check_special_ranges(ip)
            }
        except Exception as e:
            logging.error(f"Error in technical details: {e}")
            return {'error': str(e)}

    def _get_network_class(self, ip: str) -> str:
        """Determine network class with detailed information"""
        try:
            first_octet = int(ip.split('.')[0])
            if 1 <= first_octet <= 126:
                return {
                    'class': 'A',
                    'range': '1.0.0.0 to 126.255.255.255',
                    'default_subnet': '255.0.0.0',
                    'purpose': 'Large networks and organizations'
                }
            elif 128 <= first_octet <= 191:
                return {
                    'class': 'B',
                    'range': '128.0.0.0 to 191.255.255.255',
                    'default_subnet': '255.255.0.0',
                    'purpose': 'Medium-sized networks'
                }
            elif 192 <= first_octet <= 223:
                return {
                    'class': 'C',
                    'range': '192.0.0.0 to 223.255.255.255',
                    'default_subnet': '255.255.255.0',
                    'purpose': 'Small networks and LANs'
                }
            elif 224 <= first_octet <= 239:
                return {
                    'class': 'D',
                    'range': '224.0.0.0 to 239.255.255.255',
                    'purpose': 'Multicast addresses'
                }
            elif 240 <= first_octet <= 255:
                return {
                    'class': 'E',
                    'range': '240.0.0.0 to 255.255.255.255',
                    'purpose': 'Reserved for experimental use'
                }
            return {'class': 'Unknown', 'purpose': 'Invalid or special address'}
        except:
            return {'class': 'Error', 'purpose': 'Could not determine network class'}

    def _get_hostname(self, ip: str) -> Dict[str, Any]:
        """Get detailed hostname information"""
        try:
            hostname_info = {
                'primary_hostname': None,
                'all_hostnames': [],
                'reverse_dns': [],
                'method': None
            }

            # Try socket first
            try:
                hostname, aliases, _ = socket.gethostbyaddr(ip)
                hostname_info['primary_hostname'] = hostname
                hostname_info['all_hostnames'].extend(aliases)
                hostname_info['method'] = 'socket'
            except socket.herror:
                pass

            # Try reverse DNS lookup
            try:
                if platform.system() != 'Windows':
                    output = subprocess.check_output(['host', ip], universal_newlines=True)
                    matches = re.findall(r'domain name pointer (.*?)\.', output)
                    if matches:
                        hostname_info['reverse_dns'].extend(matches)
                        if not hostname_info['primary_hostname']:
                            hostname_info['primary_hostname'] = matches[0]
                            hostname_info['method'] = 'reverse_dns'
            except:
                pass

            return hostname_info
        except Exception as e:
            logging.error(f"Error in hostname lookup: {e}")
            return {'error': str(e)}

    def _get_subnet_bits(self, prefix_length: int) -> Dict[str, Any]:
        """Calculate subnet bit information"""
        return {
            'network_bits': prefix_length,
            'host_bits': 32 - prefix_length,
            'max_hosts': 2 ** (32 - prefix_length) - 2,
            'subnet_mask_binary': '1' * prefix_length + '0' * (32 - prefix_length)
        }

    def _get_subnet_type(self, prefix_length: int) -> str:
        """Determine subnet type based on prefix length"""
        if (prefix_length == 8):
            return "Class A default"
        elif (prefix_length == 16):
            return "Class B default"
        elif (prefix_length == 24):
            return "Class C default"
        elif (prefix_length < 8):
            return "Supernet (Class A)"
        elif (prefix_length < 16):
            return "Supernet (Class B)"
        elif (prefix_length < 24):
            return "Supernet (Class C)"
        else:
            return "Subnet"

    def _trace_route(self, ip: str, max_hops: int = 30) -> List[Dict[str, Any]]:
        """Perform traceroute and get path information"""
        hops = []
        try:
            if platform.system() == "Windows":
                cmd = ['tracert', '-h', str(max_hops), '-w', '500', ip]
            else:
                cmd = ['traceroute', '-m', str(max_hops), '-w', '1', ip]
            
            output = subprocess.check_output(cmd, universal_newlines=True)
            hop_lines = output.split('\n')
            
            for line in hop_lines:
                if '*' not in line and line.strip():
                    try:
                        hop_ip = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                        if hop_ip:
                            hops.append({
                                'ip': hop_ip[0],
                                'hostname': self._get_hostname(hop_ip[0])['primary_hostname'],
                                'response_time': self._extract_response_time(line)
                            })
                    except:
                        continue
            
            return hops
        except:
            return []

    def _get_network_range(self, ip: str) -> Dict[str, Any]:
        """Get detailed network range information"""
        try:
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return {
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'first_host': str(network.network_address + 1),
                'last_host': str(network.broadcast_address - 1),
                'total_hosts': network.num_addresses - 2,
                'netmask': str(network.netmask),
                'wildcard_mask': str(network.hostmask)
            }
        except Exception as e:
            return {'error': str(e)}

    def _check_special_ranges(self, ip: str) -> Dict[str, bool]:
        """Check if IP belongs to special ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                'private_range': ip_obj.is_private,
                'reserved_range': ip_obj.is_reserved,
                'multicast_range': ip_obj.is_multicast,
                'loopback_range': ip_obj.is_loopback,
                'link_local': ip_obj.is_link_local,
                'documentation_range': self._is_documentation_range(ip),
                'carrier_grade_nat': self._is_cgnat_range(ip),
                'unique_local': self._is_unique_local(ip),
                'special_purpose': self._is_special_purpose(ip)
            }
        except Exception as e:
            return {'error': str(e)}

    def print_ip_info(self, ip_info: Dict[str, Any]) -> None:
        """Print detailed IP information"""
        print("\nIP INFORMATION")
        print("=" * 70)

        # Basic Information
        basic = ip_info['basic_info']
        print("\nBasic Information:")
        print(f"IP Address: {basic['ip_address']}")
        print(f"Version: IPv{basic['ip_version']}")
        print(f"Network Class: {basic['network_class']['class']}")
        print(f"Class Range: {basic['network_class']['range']}")
        print(f"Purpose: {basic['network_class']['purpose']}")
        if basic.get('hostname', {}).get('primary_hostname'):
            print(f"Hostname: {basic['hostname']['primary_hostname']}")

        # Network Information
        net = ip_info['network_info']
        print("\nNetwork Information:")
        print(f"Network Address: {net['network_address']}")
        print(f"Broadcast Address: {net['broadcast_address']}")
        print(f"Netmask: {net['netmask']}")
        print(f"Prefix Length: /{net['prefix_length']}")
        print(f"Subnet Type: {net['subnet_type']}")
        print(f"Address Range: {net['address_range']['first']} - {net['address_range']['last']}")

        # Technical Details
        tech = ip_info['technical_details']
        print("\nTechnical Details:")
        print(f"Binary: {tech['binary_format']}")
        print(f"Hexadecimal: {tech['hex_format']}")
        print(f"Decimal: {tech['decimal_format']}")
        print(f"Octal: {tech['octal_format']}")

        # Special Ranges
        ranges = tech['special_ranges']
        print("\nSpecial Range Information:")
        for range_type, is_in_range in ranges.items():
            if is_in_range:
                print(f"• {range_type.replace('_', ' ').title()}: Yes")

        # Routing Information
        if ip_info['routing_info'].get('hops'):
            print("\nRouting Information:")
            for i, hop in enumerate(ip_info['routing_info']['hops'], 1):
                print(f"Hop {i}: {hop['ip']} ({hop['hostname'] or 'Unknown'})")

        # Add geolocation information with error handling
        geo = ip_info.get('geo_location', {})
        if geo:
            print("\nGeolocation Information:")
            if geo.get('country'):
                print(f"Country: {geo['country']} ({geo['country_code']})")
                print(f"Region: {geo['region']}")
                print(f"City: {geo['city']}")
                print(f"Coordinates: {geo['latitude']}, {geo['longitude']}")
                print(f"Timezone: {geo['timezone']}")
                print(f"ISP: {geo['isp']}")
                print(f"Organization: {geo['org']}")
                print(f"AS: {geo['as']}")

        # Add ASN and network information
        asn = ip_info.get('asn_info', {})
        if asn:
            print("\nNetwork Organization Information:")
            print(f"ASN: {asn.get('asn', 'N/A')}")
            print(f"Organization: {asn.get('org', 'N/A')}")
            print(f"ISP: {asn.get('isp', 'N/A')}")
            if asn.get('route'):
                print(f"Route: {asn['route']}")

        # Add security information
        security = ip_info.get('security_info', {})
        if security:
            print("\nSecurity Information:")
            if security.get('blacklists'):
                print("Blacklist Status:")
                for bl, status in security['blacklists'].items():
                    print(f"• {bl}: {status}")
            if security.get('threats'):
                print("\nThreat Indicators:")
                for threat in security['threats']:
                    print(f"• {threat}")

        print("\n" + "=" * 70)

    # Helper methods
    def _ip_to_binary(self, ip: str) -> str:
        return ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])

    def _ip_to_hex(self, ip: str) -> str:
        return '0x' + ''.join([hex(int(x)+256)[3:] for x in ip.split('.')])

    def _ip_to_decimal(self, ip: str) -> int:
        return struct.unpack('!L', socket.inet_aton(ip))[0]

    def _ip_to_octal(self, ip: str) -> str:
        return '.'.join([oct(int(x))[2:] for x in ip.split('.')])

    def _reverse_ip(self, ip: str) -> str:
        return '.'.join(reversed(ip.split('.')))

    def _get_ip_segments(self, ip: str) -> Dict[str, Any]:
        octets = ip.split('.')
        return {
            'first_octet': {'decimal': int(octets[0]), 'binary': bin(int(octets[0]))[2:].zfill(8)},
            'second_octet': {'decimal': int(octets[1]), 'binary': bin(int(octets[1]))[2:].zfill(8)},
            'third_octet': {'decimal': int(octets[2]), 'binary': bin(int(octets[2]))[2:].zfill(8)},
            'fourth_octet': {'decimal': int(octets[3]), 'binary': bin(int(octets[3]))[2:].zfill(8)}
        }

    def _is_documentation_range(self, ip: str) -> bool:
        doc_ranges = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(r) for r in doc_ranges)

    def _is_cgnat_range(self, ip: str) -> bool:
        return ipaddress.ip_address(ip) in ipaddress.ip_network('100.64.0.0/10')

    def _is_unique_local(self, ip: str) -> bool:
        return ipaddress.ip_address(ip) in ipaddress.ip_network('fc00::/7')

    def _is_special_purpose(self, ip: str) -> bool:
        special_ranges = [
            '192.88.99.0/24',  # 6to4 relay
            '192.0.0.0/24',    # IETF Protocol Assignments
            '255.255.255.255/32'  # Limited broadcast
        ]
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(r) for r in special_ranges)

    def _get_rtt(self, ip: str) -> Optional[float]:
        """Get round-trip time to IP"""
        try:
            if platform.system() == "Windows":
                cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            output = subprocess.check_output(cmd, universal_newlines=True)
            match = re.search(r'time[=<](\d+\.?\d*)', output)
            return float(match.group(1)) if match else None
        except:
            return None

    def _get_path_mtu(self, ip: str) -> Optional[int]:
        """Get path MTU"""
        try:
            if platform.system() != "Windows":
                cmd = ['ping', '-c', '1', '-M', 'do', '-s', '1472', ip]
                try:
                    subprocess.check_output(cmd, stderr=subprocess.STDOUT)
                    return 1500
                except subprocess.CalledProcessError as e:
                    match = re.search(r'mtu=(\d+)', e.output.decode())
                    return int(match.group(1)) if match else None
        except:
            return None
        return None

    def _extract_response_time(self, line: str) -> Optional[float]:
        """Extract response time from traceroute line"""
        try:
            match = re.search(r'(\d+\.?\d*)\s*ms', line)
            return float(match.group(1)) if match else None
        except:
            return None

    def _get_reverse_dns(self, ip: str) -> List[str]:
        """Get reverse DNS records for an IP address"""
        records = []
        try:
            # Try socket gethostbyaddr
            try:
                hostname, aliases, _ = socket.gethostbyaddr(ip)
                if hostname:
                    records.append(hostname)
                records.extend(aliases)
            except socket.herror:
                pass

            # Try using 'host' command on Unix-like systems
            if platform.system() != "Windows":
                try:
                    output = subprocess.check_output(['host', ip], universal_newlines=True)
                    matches = re.findall(r'domain name pointer (.*?)\.', output)
                    records.extend(matches)
                except (subprocess.SubprocessError, FileNotFoundError):
                    pass

            return list(set(records))  # Remove duplicates
        except Exception as e:
            logging.error(f"Error in reverse DNS lookup: {e}")
            return []

    def _get_geo_location(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information using ip-api.com"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'N/A'),
                        'country_code': data.get('countryCode', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'latitude': data.get('lat', 'N/A'),
                        'longitude': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'as': data.get('as', 'N/A')
                    }
            return {}
        except Exception as e:
            logging.debug(f"Geo lookup failed: {e}")
            return {}

    def _get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN and network organization information"""
        try:
            # Using GeoLite2 ASN database
            import geoip2.database
            reader = geoip2.database.Reader('assets/GeoLite2-ASN.mmdb')
            response = reader.asn(ip)
            
            return {
                'asn': f"AS{response.autonomous_system_number}",
                'org': response.autonomous_system_organization,
                'network': self._get_network_org(ip),
                'isp': self._get_isp_info(ip),
                'route': self._get_route_info(ip)
            }
        except Exception as e:
            logging.debug(f"ASN lookup failed: {e}")
            return {}

    def _get_security_info(self, ip: str) -> Dict[str, Any]:
        """Get security-related information"""
        try:
            return {
                'blacklists': self._check_blacklists(ip),
                'abuse_reports': self._check_abuse_reports(ip),
                'threats': self._check_threats(ip)
            }
        except Exception as e:
            logging.debug(f"Security info lookup failed: {e}")
            return {}

    def _get_network_org(self, ip: str) -> str:
        """Get network organization information using whois"""
        try:
            # Try RIPE first
            whois_cmd = ['whois', ip]
            output = subprocess.check_output(whois_cmd, universal_newlines=True)
            
            # Look for organization info in different formats
            org_patterns = [
                r'Organization:\s*(.*)',
                r'org-name:\s*(.*)',
                r'OrgName:\s*(.*)',
                r'owner:\s*(.*)'
            ]
            
            for pattern in org_patterns:
                match = re.search(pattern, output)
                if match:
                    return match.group(1).strip()
            
            return "Unknown"
        except:
            return "Unknown"

    def _get_isp_info(self, ip: str) -> str:
        """Get ISP information"""
        try:
            whois_cmd = ['whois', ip]
            output = subprocess.check_output(whois_cmd, universal_newlines=True)
            
            # Look for ISP info
            isp_patterns = [
                r'inetnum:\s*(.*)',
                r'NetName:\s*(.*)',
                r'descr:\s*(.*)'
            ]
            
            for pattern in isp_patterns:
                match = re.search(pattern, output)
                if match:
                    return match.group(1).strip()
            
            return "Unknown"
        except:
            return "Unknown"

    def _check_blacklists(self, ip: str) -> Dict[str, str]:
        """Check IP against common blacklists"""
        blacklists = {
            'Spamhaus': self._check_spamhaus(ip),
            'SORBS': self._check_sorbs(ip),
            'SpamCop': self._check_spamcop(ip)
        }
        return {k: v for k, v in blacklists.items() if v is not None}

    def _check_threats(self, ip: str) -> List[str]:
        """Check for known threats associated with the IP"""
        threats = []
        
        # Check common threat indicators
        if self._is_tor_exit(ip):
            threats.append("TOR Exit Node")
        if self._is_proxy(ip):
            threats.append("Proxy/VPN")
        if self._is_known_malicious(ip):
            threats.append("Known Malicious Activity")
            
        return threats

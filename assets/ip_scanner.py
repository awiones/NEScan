import socket
import subprocess
import concurrent.futures
import platform
from typing import Dict, List, Optional
import logging
from colorama import Fore, Style
import time

class IPScanner:
    def __init__(self, timeout: int = 2):
        self.timeout = timeout
        self.OS_TYPE = platform.system().lower()

    def ping_host(self, ip: str) -> bool:
        """Attempt to ping a host"""
        try:
            if self.OS_TYPE == "windows":
                command = ['ping', '-n', '1', '-w', str(self.timeout * 1000), ip]
            else:
                command = ['ping', '-c', '1', '-W', str(self.timeout), ip]
            
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception:
            return False

    def check_port(self, ip: str, port: int) -> bool:
        """Try to connect to a common port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

    def check_host_availability(self, ip: str) -> Dict:
        """Check if host is available using multiple methods"""
        result = {
            'ip': ip,
            'is_up': False,
            'method': None,
            'ports_respond': False
        }

        # First try ping
        if self.ping_host(ip):
            result['is_up'] = True
            result['method'] = 'ping'
            return result

        # If ping fails, try common ports
        common_ports = [80, 443, 22, 445, 139]
        for port in common_ports:
            if self.check_port(ip, port):
                result['is_up'] = True
                result['method'] = f'port_{port}'
                result['ports_respond'] = True
                return result

        # If both methods fail, mark as potentially filtered
        result['method'] = 'filtered'
        return result

    def scan_host(self, ip: str, force_scan: bool = False) -> Dict:
        """
        Scan a host and determine if it should be scanned further
        force_scan: If True, treat as up regardless of ping/port checks (like Nmap -Pn)
        """
        result = self.check_host_availability(ip)
        
        if force_scan:
            result['should_scan'] = True
            result['scan_method'] = 'forced'
        else:
            result['should_scan'] = result['is_up'] or result['method'] == 'filtered'
            result['scan_method'] = 'normal' if result['is_up'] else 'filtered'

        return result

def scan_target(ip: str, force_scan: bool = False) -> Dict:
    """Utility function to scan a single target"""
    scanner = IPScanner()
    return scanner.scan_host(ip, force_scan)

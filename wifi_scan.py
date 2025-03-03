# =============================================================================
# Author      : awiones
# Created     : 2025-02-18
# License     : GNU General Public License v3.0
# Description : This code was developed by awiones. It is a comprehensive network
#               scanning tool designed to enumerate hosts, scan for open TCP and UDP
#               ports, retrieve DNS and HTTP information, and generate detailed reports
#               on network security and potential vulnerabilities.
# =============================================================================


#!/usr/bin/env python3
import subprocess
import os
import platform
from colorama import Fore, Style, init
from assets.wifi_scanner import WiFiScanner, format_wifi_results
import time

def check_wsl_wifi_capabilities():
    """Check WiFi capabilities in WSL environment"""
    print(f"{Fore.CYAN}Checking WSL WiFi capabilities...{Style.RESET_ALL}")
    
    # Check for Windows wireless interfaces using netsh directly
    try:
        paths = [
            '/mnt/c/Windows/System32/netsh.exe',
            '/mnt/c/Windows/SysWOW64/netsh.exe'
        ]
        
        netsh_path = None
        for path in paths:
            if os.path.exists(path):
                netsh_path = path
                break
        
        if netsh_path:
            result = subprocess.run([netsh_path, 'wlan', 'show', 'interfaces'], 
                                 capture_output=True, text=True)
            
            if "no wireless interface" not in result.stdout.lower():
                print(f"\n{Fore.GREEN}[✓] Windows wireless interfaces found:{Style.RESET_ALL}")
                print(result.stdout)
                return True
    except:
        pass
        
    print(f"\n{Fore.RED}[!] No wireless interfaces found in Windows host")
    print(f"\n{Fore.YELLOW}To enable WiFi scanning in WSL, you need to:{Style.RESET_ALL}")
    print("1. Ensure Windows has WiFi enabled")
    print("2. Enable WSL networking integration:")
    print("   - From PowerShell (as admin): 'wsl --shutdown'")
    print("   - Then restart your WSL terminal")
    print("3. Or use a USB WiFi adapter with WSL2")
    return False

def run_scan_loop():
    """Run continuous WiFi scanning"""
    init(autoreset=True)
    
    # Check if running in WSL
    in_wsl = 'microsoft' in platform.uname().release.lower()
    if in_wsl:
        if not check_wsl_wifi_capabilities():
            print(f"{Fore.YELLOW}[*] WSL WiFi capabilities not available, trying native methods...{Style.RESET_ALL}")
    
    try:
        scanner = WiFiScanner()
        while True:
            print(f"\n{Fore.CYAN}=== Scanning for WiFi Networks ==={Style.RESET_ALL}")
            try:
                networks = scanner.scan_networks()
                if networks:
                    print(format_wifi_results(networks))
                else:
                    print(f"{Fore.YELLOW}[!] No networks found{Style.RESET_ALL}")
                    print("[*] Troubleshooting:")
                    print("    1. Check if WiFi is enabled")
                    print("    2. Verify WiFi adapter is working")
                    print("    3. Try moving to a different location")
                    print("    4. Run 'sudo rfkill unblock wifi'")
            except Exception as e:
                print(f"{Fore.RED}[!] Scan failed: {str(e)}{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}[*] Press Ctrl+C to stop scanning{Style.RESET_ALL}")
            time.sleep(10)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scanning stopped by user{Style.RESET_ALL}")

if __name__ == "__main__":
    run_scan_loop()

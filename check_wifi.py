#!/usr/bin/env python3
import subprocess
import os
import platform
from colorama import Fore, Style, init

def is_wsl() -> bool:
    """Check if running in Windows Subsystem for Linux"""
    try:
        with open('/proc/version', 'r') as f:
            return 'microsoft' in f.read().lower() or 'wsl' in f.read().lower()
    except:
        return False

def run_powershell_command(command: str) -> str:
    """Run a PowerShell command and return its output"""
    try:
        full_command = f'powershell.exe -Command "{command}"'
        result = subprocess.run(full_command, capture_output=True, text=True, shell=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error executing PowerShell command: {str(e)}"

def check_wifi_capability():
    init(autoreset=True)
    print(f"{Fore.CYAN}=== WiFi Hardware Check ==={Style.RESET_ALL}\n")
    
    if is_wsl():
        print(f"{Fore.YELLOW}[!] Running in Windows Subsystem for Linux (WSL)")
        print("[*] Checking Windows host wireless interfaces...\n")
        
        try:
            # Check if WiFi is enabled in Windows
            wifi_status = run_powershell_command("Get-NetAdapter | Where-Object {$_.InterfaceDescription -Match 'Wireless|WiFi|802.11'} | Select-Object Status, InterfaceDescription | Format-Table")
            print(f"{Fore.CYAN}WiFi Adapters:{Style.RESET_ALL}")
            print(wifi_status)

            # Get available networks
            networks = run_powershell_command("netsh wlan show networks mode=Bssid")
            if "not running" not in networks.lower():
                print(f"\n{Fore.CYAN}Available Networks:{Style.RESET_ALL}")
                print(networks)
            
            print(f"\n{Fore.YELLOW}[*] To use WiFi scanning in WSL, you can:{Style.RESET_ALL}")
            print("    1. Use the Windows host's wireless adapter:")
            print("       - Run: netsh wlan show interfaces")
            print("       - Run: netsh wlan show networks")
            print("    2. Or install a USB WiFi adapter directly accessible to WSL")
            print("    3. Or configure WSL2 network bridging")
            
            # Additional debug information
            print(f"\n{Fore.CYAN}Debug Information:{Style.RESET_ALL}")
            wsl_version = run_powershell_command("wsl.exe --version")
            print(f"WSL Version: {wsl_version}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error accessing Windows wireless interfaces: {str(e)}{Style.RESET_ALL}")
            print("\nTroubleshooting steps:")
            print("1. Ensure you have administrative privileges")
            print("2. Check if WLAN AutoConfig service is running in Windows")
            print("3. Verify WiFi adapter is enabled in Windows Device Manager")
        return

    # Regular Linux checks
    system_info = {}
    
    # Check system type
    try:
        if os.path.exists('/sys/class/dmi/id/product_name'):
            with open('/sys/class/dmi/id/product_name', 'r') as f:
                system_info['product'] = f.read().strip()
        
        if os.path.exists('/sys/class/dmi/id/sys_vendor'):
            with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                system_info['vendor'] = f.read().strip()
                
        print(f"System: {system_info.get('vendor', 'Unknown')} {system_info.get('product', '')}")
    except:
        print("Could not determine system type")

    # Check PCI devices with multiple methods
    print("\nChecking PCI devices:")
    try:
        methods = [
            ['lspci', '-v'],
            ['lspci', '-nn'],
            ['lshw', '-C', 'network']
        ]
        
        for cmd in methods:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout:
                    network_devices = [line for line in result.stdout.split('\n') 
                                    if any(x in line.lower() for x in ['network', 'wireless', 'wifi'])]
                    if network_devices:
                        for device in network_devices:
                            print(f"[+] {device}")
                        break
            except:
                continue
        else:
            print(f"{Fore.YELLOW}[!] No PCI network devices found{Style.RESET_ALL}")
    except:
        print("Could not check PCI devices")

    # Additional system information
    print("\nSystem Information:")
    try:
        # Check kernel modules
        print("\nLoaded wireless modules:")
        result = subprocess.run(['lsmod'], capture_output=True, text=True)
        if result.returncode == 0:
            modules = [line for line in result.stdout.split('\n') 
                      if any(x in line.lower() for x in ['wifi', '80211', 'wireless'])]
            if modules:
                for module in modules:
                    print(f"[+] {module}")
            else:
                print(f"{Fore.YELLOW}[!] No wireless modules detected{Style.RESET_ALL}")
    except:
        print("Could not check kernel modules")

    # Network interface check
    print("\nNetwork Interfaces:")
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if result.returncode == 0:
            interfaces = result.stdout.split('\n')
            for iface in interfaces:
                if iface.strip():
                    print(f"[*] {iface.strip()}")
    except:
        print("Could not check network interfaces")

if __name__ == "__main__":
    check_wifi_capability()

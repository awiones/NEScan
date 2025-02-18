# =============================================================================
# Author      : awiones
# Created     : 2025-02-18
# License     : GNU General Public License v3.0
# Description : This code was developed by awiones. It is a comprehensive network
#               scanning tool designed to enumerate hosts, scan for open TCP and UDP
#               ports, retrieve DNS and HTTP information, and generate detailed reports
#               on network security and potential vulnerabilities.
# =============================================================================


import subprocess
import re
import time
import os
from typing import Dict, List
import platform
import logging
from colorama import Fore, Style
import requests 

class WiFiScanner:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.interface = None
        self.debug_info = []
        self.is_wsl = self._check_wsl()
        self.powershell_available = self._check_powershell()
        self.scan_retries = 3  # Number of scan retries
        self.deep_scan = False
        self.vuln_db = self._load_wifi_vulnerabilities()
        
        # Initialize WSL WiFi capabilities
        if self.is_wsl:
            self._init_wsl_wifi()
        else:
            self._check_wifi_hardware()
            self.setup_interface()

    def _check_wsl(self) -> bool:
        """Check if running in Windows Subsystem for Linux"""
        try:
            with open('/proc/version', 'r') as f:
                return 'microsoft' in f.read().lower()
        except:
            return False

    def _check_powershell(self) -> bool:
        """Check if PowerShell is accessible"""
        try:
            # Try using where.exe to find powershell
            result = subprocess.run(['where.exe', 'powershell.exe'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return True
                
            # Alternate check using common paths
            paths = [
                '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
                '/mnt/c/Program Files/PowerShell/7/pwsh.exe'
            ]
            return any(os.path.exists(path) for path in paths)
        except:
            return False

    def _init_wsl_wifi(self):
        """Initialize WiFi capabilities in WSL"""
        # Try Windows netsh command directly first
        try:
            netsh_paths = [
                '/mnt/c/Windows/System32/netsh.exe',
                '/mnt/c/Windows/SysWOW64/netsh.exe'
            ]
            
            for path in netsh_paths:
                if os.path.exists(path):
                    result = subprocess.run([path, 'wlan', 'show', 'interfaces'], 
                                         capture_output=True, text=True)
                    if "interface" in result.stdout.lower():
                        self.netsh_path = path
                        self._add_debug_info(f"Found working netsh at: {path}")
                        return
                        
            self._add_debug_info("No working netsh found")
        except Exception as e:
            self._add_debug_info(f"WSL WiFi init failed: {str(e)}")

    def _ensure_wlan_service(self):
        """Ensure WLAN service is running in Windows"""
        if not self.powershell_available:
            self._add_debug_info("Cannot access Windows WLAN service: PowerShell not available")
            return
        try:
            # Check WLAN service status
            check_cmd = '''
            $service = Get-Service -Name "WlanSvc" -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -ne 'Running') {
                    Start-Service WlanSvc
                    Start-Sleep -Seconds 2
                }
                Write-Output "WLAN Service Status: $($service.Status)"
            } else {
                Write-Output "WLAN Service not found"
            }
            '''
            result = subprocess.run(['powershell.exe', '-Command', check_cmd], 
                                  capture_output=True, text=True, shell=True)
            
            self._add_debug_info(f"WLAN Service check: {result.stdout.strip()}")

            # If service starts successfully, try to enable the wireless adapter
            if 'Running' in result.stdout:
                enable_cmd = '''
                $adapter = Get-NetAdapter | Where-Object {$_.InterfaceDescription -Match 'Wireless|WiFi|802.11'} | Select-Object -First 1
                if ($adapter) {
                    if ($adapter.Status -ne 'Up') {
                        Enable-NetAdapter -Name $adapter.Name -Confirm:$false
                        Start-Sleep -Seconds 2
                    }
                    Write-Output "Wireless Adapter Status: $($adapter.Status)"
                } else {
                    Write-Output "No wireless adapter found"
                }
                '''
                adapter_result = subprocess.run(['powershell.exe', '-Command', enable_cmd], 
                                             capture_output=True, text=True, shell=True)
                self._add_debug_info(f"Wireless adapter check: {adapter_result.stdout.strip()}")
            
        except Exception as e:
            self._add_debug_info(f"Failed to configure WLAN service: {str(e)}")

    def _setup_wsl_scanning(self):
        """Setup automatic WiFi scanning in WSL"""
        try:
            # Enable WLAN AutoConfig service
            subprocess.run(['powershell.exe', 'Start-Service', 'WlanSvc'], capture_output=True)
            # Configure WiFi adapter
            subprocess.run(['powershell.exe', 'Get-NetAdapter | Where-Object {$_.InterfaceDescription -Match "Wireless|WiFi|802.11"} | Enable-NetAdapter'], capture_output=True)
            time.sleep(2)  # Give the service time to start
        except Exception as e:
            self._add_debug_info(f"WSL scanning setup failed: {str(e)}")

    def _check_wifi_hardware(self):
        """Check if WiFi hardware is present"""
        try:
            # Check if running in VM
            is_vm = False
            try:
                with open('/sys/class/dmi/id/product_name', 'r') as f:
                    product = f.read().strip().lower()
                    if any(x in product for x in ['virtual', 'vmware', 'vbox']):
                        is_vm = True
            except:
                pass

            # Check for WiFi hardware
            wifi_exists = False
            try:
                lspci = subprocess.run(['lspci'], capture_output=True, text=True)
                if any('network' in line.lower() or 'wireless' in line.lower() for line in lspci.stdout.split('\n')):
                    wifi_exists = True
            except:
                pass

            try:
                lsusb = subprocess.run(['lsusb'], capture_output=True, text=True)
                if any('wireless' in line.lower() or 'wifi' in line.lower() for line in lsusb.stdout.split('\n')):
                    wifi_exists = True
            except:
                pass

            if is_vm and not wifi_exists:
                print(f"{Fore.YELLOW}[!] Running in virtual machine without WiFi hardware")
                print("[*] To use WiFi scanning, you need to:")
                print("    1. Add a virtual wireless adapter to your VM, or")
                print("    2. Pass through a physical wireless adapter")
                print(f"    3. Ensure WiFi drivers are installed{Style.RESET_ALL}")
            elif not wifi_exists:
                print(f"{Fore.YELLOW}[!] No WiFi hardware detected")
                print("[*] Please ensure:")
                print("    1. Your system has WiFi hardware")
                print("    2. WiFi hardware is not disabled (check rfkill)")
                print(f"    3. Proper drivers are installed{Style.RESET_ALL}")

            self._add_debug_info(f"VM detected: {is_vm}")
            self._add_debug_info(f"WiFi hardware detected: {wifi_exists}")

        except Exception as e:
            self._add_debug_info(f"Hardware check failed: {str(e)}")

    def setup_interface(self):
        """Setup wireless interface with fallback options"""
        try:
            # First try to get existing interface
            self.interface = self._get_wireless_interface()
            if self.interface:
                print(f"{Fore.GREEN}[✓] Found wireless interface: {self.interface}{Style.RESET_ALL}")
                return

            # If no interface found, try to create a monitor interface
            self.interface = self._create_monitor_interface()
            if self.interface:
                print(f"{Fore.GREEN}[✓] Created monitor interface: {self.interface}{Style.RESET_ALL}")
                return

            raise Exception("Could not find or create wireless interface")
        except Exception as e:
            logging.error(f"Interface setup failed: {e}")
            raise

    def _create_monitor_interface(self) -> str:
        """Attempt to create a monitor interface"""
        try:
            if self.os_type != "linux":
                return None

            # Try to load necessary kernel modules
            modules = ['mac80211', 'cfg80211', 'iwlwifi']
            for module in modules:
                try:
                    subprocess.run(['sudo', 'modprobe', module], capture_output=True)
                except:
                    pass

            # Check for any network interface that might support monitor mode
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            interfaces = re.findall(r'\d+: ([^:@]+)[:@]', result.stdout)
            
            for iface in interfaces:
                # Skip loopback and ethernet interfaces
                if iface in ['lo', 'eth0', 'ens33'] or iface.startswith(('eth', 'ens', 'enp')):
                    continue
                
                try:
                    # Try to set interface up
                    subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'], capture_output=True)
                    time.sleep(1)
                    
                    # Check if interface is wireless
                    check = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
                    if 'no wireless extensions' not in check.stderr:
                        return iface
                except:
                    continue

            return None

        except Exception as e:
            logging.error(f"Failed to create monitor interface: {e}")
            return None

    def _add_debug_info(self, msg: str):
        """Add debug information for troubleshooting"""
        self.debug_info.append(msg)
        if self.debug_info:
            print(f"{Fore.YELLOW}[*] Debug: {msg}{Style.RESET_ALL}")

    def _get_wireless_interface(self) -> str:
        """Get the first available wireless interface with extended detection"""
        try:
            if self.os_type == "linux":
                interfaces = []
                
                # Method 1: Direct check of network interfaces
                try:
                    for iface in os.listdir('/sys/class/net'):
                        # Check if it might be a wireless interface
                        if os.path.exists(f'/sys/class/net/{iface}/wireless') or \
                           os.path.exists(f'/sys/class/net/{iface}/phy80211'):
                            self._add_debug_info(f"Found potential wireless interface: {iface}")
                            interfaces.append(iface)
                except Exception as e:
                    self._add_debug_info(f"Method 1 failed: {str(e)}")

                # Method 2: Use ip link
                try:
                    result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                    self._add_debug_info(f"ip link output: {result.stdout}")
                    # Look for wireless interfaces (wlan, wifi, etc.)
                    for line in result.stdout.split('\n'):
                        if any(wpattern in line.lower() for wpattern in ['wlan', 'wifi', 'wireless']):
                            iface = line.split(':')[1].strip()
                            interfaces.append(iface)
                except Exception as e:
                    self._add_debug_info(f"Method 2 failed: {str(e)}")

                # Method 3: Use iwconfig
                try:
                    result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                    self._add_debug_info(f"iwconfig output: {result.stdout}")
                    for line in result.stdout.split('\n'):
                        if 'no wireless extensions' not in line and line.strip():
                            iface = line.split()[0]
                            interfaces.append(iface)
                except Exception as e:
                    self._add_debug_info(f"Method 3 failed: {str(e)}")

                # Method 4: Check common names
                common_interfaces = ['wlan0', 'wlp2s0', 'wlp3s0', 'wifi0', 'wlp0s20f3']
                for iface in common_interfaces:
                    if os.path.exists(f'/sys/class/net/{iface}'):
                        interfaces.append(iface)

                # Remove duplicates
                interfaces = list(set(interfaces))
                self._add_debug_info(f"Found interfaces: {interfaces}")

                if not interfaces:
                    # Try to load wireless modules
                    try:
                        subprocess.run(['sudo', 'modprobe', 'iwlwifi'], capture_output=True)
                        subprocess.run(['sudo', 'modprobe', 'cfg80211'], capture_output=True)
                        time.sleep(2)
                        # Recheck interfaces
                        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                        for line in result.stdout.split('\n'):
                            if 'no wireless extensions' not in line and line.strip():
                                iface = line.split()[0]
                                interfaces.append(iface)
                    except Exception as e:
                        self._add_debug_info(f"Module loading failed: {str(e)}")

                # Try to activate the first available interface
                for iface in interfaces:
                    try:
                        subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'], capture_output=True)
                        self._add_debug_info(f"Successfully activated interface: {iface}")
                        return iface
                    except Exception as e:
                        self._add_debug_info(f"Failed to activate {iface}: {str(e)}")
                        continue

            elif self.os_type == "darwin":
                try:
                    # First try using networksetup
                    result = subprocess.run(['networksetup', '-listallhardwareports'], capture_output=True, text=True)
                    wifi_info = re.search(r'Hardware Port: Wi-Fi\nDevice: (en\d+)', result.stdout)
                    if wifi_info:
                        return wifi_info.group(1)
                    
                    # Fallback to airport utility
                    result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                                         capture_output=True, text=True)
                    if result.returncode == 0:
                        return 'en0'  # Default macOS WiFi interface
                except:
                    pass

            if not interfaces:
                # Get system information for debugging
                try:
                    lspci = subprocess.run(['lspci'], capture_output=True, text=True)
                    self._add_debug_info(f"lspci output: {lspci.stdout}")
                except:
                    pass

                try:
                    dmesg = subprocess.run(['dmesg', '|', 'grep', '-i', 'wifi'], capture_output=True, text=True)
                    self._add_debug_info(f"dmesg wifi info: {dmesg.stdout}")
                except:
                    pass

                raise Exception("No wireless interfaces found. Debug info:\n" + "\n".join(self.debug_info))

        except Exception as e:
            self._add_debug_info(f"Interface detection failed: {str(e)}")
            raise Exception(f"Could not find wireless interface. Run with --verbose for debug info. Error: {str(e)}")

    def _get_windows_wifi_info(self) -> List[Dict]:
        """Get WiFi information using Windows netsh command"""
        try:
            if hasattr(self, 'netsh_path'):
                # First ensure WLAN service is running
                self._ensure_wlan_service()
                
                # Get all wireless interfaces
                iface_result = subprocess.run([self.netsh_path, 'wlan', 'show', 'interfaces'], 
                                           capture_output=True, text=True, shell=False)
                
                # Force refresh on all interfaces and scan multiple times
                networks = []
                for attempt in range(self.scan_retries):
                    print(f"{Fore.YELLOW}[*] Scanning attempt {attempt + 1}/{self.scan_retries}...{Style.RESET_ALL}")
                    
                    # Force rescan on all interfaces
                    subprocess.run([self.netsh_path, 'wlan', 'scan'], 
                                capture_output=True, text=True, shell=False)
                    time.sleep(2)  # Wait for scan to complete
                    
                    # Get all networks with full details
                    result = subprocess.run([self.netsh_path, 'wlan', 'show', 'all'], 
                                         capture_output=True, text=True, shell=False)
                    
                    # Parse networks from the detailed output
                    current_network = None
                    
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        
                        if 'SSID' in line and ':' in line and 'BSSID' not in line:
                            if current_network:
                                if current_network['ssid']:  # Only add networks with valid SSIDs
                                    networks.append(current_network)
                            current_network = {
                                'ssid': line.split(':', 1)[1].strip().strip('"'),
                                'encryption': [],
                                'quality': 'Unknown',
                                'signal': 'Unknown',
                                'channel': 'Unknown',
                                'bssids': [],
                                'frequency': ''
                            }
                        
                        elif current_network and ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            if 'Signal' in key:
                                if value != "Unknown":
                                    try:
                                        signal_percent = int(value.rstrip('%'))
                                        current_network['quality'] = f"{signal_percent}%"
                                        dbm = int((signal_percent / 100.0 * 60) - 100)
                                        current_network['signal'] = f"{dbm} dBm"
                                    except ValueError:
                                        current_network['quality'] = value
                                        current_network['signal'] = 'Unknown'
                            elif 'Authentication' in key:
                                auth_type = value.strip()
                                if 'WPA' in auth_type:
                                    current_network['encryption'].append('WPA2')
                                elif 'WEP' in auth_type:
                                    current_network['encryption'].append('WEP')
                                current_network['encrypted'] = auth_type != 'Open'
                            elif 'BSSID' in key:
                                bssid = value.strip()
                                if bssid and bssid not in current_network['bssids']:
                                    current_network['bssids'].append(bssid)
                            elif 'Channel' in key:
                                try:
                                    channel = int(value)
                                    current_network['channel'] = channel
                                    # Set frequency band based on channel
                                    if channel <= 14:
                                        current_network['frequency'] = "2.4 GHz"
                                    else:
                                        current_network['frequency'] = "5 GHz"
                                except ValueError:
                                    current_network['channel'] = value
                    
                    # Add the last network
                    if current_network and current_network['ssid']:
                        networks.append(current_network)
                    
                    # Remove duplicates while keeping the strongest signal
                    unique_networks = {}
                    for network in networks:
                        ssid = network['ssid']
                        if ssid not in unique_networks or \
                           (network['signal'] != 'Unknown' and 
                            (unique_networks[ssid]['signal'] == 'Unknown' or 
                             int(network['signal'].split()[0]) > int(unique_networks[ssid]['signal'].split()[0]))):
                            unique_networks[ssid] = network
                    
                    networks = list(unique_networks.values())
                    
                    if networks:
                        return sorted(networks, key=lambda x: x['ssid'].lower())
                    
                    time.sleep(1)

                print(f"{Fore.YELLOW}[!] No networks found after {self.scan_retries} attempts")
                return []

            return self._handle_missing_netsh()

        except Exception as e:
            self._add_debug_info(f"Windows WiFi scan failed: {str(e)}")
            return []

    def _handle_missing_netsh(self) -> List[Dict]:
        """Handle case when netsh is not available"""
        print(f"{Fore.RED}[!] Cannot access Windows WiFi functionality")
        print(f"{Fore.YELLOW}Please check:")
        print("1. Windows WiFi is enabled")
        print("2. WSL has access to Windows network")
        print("3. Try running 'wsl --shutdown' from PowerShell")
        print(f"4. Restart your WSL terminal{Style.RESET_ALL}")
        return []

    def _parse_windows_networks(self, output: str) -> List[Dict]:
        """Parse Windows netsh output into network list"""
        networks = []
        current_network = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'SSID' in line and ':' in line and 'BSSID' not in line:
                if current_network:
                    networks.append(current_network)
                current_network = {
                    'ssid': line.split(':', 1)[1].strip().strip('"'),
                    'encryption': [],
                    'quality': '0%',
                    'signal': '0 dBm',
                    'channel': '0'
                }
            
            elif current_network:
                if 'Signal' in line and ':' in line:
                    signal = line.split(':', 1)[1].strip().rstrip('%')
                    current_network['quality'] = f"{signal}%"
                    dbm = int((int(signal) / 100.0 * 60) - 100)
                    current_network['signal'] = f"{dbm} dBm"
                elif 'Authentication' in line and ':' in line:
                    auth = line.split(':', 1)[1].strip()
                    if 'WPA' in auth:
                        current_network['encryption'].append('WPA2')
                    current_network['encrypted'] = auth != 'Open'
                elif 'Channel' in line and ':' in line:
                    current_network['channel'] = line.split(':', 1)[1].strip()

        if current_network:
            networks.append(current_network)
            
        return networks

    def scan_networks(self, deep_scan: bool = False) -> List[Dict]:
        """Enhanced network scanning with optional deep scan"""
        self.deep_scan = deep_scan
        
        if self.is_wsl:
            print(f"{Fore.YELLOW}[*] Using Windows host's wireless interface{Style.RESET_ALL}")
            networks = self._get_windows_wifi_info()
            if not networks:
                print(f"{Fore.YELLOW}[*] Windows WiFi scanning failed, trying native methods...{Style.RESET_ALL}")
                return self._scan_native()
            return networks

        if not self.interface:
            raise Exception("No wireless interface found. Please ensure WiFi is enabled.")

        print(f"{Fore.BLUE}[*] Using wireless interface: {self.interface}{Style.RESET_ALL}")

        try:
            if self.os_type == "linux":
                # Try to ensure interface is up
                try:
                    subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], capture_output=True)
                    time.sleep(1)  # Give interface time to come up
                except:
                    pass
                return self._scan_linux()
            elif self.os_type == "darwin":
                return self._scan_macos()
            else:
                raise Exception("Unsupported operating system")
        except Exception as e:
            logging.error(f"WiFi scan failed: {e}")
            raise

    def _scan_native(self) -> List[Dict]:
        """Attempt to scan using native Linux WiFi tools"""
        networks = []
        
        try:
            # Try using iwlist
            result = subprocess.run(['sudo', 'iwlist', 'wlan0', 'scan'], 
                                 capture_output=True, text=True)
            if "Interface doesn't support scanning" not in result.stderr:
                return self._scan_linux()  # Use existing Linux scanning method
        except:
            pass
            
        try:
            # Try using iw
            result = subprocess.run(['sudo', 'iw', 'dev', 'wlan0', 'scan'], 
                                 capture_output=True, text=True)
            if "command failed" not in result.stderr:
                # Parse iw output
                return self._parse_iw_scan(result.stdout)
        except:
            pass
            
        return networks

    def _scan_linux(self) -> List[Dict]:
        """Scan WiFi networks on Linux"""
        try:
            # Force rescan
            subprocess.run(['sudo', 'iwlist', self.interface, 'scan'], capture_output=True)
            time.sleep(1)  # Wait for scan to complete
            
            result = subprocess.run(['sudo', 'iwlist', self.interface, 'scan'], capture_output=True, text=True)
            networks = []
            
            current_network = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'Cell' in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {'encryption': []}
                
                if 'ESSID:' in line:
                    essid = re.findall(r'ESSID:"([^"]*)"', line)
                    current_network['ssid'] = essid[0] if essid else 'Hidden Network'
                
                elif 'Quality=' in line:
                    quality = re.findall(r'Quality=(\d+/\d+)', line)
                    signal = re.findall(r'Signal level=(-\d+) dBm', line)
                    if quality:
                        num, den = map(int, quality[0].split('/'))
                        current_network['quality'] = f"{(num/den)*100:.0f}%"
                    if signal:
                        current_network['signal'] = f"{signal[0]} dBm"
                
                elif 'Encryption key:' in line:
                    current_network['encrypted'] = 'on' in line.lower()
                
                elif 'IE: IEEE 802.11i/WPA2' in line:
                    current_network['encryption'].append('WPA2')
                elif 'IE: WPA Version' in line:
                    current_network['encryption'].append('WPA')
            
            if current_network:
                networks.append(current_network)
                
            return networks
            
        except Exception as e:
            logging.error(f"Linux WiFi scan failed: {e}")
            return []

    def _scan_macos(self) -> List[Dict]:
        """Scan WiFi networks on macOS"""
        try:
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                                  capture_output=True, text=True)
            
            networks = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header line
            
            for line in lines:
                fields = line.split()
                if len(fields) >= 7:
                    networks.append({
                        'ssid': fields[0],
                        'signal': f"{fields[2]} dBm",
                        'quality': f"{(float(fields[2]) + 100):.0f}%",
                        'encryption': ['WPA2'] if fields[6] != 'NONE' else [],
                        'encrypted': fields[6] != 'NONE'
                    })
            
            return networks
            
        except Exception as e:
            logging.error(f"macOS WiFi scan failed: {e}")
            return []

    def _get_network_details(self, network: Dict, retries: int = 3) -> Dict:
        """Get comprehensive network details with multiple methods"""
        try:
            for _ in range(retries):
                # Try getting active state information first
                if self.is_wsl:
                    try:
                        # Get current connection status
                        status = subprocess.run([self.netsh_path, 'wlan', 'show', 'interface'], 
                                             capture_output=True, text=True)
                        if network['ssid'] in status.stdout:
                            network['state'] = 'Connected'
                            # Get IP if connected
                            ipconfig = subprocess.run(['ipconfig.exe'], capture_output=True, text=True)
                            ip_match = re.search(r'IPv4 Address[^:]*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ipconfig.stdout)
                            if ip_match:
                                network['ip_address'] = ip_match.group(1)
                        else:
                            network['state'] = 'Not Connected'

                        # Get manufacturer info for each BSSID
                        if 'bssids' in network:
                            network['manufacturers'] = []
                            for bssid in network['bssids']:
                                vendor = self._get_network_vendor(bssid)
                                if vendor != "Unknown":
                                    network['manufacturers'].append(f"{bssid} ({vendor})")
                                else:
                                    network['manufacturers'].append(bssid)

                        # Get authentication details
                        auth_details = subprocess.run([self.netsh_path, 'wlan', 'show', 'networks', 
                                                    f'ssid={network["ssid"]}', 'key=clear'],
                                                    capture_output=True, text=True)
                        
                        # Parse authentication and cipher details
                        auth_match = re.search(r'Authentication\s*:\s*(.*)', auth_details.stdout)
                        cipher_match = re.search(r'Cipher\s*:\s*(.*)', auth_details.stdout)
                        
                        if auth_match:
                            network['authentication'] = auth_match.group(1).strip()
                        if cipher_match:
                            network['cipher'] = cipher_match.group(1).strip()

                        # Get connection capabilities
                        network['capabilities'] = []
                        if "802.11ac" in auth_details.stdout:
                            network['capabilities'].append("WiFi 5 (802.11ac)")
                        if "802.11ax" in auth_details.stdout:
                            network['capabilities'].append("WiFi 6 (802.11ax)")
                        if "WPA3" in auth_details.stdout:
                            network['capabilities'].append("WPA3 Support")

                        # Determine network type and broadcast status
                        network['network_type'] = 'Infrastructure' if 'BSS Network' in auth_details.stdout else 'Ad-hoc'
                        network['ssid_broadcast'] = 'Enabled' if not 'Hidden Network' in auth_details.stdout else 'Disabled'

                        # Get signal quality metrics
                        signal_strength = int(network['quality'].rstrip('%'))
                        network['signal_rating'] = (
                            'Excellent' if signal_strength >= 80 else
                            'Good' if signal_strength >= 60 else
                            'Fair' if signal_strength >= 40 else
                            'Poor'
                        )

                        # Get frequency details
                        if 'channel' in network:
                            channel = int(network['channel'])
                            if channel <= 14:
                                network['frequency'] = "2.4 GHz"
                                network['channel_width'] = "20/40 MHz"
                            else:
                                network['frequency'] = "5 GHz"
                                network['channel_width'] = "20/40/80 MHz"

                        return network
                    except Exception as e:
                        self._add_debug_info(f"WSL detail fetch error: {str(e)}")
                        continue

                # For Linux systems
                else:
                    try:
                        # Use iw for detailed scanning
                        iw_result = subprocess.run(['sudo', 'iw', 'dev', self.interface, 'scan'],
                                                capture_output=True, text=True)
                        # Parse iw output for additional details
                        # ... Linux-specific parsing code ...
                    except Exception as e:
                        self._add_debug_info(f"Linux detail fetch error: {str(e)}")
                        continue

            return network
        except Exception as e:
            self._add_debug_info(f"Detail fetch error: {str(e)}")
            return network

    def scan_specific_network(self, target_ssid: str) -> Dict:
        """Scan for a specific WiFi network with improved detail collection"""
        try:
            networks = self.scan_networks()
            if not networks:
                raise Exception("No networks found")

            # Case-insensitive search for target network
            target_network = next(
                (network for network in networks 
                 if network['ssid'].lower() == target_ssid.lower()),
                None
            )
            
            if not target_network:
                similar_networks = [
                    net['ssid'] for net in networks 
                    if target_ssid.lower() in net['ssid'].lower()
                ]
                
                error_msg = f"Network '{target_ssid}' not found."
                if similar_networks:
                    error_msg += f"\nSimilar networks: {', '.join(similar_networks)}"
                raise Exception(error_msg)
            
            if target_network:
                # Get enhanced network details
                target_network = self._get_network_details(target_network)
                
                # Add security assessment
                if target_network.get('encryption'):
                    security_score = self._assess_network_security(target_network)
                    target_network['security_assessment'] = {
                        'score': security_score,
                        'rating': self._get_security_rating(security_score),
                        'recommendations': self._get_security_recommendations(target_network)
                    }

            return target_network
            
        except Exception as e:
            raise Exception(f"Error scanning for network: {str(e)}")

    def _parse_network_details(self, network: Dict, details: str) -> None:
        """Parse detailed network information"""
        try:
            # Enhanced network details patterns
            patterns = {
                'Channel': r'Channel\s*:\s*(\d+)',
                'Band': r'Band\s*:\s*([\d.]+)',
                'Radio type': r'Radio type\s*:\s*(.+)',
                'Basic rates': r'Basic rates \(Mbps\)\s*:\s*(.+)',
                'Other rates': r'Other rates \(Mbps\)\s*:\s*(.+)',
                'BSSID': r'BSSID \d+\s*:\s*([0-9A-Fa-f:]+)',
                'Signal': r'Signal\s*:\s*(\d+)%',
                'Network type': r'Network type\s*:\s*(.+)',
                'Authentication': r'Authentication\s*:\s*(.+)',
                'Encryption': r'Encryption\s*:\s*(.+)',
                'Connection': r'Connection mode\s*:\s*(.+)',
                'Interface': r'Interface\s*:\s*(.+)',
                'Physical address': r'Physical address\s*:\s*([0-9A-Fa-f:]+)',
                'State': r'State\s*:\s*(.+)',
                'SSID broadcast': r'SSID Broadcast\s*:\s*(.+)'
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, details)
                if match:
                    value = match.group(1).strip()
                    if key == 'Band':
                        network['frequency'] = f"{value} GHz"
                    elif key == 'BSSID':
                        network.setdefault('bssids', []).append(value)
                    elif key in ['Basic rates', 'Other rates']:
                        network.setdefault('supported_rates', []).extend(value.split())
                    else:
                        network[key.lower()] = value

            # Try to get IP address if connected
            if network.get('state', '').lower() == 'connected':
                try:
                    ip_info = subprocess.run([self.netsh_path, 'interface', 'ip', 'show', 'address'], 
                                          capture_output=True, text=True)
                    if ip_info.stdout:
                        ip_match = re.search(rf'Interface\s+.+?{network.get("interface", "")}.*?IP Address:\s+(\d+\.\d+\.\d+\.\d+)',
                                           ip_info.stdout, re.DOTALL)
                        if ip_match:
                            network['ip_address'] = ip_match.group(1)
                except:
                    pass
                    
        except Exception as e:
            self._add_debug_info(f"Error parsing network details: {str(e)}")

    def _get_additional_details_linux(self, network: Dict):
        """Get additional network details on Linux"""
        try:
            result = subprocess.run(['sudo', 'iwlist', self.interface, 'scan'], capture_output=True, text=True)
            for block in result.stdout.split('Cell'):
                if network['ssid'] in block:
                    # Extract frequency
                    freq = re.findall(r'Frequency:(\d+\.\d+) GHz', block)
                    if freq:
                        network['frequency'] = f"{freq[0]} GHz"
                    
                    # Extract channel
                    channel = re.findall(r'Channel:(\d+)', block)
                    if channel:
                        network['channel'] = channel[0]
                    
                    # Extract supported rates
                    rates = re.findall(r'Bit Rates:(.*?)(?=\n)', block)
                    if rates:
                        network['rates'] = rates[0].strip()
                    break
        except Exception as e:
            logging.error(f"Failed to get additional details: {e}")

    def _get_additional_details_macos(self, network: Dict):
        """Get additional network details on macOS"""
        try:
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if network['ssid'] in line:
                    fields = line.split()
                    if len(fields) >= 7:
                        network['channel'] = fields[3]
                        network['frequency'] = "2.4 GHz" if int(fields[3]) <= 14 else "5 GHz"
                    break
        except Exception as e:
            logging.error(f"Failed to get additional details: {e}")

    def _load_wifi_vulnerabilities(self) -> Dict:
        """Load known WiFi vulnerabilities database"""
        return {
            'WEP': {
                'risk': 'HIGH',
                'description': 'WEP encryption is broken and can be cracked easily',
                'mitigations': ['Upgrade to WPA3', 'Use strong passwords']
            },
            'WPA': {
                'risk': 'MEDIUM',
                'description': 'Original WPA has known vulnerabilities',
                'mitigations': ['Upgrade to WPA3']
            },
            'WPA2': {
                'risk': 'LOW-MEDIUM',
                'description': 'Vulnerable to KRACK attacks if not patched',
                'mitigations': ['Update firmware', 'Use WPA3 if available']
            }
        }

    def _get_network_vendor(self, mac: str) -> str:
        """Get vendor information from MAC address"""
        try:
            oui = mac.replace(':', '').upper()[:6]
            url = f"https://api.macvendors.com/{oui}"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                return response.text.strip()
            return "Unknown"
        except:
            return "Unknown"

    def _get_additional_network_info(self, network: Dict) -> Dict:
        """Get additional network information"""
        try:
            if hasattr(self, 'netsh_path'):
                # Get detailed network information
                cmd = [
                    self.netsh_path, 'wlan', 'show', 'network',
                    f'name="{network["ssid"]}"', 'mode=Bssid'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Parse additional information
                info = {
                    'capabilities': [],
                    'protocols': set(),
                    'vendors': set(),
                    'vulnerabilities': [],
                    'security_rating': 'Unknown'
                }
                
                # Extract capabilities
                if '802.11ac' in result.stdout:
                    info['protocols'].add('802.11ac')
                if '802.11ax' in result.stdout:
                    info['protocols'].add('802.11ax (WiFi 6)')
                
                # Check for vulnerabilities
                security_score = 100
                if network.get('encryption'):
                    for enc in network['encryption']:
                        if enc in self.vuln_db:
                            vuln = self.vuln_db[enc]
                            info['vulnerabilities'].append({
                                'type': enc,
                                'risk': vuln['risk'],
                                'description': vuln['description'],
                                'mitigations': vuln['mitigations']
                            })
                            if vuln['risk'] == 'HIGH':
                                security_score -= 40
                            elif vuln['risk'] == 'MEDIUM':
                                security_score -= 20
                            else:
                                security_score -= 10

                # Get vendor information for each BSSID
                if 'bssids' in network:
                    for bssid in network['bssids']:
                        vendor = self._get_network_vendor(bssid)
                        if vendor != "Unknown":
                            info['vendors'].add(vendor)

                # Calculate security rating
                info['security_rating'] = (
                    'High' if security_score >= 80 else
                    'Medium' if security_score >= 60 else
                    'Low'
                )
                
                network['advanced_info'] = info
                
            return network
        except Exception as e:
            logging.error(f"Error getting additional network info: {e}")
            return network

    def _assess_network_security(self, network: Dict) -> int:
        """Calculate security score for network"""
        score = 100

        # Check encryption
        if not network.get('encryption'):
            score -= 80  # Open network
        else:
            for enc in network['encryption']:
                if enc == 'WEP':
                    score -= 60  # Severe vulnerability
                elif enc == 'WPA':
                    score -= 30  # Known vulnerabilities
                elif enc == 'WPA2':
                    score -= 10  # Some vulnerabilities but generally secure

        # Check signal strength
        signal_strength = int(network['quality'].rstrip('%'))
        if signal_strength < 30:
            score -= 20  # Poor signal
        elif signal_strength < 60:
            score -= 10  # Moderate signal

        # Check channel congestion (if available)
        if 'channel' in network:
            channel = int(network['channel'])
            if channel in [1, 6, 11]:  # Optimal 2.4GHz channels
                score += 5
            elif channel > 14:  # 5GHz channels typically have less interference
                score += 10

        # Additional security features
        if network.get('authentication', '').startswith('WPA3'):
            score += 15
        if network.get('ssid_broadcast') == 'Disabled':
            score += 5

        return max(0, min(100, score))  # Ensure score is between 0 and 100

    def _get_security_rating(self, score: int) -> str:
        """Convert security score to rating"""
        if score >= 90:
            return f"{Fore.GREEN}Excellent{Style.RESET_ALL}"
        elif score >= 75:
            return f"{Fore.BLUE}Good{Style.RESET_ALL}"
        elif score >= 60:
            return f"{Fore.YELLOW}Fair{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}Poor{Style.RESET_ALL}"

    def _get_security_recommendations(self, network: Dict) -> List[str]:
        """Generate security recommendations based on network configuration"""
        recommendations = []

        # Check encryption
        if not network.get('encryption'):
            recommendations.append("CRITICAL: Enable encryption immediately (WPA2 or WPA3)")
        elif 'WEP' in network.get('encryption', []):
            recommendations.append("CRITICAL: Replace WEP with WPA2 or WPA3")
        elif 'WPA' in network.get('encryption', []) and 'WPA2' not in network.get('encryption', []):
            recommendations.append("HIGH: Upgrade to WPA2 or WPA3")

        # Check signal strength
        signal_strength = int(network['quality'].rstrip('%'))
        if signal_strength < 30:
            recommendations.append("LOW: Improve signal strength (consider adding repeaters)")

        # Channel recommendations
        if 'channel' in network:
            channel = int(network['channel'])
            if channel <= 14 and channel not in [1, 6, 11]:
                recommendations.append("LOW: Use channels 1, 6, or 11 for better 2.4GHz performance")

        # Additional security recommendations
        if network.get('ssid_broadcast') == 'Enabled':
            recommendations.append("LOW: Consider disabling SSID broadcast")
        if not any('WPA3' in cap for cap in network.get('capabilities', [])):
            recommendations.append("MEDIUM: Consider upgrading to WPA3 if hardware supports it")

        return recommendations

def format_wifi_results(networks: List[Dict], target_ssid: str = None) -> str:
    """Format WiFi scan results for display"""
    if not networks:
        return f"{Fore.RED}No networks found{Style.RESET_ALL}"

    output = []
    
    if (target_ssid):
        output.append(f"\n{Fore.CYAN}╔{'═' * 68}╗")
        output.append(f"║{' '*20}DETAILED WIFI SCAN RESULTS{' '*22}║")
        output.append(f"╚{'═' * 68}╝{Style.RESET_ALL}\n")
        
        network = networks[0] if isinstance(networks, list) else networks
        output.append(f"{Fore.YELLOW}Network Details:{Style.RESET_ALL}")
        output.append(f"• SSID: {network['ssid']}")
        output.append(f"• Status:")
        output.append(f"  ├─ State: {network.get('state', 'Unknown')}")
        output.append(f"  ├─ Signal: {network['signal']} ({network['quality']})")
        if 'ip_address' in network:
            output.append(f"  └─ IP Address: {network['ip_address']}")
        
        output.append(f"• Security:")
        output.append(f"  ├─ Authentication: {network.get('authentication', 'Unknown')}")
        output.append(f"  ├─ Encryption: {', '.join(network['encryption']) if network['encryption'] else 'None'}")
        output.append(f"  └─ SSID Broadcast: {network.get('ssid_broadcast', 'Unknown')}")
        
        output.append(f"• Hardware:")
        if 'physical_address' in network:
            output.append(f"  ├─ MAC Address: {network['physical_address']}")
        if 'interface' in network:
            output.append(f"  ├─ Interface: {network['interface']}")
        if 'radio_type' in network:
            output.append(f"  └─ Radio Type: {network['radio_type']}")
        
        output.append(f"• Network Configuration:")
        if 'channel' in network:
            output.append(f"  ├─ Channel: {network['channel']}")
        if 'frequency' in network:
            output.append(f"  ├─ Frequency Band: {network['frequency']}")
        if 'network_type' in network:
            output.append(f"  └─ Network Type: {network['network_type']}")
        
        if 'bssids' in network:
            output.append(f"• Access Points:")
            for bssid in network['bssids']:
                output.append(f"  └─ {bssid}")
        
        if 'supported_rates' in network:
            output.append(f"• Supported Rates (Mbps): {', '.join(network['supported_rates'])}")
        
        # Add scan timestamp
        output.append(f"\n{Fore.BLUE}Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        
        # Add advanced information if available
        if 'advanced_info' in network:
            info = network['advanced_info']
            
            output.append(f"\n• Advanced Information:")
            if info['protocols']:
                output.append(f"  ├─ Supported Protocols: {', '.join(info['protocols'])}")
            if info['vendors']:
                output.append(f"  ├─ Equipment Vendors: {', '.join(info['vendors'])}")
            output.append(f"  └─ Security Rating: {info['security_rating']}")
            
            if info['vulnerabilities']:
                output.append(f"\n• Security Vulnerabilities:")
                for vuln in info['vulnerabilities']:
                    output.append(f"  ├─ Type: {vuln['type']} ({vuln['risk']} Risk)")
                    output.append(f"  ├─ Issue: {vuln['description']}")
                    output.append(f"  └─ Mitigations: {', '.join(vuln['mitigations'])}")

    else:
        output.append(f"\n{Fore.CYAN}╔{'═' * 68}╗")
        output.append(f"║{' '*25}WIFI SCAN RESULTS{' '*25}║")
        output.append(f"╚{'═' * 68}╝{Style.RESET_ALL}\n")
        
        for i, network in enumerate(networks, 1):
            security = ', '.join(network['encryption']) if network['encryption'] else 'None'
            output.append(f"{Fore.BLUE}[{i}]{Style.RESET_ALL} {network['ssid']}")
            output.append(f"   Signal: {network['signal']} ({network['quality']})")
            output.append(f"   Security: {security}\n")

    return '\n'.join(output)

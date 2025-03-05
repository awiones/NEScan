from colorama import Fore, Style

def get_hint(error_type: str) -> str:
    """Return formatted usage hint based on error type"""
    hints = {
        'rtsp_no_target': f"""
{Fore.YELLOW}RTSP scan requires a target. Use:
{Fore.CYAN}python NEScan.py --rtsp-scan --target <IP/HOSTNAME> {Fore.GREEN}[options]
{Fore.YELLOW}Example:
{Fore.CYAN}python NEScan.py --rtsp-scan --target 192.168.1.100 --rtsp-port 554{Style.RESET_ALL}
        """,
        
        'no_target': f"""
{Fore.YELLOW}A target is required. Use:
{Fore.CYAN}python NEScan.py --target <IP/HOSTNAME/NETWORK> {Fore.GREEN}[options]
{Fore.YELLOW}Examples:
{Fore.CYAN}python NEScan.py --target 192.168.1.100
python NEScan.py --target example.com
python NEScan.py --target 192.168.1.0/24{Style.RESET_ALL}
        """,
        
        'invalid_port': f"""
{Fore.YELLOW}Invalid port specified. Port must be between 1-65535. Use:
{Fore.CYAN}python NEScan.py --target <IP> --rtsp-port <PORT>
{Fore.YELLOW}Example:
{Fore.CYAN}python NEScan.py --target 192.168.1.100 --rtsp-port 554{Style.RESET_ALL}
        """,
        
        'api_key_format': f"""
{Fore.YELLOW}Invalid API key format. Use:
{Fore.CYAN}python NEScan.py --target <IP> --api-vulners <KEY> --api-nvd <KEY>
{Fore.YELLOW}Example:
{Fore.CYAN}python NEScan.py --target example.com --api-vulners YOUR-KEY --api-nvd YOUR-KEY{Style.RESET_ALL}
        """,
        
        'wifi_sudo': f"""
{Fore.YELLOW}WiFi scanning requires root privileges. Use:
{Fore.CYAN}sudo python3 NEScan.py --wifiscan
{Fore.YELLOW}or for specific SSID:
{Fore.CYAN}sudo python3 NEScan.py --wt <SSID>{Style.RESET_ALL}
        """,
        
        'invalid_range': f"""
{Fore.YELLOW}Invalid IP range format. Use CIDR notation:
{Fore.CYAN}python NEScan.py --target <NETWORK>/<MASK>
{Fore.YELLOW}Examples:
{Fore.CYAN}python NEScan.py --target 192.168.1.0/24
python NEScan.py --target 10.0.0.0/16{Style.RESET_ALL}
        """,
        
        'general': f"""
{Fore.YELLOW}For complete usage information, use:
{Fore.CYAN}python NEScan.py --help

{Fore.YELLOW}Common usage patterns:
{Fore.CYAN}1. Basic scan:      python NEScan.py --target <IP/DOMAIN>
2. TCP only:        python NEScan.py --target <IP/DOMAIN> --tcp
3. RTSP scan:       python NEScan.py --target <IP/DOMAIN> --rtsp-scan
4. WiFi scan:       sudo python3 NEScan.py --wifiscan
5. Network range:   python NEScan.py --target 192.168.1.0/24{Style.RESET_ALL}
        """,
        
        'missing_dependencies': f"""
{Fore.YELLOW}Optional dependencies not found. To enable full functionality, install:
{Fore.CYAN}pip install vulners shodan dnspython python-whois
{Fore.YELLOW}Additional system dependencies may be required:
{Fore.CYAN}sudo apt-get install nmap wireless-tools{Style.RESET_ALL}
        """,
        
        'invalid_domain': f"""
{Fore.YELLOW}Invalid domain format. Use:
{Fore.CYAN}python NEScan.py --target example.com
{Fore.YELLOW}Example:
{Fore.CYAN}python NEScan.py --target google.com{Style.RESET_ALL}
        """,
        
        'invalid_ip': f"""
{Fore.YELLOW}Invalid IP address format. Use:
{Fore.CYAN}python NEScan.py --target <IP>
{Fore.YELLOW}Example:
{Fore.CYAN}python NEScan.py --target 192.168.1.100{Style.RESET_ALL}
        """,

        'scan_interrupted': f"""
{Fore.YELLOW}Scan interrupted by user.
{Fore.CYAN}To resume scanning, use the same command:
{Fore.GREEN}Last used command will be shown here{Style.RESET_ALL}
        """,
        
        'rate_limit_exceeded': f"""
{Fore.YELLOW}Rate limit exceeded. Consider:
{Fore.CYAN}1. Decreasing scan rate:    --rate-limit-global <number>
2. Increasing timeout:     --timeout <seconds>
3. Reducing target range:  Scan fewer hosts/ports{Style.RESET_ALL}
        """,

        'ssl_error': f"""
{Fore.YELLOW}SSL/TLS connection failed. Try:
{Fore.CYAN}1. Check target SSL/TLS configuration
2. Use --no-verify-ssl to bypass certificate verification
3. Ensure up-to-date CA certificates{Style.RESET_ALL}
        """,
        
        'dns_error': f"""
{Fore.YELLOW}DNS resolution failed. Check:
{Fore.CYAN}1. Domain name spelling
2. DNS server configuration
3. Network connectivity
4. Try using IP address directly{Style.RESET_ALL}
        """,

        'permission_error': f"""
{Fore.YELLOW}Permission denied. The scan requires:
{Fore.CYAN}1. Root/Administrator privileges
2. Proper file permissions
3. Required system capabilities
{Fore.YELLOW}Try running with sudo:{Style.RESET_ALL}
{Fore.CYAN}sudo python3 NEScan.py [options]{Style.RESET_ALL}
        """
    }
    
    return hints.get(error_type, hints['general'])

def print_hint(error_type: str, additional_info: str = None) -> None:
    """Print a formatted usage hint"""
    print(f"\n{Fore.RED}[!] Usage Error: {Style.RESET_ALL}")
    if additional_info:
        print(f"{Fore.RED}{additional_info}{Style.RESET_ALL}")
    print(get_hint(error_type))

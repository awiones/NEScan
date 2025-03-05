from colorama import Fore, Style

def format_scan_error(error_msg: str) -> str:
    """Format scan error message"""
    return f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}\n"

def format_scan_success(results: dict) -> str:
    """Format successful scan results"""
    output = []
    
    # Basic information section
    output.append(f"\n{Fore.YELLOW}Target Information:{Style.RESET_ALL}")
    output.append(f"• IP Address: {results.get('ip', 'N/A')}")
    output.append(f"• Domain: {results.get('domain', 'N/A')}")
    output.append(f"• Scan Time: {results.get('timestamp', 'N/A')}")
    output.append(f"• Scan Type: {', '.join(results.get('scan_type', ['Unknown']))}")

    # Port scan results section
    if 'open_ports' in results:
        output.append(f"\n{Fore.YELLOW}[*] PORT SCAN RESULTS:{Style.RESET_ALL}")
        
        # TCP ports
        if 'tcp' in results['open_ports'] and results['open_ports']['tcp']:
            output.append(f"\n{Fore.BLUE}TCP Open Ports:{Style.RESET_ALL}")
            for port, service in results['open_ports']['tcp']:
                if service and service != "unknown":
                    output.append(f"• Port {port}/tcp - {service}")
                else:
                    output.append(f"• Port {port}/tcp")
        
        # UDP ports
        if 'udp' in results['open_ports'] and results['open_ports']['udp']:
            output.append(f"\n{Fore.BLUE}UDP Open Ports:{Style.RESET_ALL}")
            for port, service in results['open_ports']['udp']:
                if service and service != "unknown":
                    output.append(f"• Port {port}/udp - {service}")
                else:
                    output.append(f"• Port {port}/udp")
        
        # If no open ports found
        if (not results['open_ports'].get('tcp') and 
            not results['open_ports'].get('udp')):
            output.append(f"{Fore.GREEN}No open ports found{Style.RESET_ALL}")

    # Vulnerability results section
    if 'vulnerabilities' in results:
        output.append(f"\n{Fore.YELLOW}[*] VULNERABILITY SCAN RESULTS:{Style.RESET_ALL}")
        vulns = results['vulnerabilities']
        
        if vulns.get('findings'):
            output.append(f"\n{Fore.RED}Found Vulnerabilities:{Style.RESET_ALL}")
            for vuln in vulns['findings']:
                cvss_color = (Fore.RED if vuln.get('cvss', 0) >= 7.0 else 
                            Fore.YELLOW if vuln.get('cvss', 0) >= 4.0 else 
                            Fore.GREEN)
                
                output.append(f"\n• {Fore.CYAN}CVE:{Style.RESET_ALL} {vuln.get('cve_id')}")
                output.append(f"  {Fore.CYAN}CVSS:{Style.RESET_ALL} {cvss_color}{vuln.get('cvss', 'N/A')}{Style.RESET_ALL}")
                output.append(f"  {Fore.CYAN}Description:{Style.RESET_ALL} {vuln.get('description', 'N/A')}")
                
                if vuln.get('exploit_available'):
                    output.append(f"  {Fore.RED}⚠ Exploit Available{Style.RESET_ALL}")
            
            # Add summary
            output.append(f"\n{Fore.YELLOW}Summary:{Style.RESET_ALL}")
            output.append(f"• Total Vulnerabilities: {vulns['summary']['total']}")
            output.append(f"• Critical: {Fore.RED}{vulns['summary']['critical']}{Style.RESET_ALL}")
            output.append(f"• High: {Fore.RED}{vulns['summary']['high']}{Style.RESET_ALL}")
            output.append(f"• Medium: {Fore.YELLOW}{vulns['summary']['medium']}{Style.RESET_ALL}")
            output.append(f"• Low: {Fore.GREEN}{vulns['summary']['low']}{Style.RESET_ALL}")
        else:
            output.append(f"{Fore.GREEN}No vulnerabilities found{Style.RESET_ALL}")

    return '\n'.join(output)

def format_save_confirmation(report_file: str, scan_dir: str) -> str:
    """Format save confirmation message"""
    return f"\n{Fore.GREEN}[+] Results saved:{Style.RESET_ALL}\n" \
           f"    Report: {report_file}\n" \
           f"    Details: {scan_dir}"

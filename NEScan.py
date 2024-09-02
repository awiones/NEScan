import socket
import subprocess
import ssl
import os
import dns.resolver
import whois
import requests
import nmap
from colorama import Fore, Back, Style, init
import time
import sys


# Initialize colorama
init(autoreset=True)

# Configuration
REPO_OWNER = 'awiones'
REPO_NAME = 'NEScan'
REPO_API_URL = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest'
LOCAL_VERSION_FILE = 'version.txt'

def get_latest_version():
    try:
        response = requests.get(REPO_API_URL)
        response.raise_for_status()
        release_data = response.json()
        return release_data['tag_name']
    except requests.RequestException as e:
        print(f"Error fetching release data: {e}")
        return None

def get_local_version():
    try:
        with open(LOCAL_VERSION_FILE, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        return None

def update_local_version(version):
    with open(LOCAL_VERSION_FILE, 'w') as file:
        file.write(version)

def main():
    latest_version = get_latest_version()
    if latest_version:
        local_version = get_local_version()
        if local_version != latest_version:
            print(f"Updating local version from {local_version} to {latest_version}")
            update_local_version(latest_version)
        else:
            print("Local version is up to date.")
    else:
        print("Could not fetch the latest version.")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print(Fore.CYAN + "="*69)
    print(Fore.CYAN + "███▄▄▄▄      ▄████████    ▄████████  ▄████████    ▄████████ ███▄▄▄▄   ")
    print(Fore.CYAN + "███▀▀▀██▄   ███    ███   ███    ███ ███    ███   ███    ███ ███▀▀▀██▄ ")
    print(Fore.CYAN + "███   ███   ███    █▀    ███    █▀  ███    █▀    ███    ███ ███   ███ ")
    print(Fore.CYAN + "███   ███  ▄███▄▄▄       ███        ███          ███    ███ ███   ███ ")
    print(Fore.CYAN + "███   ███ ▀▀███▀▀▀     ▀███████████ ███        ▀███████████ ███   ███ ")
    print(Fore.CYAN + "███   ███   ███    █▄           ███ ███    █▄    ███    ███ ███   ███ ")
    print(Fore.CYAN + "███   ███   ███    ███    ▄█    ███ ███    ███   ███    ███ ███   ███ ")
    print(Fore.CYAN + " ▀█   █▀    ██████████  ▄████████▀  ████████▀    ███    █▀   ▀█   █▀  ")
    print(Fore.CYAN + "="*69 + Style.RESET_ALL)

def animate_spinner(duration):
    spinner = ['|', '/', '-', '\\']
    start_time = time.time()
    while time.time() - start_time < duration:
        for symbol in spinner:
            sys.stdout.write(f'\r{Fore.YELLOW}{symbol} Processing...')
            sys.stdout.flush()
            time.sleep(0.1)

def get_ip_from_website(website):
    try:
        ip = socket.gethostbyname(website)
        return ip
    except socket.error as e:
        print(Fore.RED + f"Error resolving IP for {website}: {e}" + Style.RESET_ALL)
        return None

def scan_ports(ip):
    open_ports = []
    nm = nmap.PortScanner()
    print(Fore.YELLOW + "\nScanning ports..." + Style.RESET_ALL)
    animate_spinner(10)  # Simulate processing time
    nm.scan(ip, arguments='-p- -T4')  # Scan all 65535 ports
    print(Fore.YELLOW + "="*50 + Style.RESET_ALL)
    
    for port in nm[ip]['tcp']:
        state = nm[ip]['tcp'][port].get('state', 'closed')
        if state == 'open':
            service = nm[ip]['tcp'][port].get('name', 'Unknown')
            open_ports.append((port, service))
    
    return open_ports

def fetch_ip_details(ip):
    try:
        print(Fore.WHITE + f"\nFetching details for IP {ip}..." + Style.RESET_ALL)
        result = subprocess.run(['curl', '-I', ip], capture_output=True, text=True)
        if result.returncode == 0:
            print(Fore.GREEN + f"\nCurl output:\n{result.stdout}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "You can't go there..." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error fetching details for IP {ip}: {e}" + Style.RESET_ALL)

def fetch_certificate_info(ip):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                print(Fore.WHITE + f"\nCertificate details for {ip}:\n{cert}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error fetching certificate info for IP {ip}: {e}" + Style.RESET_ALL)

def fetch_dns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        print(Fore.WHITE + f"\nDNS Records for {domain}:" + Style.RESET_ALL)
        for rdata in answers:
            print(Fore.WHITE + f" - {rdata.address}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error fetching DNS records for {domain}: {e}" + Style.RESET_ALL)

def fetch_reverse_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        print(Fore.WHITE + f"\nReverse DNS for {ip}:\n{hostname}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error fetching reverse DNS for {ip}: {e}" + Style.RESET_ALL)

def fetch_whois_info(domain):
    try:
        w = whois.whois(domain)
        print(Fore.WHITE + f"\nWhois information for {domain}:" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Domain Name: {w.domain_name}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Registrar: {w.registrar}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Creation Date: {w.creation_date}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Expiration Date: {w.expiration_date}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Name Servers: {w.name_servers}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error fetching Whois info for {domain}: {e}" + Style.RESET_ALL)

def fetch_ip_geolocation(ip):
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        data = response.json()
        print(Fore.WHITE + f"\nGeolocation for {ip}:" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Country: {data.get('country')}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Region: {data.get('region')}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - City: {data.get('city')}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Location: {data.get('loc')}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Organization: {data.get('org')}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error fetching geolocation for {ip}: {e}" + Style.RESET_ALL)

def analyze_http_response(ip):
    try:
        response = requests.get(f'http://{ip}')
        print(Fore.WHITE + f"\nFull HTTP Response for {ip}:" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Status Code: {response.status_code}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Headers: {response.headers}" + Style.RESET_ALL)
        print(Fore.WHITE + f" - Content (truncated): {response.text[:500]}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error fetching HTTP response for {ip}: {e}" + Style.RESET_ALL)

def main():
    while True:
        print_header()
        website = input(Fore.CYAN + "Enter the website to scan (e.g., example.com): " + Style.RESET_ALL)
        ip = get_ip_from_website(website)
        
        if ip:
            print(Fore.WHITE + f"\nIP Address of {website}: {ip}" + Style.RESET_ALL)
            fetch_ip_details(ip)
            fetch_certificate_info(ip)
            fetch_dns_records(website)
            fetch_reverse_dns(ip)
            fetch_whois_info(website)
            fetch_ip_geolocation(ip)
            analyze_http_response(ip)
            
            open_ports = scan_ports(ip)
            if open_ports:
                print(Fore.GREEN + f"\nOpen ports:" + Style.RESET_ALL)
                for port, service in open_ports:
                    print(Fore.GREEN + f" - Port {port} is open - Service: {service}" + Style.RESET_ALL)
            else:
                print(Fore.RED + "No open ports found." + Style.RESET_ALL)
        else:
            print(Fore.RED + "Unable to retrieve IP address." + Style.RESET_ALL)
        
        cont = input(Fore.CYAN + "Do you want to scan another website? (yes/no): " + Style.RESET_ALL)
        if cont.lower() != 'yes':
            break

if __name__ == "__main__":
    main()

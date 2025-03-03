import argparse
import time
from vulners import VulnersApi
from colorama import Fore, Style, init

def run_test(client, test_name, test_func):
    start_time = time.time()
    try:
        result = test_func()
        duration = round(time.time() - start_time, 2)
        print(f"{Fore.GREEN}[✓] {test_name} - Completed in {duration}s{Style.RESET_ALL}")
        return True, result
    except Exception as e:
        print(f"{Fore.RED}[✗] {test_name} failed: {str(e)}{Style.RESET_ALL}")
        return False, None

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Test Vulners API connectivity and functionality')
    parser.add_argument('--api', required=True, help='Vulners API key')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    # Initialize colorama
    init(autoreset=True)

    print(f"{Fore.BLUE}[*] Starting Vulners API tests...{Style.RESET_ALL}")
    
    try:
        client = VulnersApi(api_key=args.api)
        tests_passed = 0
        total_tests = 4

        # Test 1: Basic connectivity test with exploit search
        success, exploits = run_test(client, "Basic Exploit Search", 
            lambda: client.find_exploit("apache"))
        if success and args.verbose:
            print(f"  └─ Found {len(exploits)} apache-related exploits")
        tests_passed += 1 if success else 0

        # Test 2: CVE search
        success, cve_results = run_test(client, "CVE Search Test", 
            lambda: client.find_exploit("CVE-2021-44228"))
        if success and args.verbose:
            print(f"  └─ Found {len(cve_results)} exploits for CVE-2021-44228")
        tests_passed += 1 if success else 0

        # Test 3: Bulletin search
        success, bulletins = run_test(client, "Bulletin Search Test", 
            lambda: client.find_exploit_all("type:exploit"))
        if success and args.verbose:
            print(f"  └─ Found {len(bulletins)} security bulletins")
        tests_passed += 1 if success else 0

        # Test 4: Search with specific parameters
        success, advanced_search = run_test(client, "Advanced Search Test", 
            lambda: client.find_exploit_all("type:exploit AND published:[2023-01-01 TO *]"))
        if success and args.verbose:
            print(f"  └─ Found {len(advanced_search)} results in advanced search")
        tests_passed += 1 if success else 0

        # Final summary
        print("\n" + "="*50)
        if tests_passed == total_tests:
            print(f"{Fore.GREEN}[✓] All tests passed successfully! ({tests_passed}/{total_tests}){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] {tests_passed}/{total_tests} tests passed{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Critical error: {str(e)}{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    main()
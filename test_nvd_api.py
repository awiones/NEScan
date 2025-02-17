import argparse
import requests
import time
from colorama import Fore, Style, init

def run_test(test_name, test_func):
    start_time = time.time()
    try:
        result = test_func()
        duration = round(time.time() - start_time, 2)
        print(f"{Fore.GREEN}[✓] {test_name} - Completed in {duration}s{Style.RESET_ALL}")
        return True, result
    except Exception as e:
        print(f"{Fore.RED}[✗] {test_name} failed: {str(e)}{Style.RESET_ALL}")
        return False, None

def test_nvd_api(api_key: str, verbose: bool = False):
    headers = {
        'apiKey': api_key,
        'Content-Type': 'application/json'
    }
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    tests_passed = 0
    total_tests = 4

    # Test 1: Basic connectivity test
    success, response = run_test("Basic Connectivity Test", 
        lambda: requests.get(base_url, params={'resultsPerPage': 1}, headers=headers))
    if success and verbose:
        print(f"  └─ API response status: {response.status_code}")
    tests_passed += 1 if success else 0

    # Test 2: Search for specific CVE
    success, cve_response = run_test("CVE Search Test", 
        lambda: requests.get(
            base_url,
            params={'cveId': 'CVE-2021-44228'},
            headers=headers
        ))
    if success and verbose and cve_response.json().get('vulnerabilities'):
        print(f"  └─ Found CVE details: {cve_response.json()['vulnerabilities'][0]['cve']['id']}")
    tests_passed += 1 if success else 0

    # Test 3: Keyword search
    success, keyword_response = run_test("Keyword Search Test", 
        lambda: requests.get(
            base_url,
            params={'keywordSearch': 'apache', 'resultsPerPage': 10},
            headers=headers
        ))
    if success and verbose:
        total = keyword_response.json().get('totalResults', 0)
        print(f"  └─ Found {total} results for 'apache'")
    tests_passed += 1 if success else 0

    # Test 4: Advanced search with multiple parameters
    success, advanced_response = run_test("Advanced Search Test", 
        lambda: requests.get(
            base_url,
            params={
                'keywordSearch': 'remote code execution',
                'cvssV3Severity': 'HIGH',
                'resultsPerPage': 10
            },
            headers=headers
        ))
    if success and verbose:
        total = advanced_response.json().get('totalResults', 0)
        print(f"  └─ Found {total} high severity RCE vulnerabilities")
    tests_passed += 1 if success else 0

    # Final summary
    print("\n" + "="*50)
    if tests_passed == total_tests:
        print(f"{Fore.GREEN}[✓] All tests passed successfully! ({tests_passed}/{total_tests}){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] {tests_passed}/{total_tests} tests passed{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Test NVD API connectivity and functionality')
    parser.add_argument('--api', required=True, help='NVD API key')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    # Initialize colorama
    init(autoreset=True)

    print(f"{Fore.BLUE}[*] Starting NVD API tests...{Style.RESET_ALL}")
    
    try:
        test_nvd_api(args.api, args.verbose)
    except Exception as e:
        print(f"{Fore.RED}[!] Critical error: {str(e)}{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    main()

**Features of Version V1.0.0**

1. **Version Management:**
   - Checks the latest release version from GitHub API.
   - Compares local and remote versions, updating the local version file if there's a mismatch.

2. **Interactive Interface:**
   - Displays a styled ASCII art header using Colorama.
   - Clears the terminal screen for a clean look.
   - Animates a spinner during processing.

3. **IP and Website Scanning:**
   - Resolves the IP address of a given website.
   - Fetches HTTP response headers and truncated content.
   - Analyzes open ports on the resolved IP using Nmap.
   - Retrieves SSL certificate details for the IP.
   - Provides DNS records (A record) of the domain.

4. **Geolocation and WHOIS Information:**
   - Fetches geolocation data (country, region, city, coordinates, and organization) using the ipinfo.io API.
   - Extracts WHOIS information, including registrar, creation/expiration date, and name servers.

5. **Reverse DNS Lookup:**
   - Retrieves reverse DNS entries for the resolved IP.

6. **Error Handling:**
   - Prints detailed error messages for any failure in API calls, DNS lookups, or scanning tasks.

7. **Port Scanning:**
   - Uses Nmap to scan all 65535 ports on the target IP and lists open ports along with their associated services.

8. **HTTP Response Analysis:**
   - Retrieves and displays the full HTTP response details, including status code and headers.

9. **Custom Terminal Coloring:**
   - Uses Colorama to display information in a visually appealing manner with colors for success, errors, and general output.

10. **End-User Experience:**
    - Asks the user for further scans or to exit the program after completing a scan.

---

**New Features and Changes in Version V1.5**

1. **Enhancements (+):**
   - **Multithreading Support:** Added `concurrent.futures.ThreadPoolExecutor` to enable concurrent port scanning, improving efficiency for large port ranges.
   - **Custom Directory for Results:** Automatically creates organized directories (`results/scans`, `results/logs`, `results/reports`) to store logs, scans, and reports.
   - **Improved Logging:** Integrated `logging` to capture detailed logs of scanning activities, stored in timestamped log files.
   - **Domain Validation:** Added validation for domain names using the `validators` library.
   - **TQDM Progress Bars:** Implemented `tqdm` for real-time progress indication during port scans and domain information fetching.
   - **Enhanced Port Scanning:** 
     - Scans a configurable range of ports (default: 1–1000) alongside common high-risk ports.
     - Added service banner grabbing for identified open ports.
     - Categorizes ports by risk level (HIGH, MEDIUM, LOW).
   - **SSL Analysis Improvements:** Uses OpenSSL for SSL certificate parsing, providing detailed issuer and expiration information.
   - **Report Generation:** Generates detailed scan reports with sections for scan statistics, open ports, DNS records, and security analysis. Includes risk scoring.
   - **Security Analysis:** Added a feature to identify security issues (e.g., missing HSTS headers, high-risk open ports) and categorize them by severity.
   - **Recommendations Section:** Provides actionable recommendations based on scan results and detected security issues.
   - **Improved DNS Record Retrieval:** Supports multiple DNS record types (A, MX, NS, TXT).
   - **Data Serialization:** Saves raw scan results in JSON format for further analysis.

2. **Nerfs (-):**
   - Removed full port range scanning (`-p-` with Nmap) as the default; now scans only a defined range or common ports for efficiency and reduced resource usage.

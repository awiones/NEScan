# NEScan Changelog

## Version V1.0.0 Features  
### Features
- **(+) Basic version management** 
- **(+) Styled ASCII header and spinner animation**  
- **(+) IP resolution and full port scanning**  
- **(+) Fetching DNS, SSL, HTTP response, and WHOIS details**  
- **(+) Reverse DNS lookup**  
- **(+) Error handling for failed tasks**  
- **(+) Full port scanning (all 65,535 ports)**  

---

## Version V1.5 Updates  

### Features
- **(+) Multithreading for faster scans**
  - Reduces scan time by processing multiple ports simultaneously.  
- **(+) Organized results into directories**
  - Keeps logs, reports, and scans neatly separated for better usability.  
- **(+) Added detailed logging**
  - Provides a comprehensive record of scan activities and errors.  
- **(+) Domain validation with `validators` library**
  - Prevents invalid domain inputs.  
- **(+) Real-time progress bars**
  - Enhances the user experience with clear feedback on task completion.  
- **(+) Risk-level categorization for open ports**
  - Highlights risky open ports like RDP (3389) or FTP (21) for immediate attention.  
- **(+) Enhanced SSL analysis using OpenSSL**
  - Identifies SSL-related vulnerabilities, like expired certificates.  
- **(+) Generates detailed reports with risk scoring**
  - Summarizes findings and ranks risks for better decision-making.  
- **(+) Identifies security issues and recommends fixes**
  - Provides actionable advice for mitigating detected risks.  
- **(+) Supports multiple DNS record types (A, MX, NS, TXT)**
  - Offers a deeper understanding of a domain's configuration.  
- **(+) Saves results in JSON format**
  - Allows integration with other tools or further automation.  

### Nerfs
- **(-) Default port scan reduced to 1–1000 and common ports**
  - Targets the most relevant ports while saving time and resources.  

## Version V2.0 Updates

### Features
- **(+) Added rate limiter using token bucket algorithm for global and per-host rate limiting.**\
  Prevents overwhelming target systems and ensures fair resource usage,  
  especially during high-volume scanning.

- **(+) Integrated command-line argument parsing with argparse for improved usability.**\
  Simplifies input handling by allowing users to specify targets and options  
  directly via the command line.

- **(+) Added User-Agent rotation support via UserAgentManager.**\
  Helps avoid detection and potential blocking by rotating User-Agent strings  
  in outgoing requests.

- **(+) Enhanced UDP port scanning with new probes, response patterns, and common UDP ports scanning.**\
  Improves the accuracy of UDP scans by using specialized probes and patterns  
  to reliably detect open UDP ports.

- **(+) Extended TCP scanning with improved service detection using assets.tcp_ports.**\
  Provides more precise identification of TCP services, ensuring better  
  vulnerability assessment.

- **(+) Introduced network range scanning support (CIDR) using the ipaddress module.**\
  Enables scanning of entire networks or subnets, increasing the tool's  
  versatility for large-scale assessments.

- **(+) Integrated multi-source vulnerability scanning (Vulners, NVD, Shodan) with vulnerability correlation.**\
  Aggregates vulnerability data from multiple sources to offer a comprehensive  
  security analysis and better risk insight.

- **(+) Improved result saving and reporting with enhanced JSON output and formatted reports.**\
  Delivers structured and easily shareable scan results for further analysis  
  and reporting.

- **(+) Added API integrations for Vulners and NVD to check for CVE vulnerabilities.**\
  Automatically retrieves known vulnerabilities, providing actionable information  
  to address potential security issues.

  **API Integration Tutorial (Vulners):**

  1. Go to [vulners.com](https://vulners.com/) and log in.
  2. Navigate to your profile and click on the **API Keys** tab, or visit [https://vulners.com/userinfo?tab=api-keys](https://vulners.com/userinfo?tab=api-keys).
  3. Create a new API key with the following settings:
     - **API Name:** Enter any name you prefer.
     - **Scope:** Set to `api` (only API access).
     - **License:** Choose `free` (or your paid option if applicable).
     - **Bound IP:** Leave this field empty (recommended).
  4. Copy your new API key and add it when you are about to scan a website/IP using the command `--api-vulners YOUR-API`.

  **API Integration Tutorial (NVD):**

  1. Visit the NVD API request page at [NVD API Request](https://nvd.nist.gov/developers/request-an-api-key).
  2. Fill in your organization name, email, and a brief description of your intended purpose.
  3. Submit the form to obtain your API key.
  4. Copy your new API key and add it when running your scan using the command `--api-nvd YOUR-API_KEY`.

- **(+) Improved TCP scanning functionality.**\
  Enhances scan reliability and speed by refining the TCP service detection methods.

- **(+) Added UDP scan capability.**\
  Broadens the scanner's coverage to include UDP protocols, ensuring a more  
  comprehensive network assessment.

- **(+) Changed message handling: replaced one-by-one input with a custom command format (e.g., python NEScam.py -t example.com).**\
  Streamlines the user experience by enabling direct command-line input  
  for faster and more efficient scanning.

- **(+) Added rate-limiting controls.**\
  Manages request frequency to minimize false positives and reduce the load  
  on target systems.

### Nerfs

- **(-) Increased scanning overhead due to additional modules and rate limiting may slow down scans in low-latency environments.**\
  Although these improvements enhance functionality and reliability,  
  they introduce a trade-off in performance under certain conditions.

## Version V2.1 Updates

### Features
- **(+) New RTSP Scanner**
  - Analyzes surveillance camera streams
  - Tests 100+ default credentials
  - Generates authentication-ready URLs
  - Supports major CCTV brands

- **(+) WiFi Network Scanner**
  - Commands: `--wifiscan` (full scan), `--wt <SSID>` (targeted)
  - Detects:
    - Signal strength & channels
    - WEP/WPA/WPA2/WPA3 security
    - Hidden networks
  - Security features:
    - Encryption analysis
    - Risk assessment
    - Vulnerability checks
  - Multi-platform:
    - Linux, WSL, macOS support
    - Real-time monitoring
    - Detailed statistics

- **(+) Enhanced Port Scanner**
  - Faster parallel scanning
  - Better service detection
  - Improved UDP verification
  - Memory optimization
  - Rate limiting
  - Result caching
  - Reduced false positives

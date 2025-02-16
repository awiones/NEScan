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

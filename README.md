# NEScan (Network Scanner)

<p align="center">
<img src="./logo.png" width="300px">
</p> 


This repository contains a Python tool designed for comprehensive network scanning and analysis. The Network Scanner performs various tasks to gather information about websites and IP addresses, including DNS resolution, port scanning, SSL certificate fetching, Whois data retrieval, and more.


## Features

- **DNS Records**: Fetch DNS A records for a given domain.
- **Reverse DNS Lookup**: Retrieve the hostname associated with an IP address.
- **Port Scanning**: Scan all ports of an IP address to identify open ports and associated services.
- **IP Details**: Fetch IP details using `curl`.
- **SSL Certificate Information**: Retrieve SSL certificate details for a given IP.
- **Whois Information**: Retrieve Whois data for a domain.
- **Geolocation**: Get geolocation data for an IP address.
- **HTTP Response Analysis**: Analyze HTTP response headers and content from a given IP.
- **Animated Spinner**: Show a spinner animation during processing.

## Installation

  ```bash
  git clone https://github.com/awiones/Network-Scanner.git
  cd Network-Scanner
  pip install -r requirements.txt
  python3 network_scanner.py
  ```
If you got error you might need to upgrade this
  
  ```bash
  pip install --upgrade pyOpenSSL cryptography
  pip install --upgrade dns aioquic
  ```

## Additional Information

- **Privacy and Security**: This tool is designed for ethical use. Ensure you have permission to scan and analyze the websites and IP addresses you target. Unauthorized scanning can be illegal and unethical.

- **Limitations**: The accuracy of the results may vary depending on the availability and response of the services queried. For example, DNS lookups and Whois data may not always be up-to-date or complete.

- **Customization**: You can customize the tool by modifying the script to fit specific needs or integrate additional features. The code is designed to be modular and easy to extend.

- **Troubleshooting**: If you encounter issues, ensure all dependencies are installed correctly and that `nmap` is properly configured. Check the script for any specific error messages and consult relevant documentation for troubleshooting.

## Contributing

Contributions are welcome! If you have suggestions, improvements, or bug fixes, please submit a pull request or open an issue.

- **Fork the Repository**: Create a personal copy of the repository on GitHub.
- **Make Changes**: Implement your changes and test them locally.
- **Submit a Pull Request**: Describe your changes and submit a pull request for review.

## License

This project is licensed under the GPL 3.0 License. See the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by Awiones

# NEScan

<div align="center">
  <img src="https://github.com/awiones/NEScan/blob/main/assets/img/logo1.jpg" alt="NEScan Banner" width="400px">
</div>

<div align="center">
  
  [![GitHub stars](https://img.shields.io/github/stars/awiones/NEScan?style=social)](https://github.com/awiones/NEScan/stargazers)
  [![GitHub watchers](https://img.shields.io/github/watchers/awiones/NEScan?style=social)](https://github.com/awiones/NEScan/watchers)
  [![GitHub forks](https://img.shields.io/github/forks/awiones/NEScan?style=social)](https://github.com/awiones/NEScan/network/members)
  [![GitHub issues](https://img.shields.io/github/issues/awiones/NEScan)](https://github.com/awiones/NEScan/issues)
  [![GitHub pull requests](https://img.shields.io/github/issues-pr/awiones/NEScan)](https://github.com/awiones/NEScan/pulls)
  
</div>

<div align="center">
  
  [![GitHub license](https://img.shields.io/github/license/awiones/NEScan)](https://github.com/awiones/NEScan/blob/main/LICENSE)
  [![GitHub last commit](https://img.shields.io/github/last-commit/awiones/NEScan)](https://github.com/awiones/NEScan/commits/main)
  [![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/awiones/NEScan/actions)
  [![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-blue)](#)
  
</div>

---

NEScan is a lightweight and efficient network scanner designed to identify devices and analyze vulnerabilities across a network. It is suitable for professionals and hobbyists looking to monitor and secure their networks.

## Features
- **Fast and Accurate Scanning**: Quickly identify all active devices in the network.
- **Port Scanning**: Detect open ports and associated services.
- **Vulnerability Detection**: Identify common security vulnerabilities.

## Installation
To get started with NEScan, follow these steps:

```bash
# Clone the repository
git clone https://github.com/awiones/NEScan.git

# Navigate to the directory
cd NEScan

# Install dependencies
pip install -r requirements.txt
```

## Usage
Here are some basic examples of how to use NEScan:

```bash
# Scan a specific IP address
python NEScan.py --target 192.168.1.1

# Scan an entire subnet
python NEScan.py --target 192.168.1.0/24

# Export results to a file
python NEScan.py --target 192.168.1.0/24 --output results.json

# Enable verbose mode for detailed logs
python NEScan.py --target 192.168.1.0/24 --verbose
```

## Don't know how to use the API?
Check out the discussion: [How to Add API on NEScan](https://github.com/awiones/NEScan/discussions/2).

## Screenshot
<div align="center">
  <img src="https://github.com/awiones/NEScan/blob/main/assets/img/screenshoot.PNG" alt="NEScan Screenshot" width="800px">
</div>

## Contributing
We welcome contributions! Please check the [CONTRIBUTING.md](https://github.com/awiones/NEScan/blob/main/CONTRIBUTING.md) for guidelines.

To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and submit a pull request.

## License
This project is licensed under the [GNU V3.0 License](https://github.com/awiones/NEScan/blob/main/LICENSE).

## Support
If you encounter any issues or have questions, feel free to:
- Open an [issue](https://github.com/awiones/NEScan/issues).
- Reach out via [discussions](https://github.com/awiones/NEScan/discussions).

## Links
- [Repository](https://github.com/awiones/NEScan)
- [Issues](https://github.com/awiones/NEScan/issues)
- [Pull Requests](https://github.com/awiones/NEScan/pulls)
- [Changelog](https://github.com/awiones/NEScan/blob/main/NEScan%20Changelog%20Series.md)
- [Usage](https://github.com/awiones/NEScan/blob/main/usage.md)

---

Maintained with ❤️ by [awiones](https://github.com/awiones).

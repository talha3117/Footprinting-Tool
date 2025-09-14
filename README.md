# FMC (Footprinting Master by CoreBridge)

<div align="center">

```
                    ███████╗███╗   ███╗ ██████╗
                    ██╔════╝████╗ ████║██╔════╝
                    █████╗  ██╔████╔██║██║     
                    ██╔══╝  ██║╚██╔╝██║██║     
                    ██║     ██║ ╚═╝ ██║╚██████╗
                    ╚═╝     ╚═╝     ╚═╝ ╚═════╝
```

**A comprehensive domain investigation tool for cybersecurity professionals by CoreBridge**

*Author: TALHA AHMED*

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.1-orange.svg)]()

</div>

## 🚀 Features

- **📚 Wikipedia Company Information** - Automated company data extraction from Wikipedia
- **🔍 WHOIS & SSL Analysis** - Comprehensive domain registration and certificate information
- **🌐 Shodan Intelligence** - Advanced threat intelligence and vulnerability assessment
- **☁️ CDN Detection** - Multi-method CDN identification and analysis
- **🎯 Multi-Source Subdomain Discovery** - Aggregated subdomain enumeration from multiple sources
- **✅ Active Subdomain Verification** - HTTP probing and live subdomain validation
- **📥 Website Mirroring** - HTTrack integration with headless fallback options
- **🔒 Nmap Stealth Port Scan** - SYN scan (-sS) with service detection and live output

## 📋 Table of Contents

- [Installation](#installation)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Features in Detail](#features-in-detail)
- [Output Files](#output-files)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🛠 Installation

### Prerequisites

- **Python 3.6+** (Recommended: Python 3.8+)
- **Operating System**: Linux, macOS, or Windows with WSL

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/talha3117/Footprinting-Tool.git
   cd Footprinting-Tool
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tool**
   ```bash
   python main_script.py
   ```

## 📦 Dependencies

### Required Python Packages

The tool will automatically check for these dependencies and provide installation instructions if missing:

```bash
pip install requests beautifulsoup4
```

### Optional Tools (Recommended)

For enhanced functionality, install these optional tools:

#### Go-based Tools
```bash
# Assetfinder - Subdomain discovery
go install github.com/tomnomnom/assetfinder@latest

# Httprobe - HTTP probing
go install github.com/tomnomnom/httprobe@latest
```

#### System Tools (Linux/macOS)
```bash
# HTTrack - Website mirroring
sudo apt update && sudo apt install httrack

# Wget - Alternative mirroring
sudo apt update && sudo apt install wget

# Whois - Domain information
sudo apt update && sudo apt install whois

# Nmap - Port scanning
sudo apt update && sudo apt install nmap
```

#### Python Tools
```bash
# Playwright - Headless browser (fallback mirroring)
pip install playwright
python -m playwright install chromium
```

### Windows Installation

For Windows users, you can install most tools using:

1. **Chocolatey** (recommended):
   ```powershell
   choco install nmap whois wget
   ```

2. **Manual installation**:
   - Download Nmap from [nmap.org](https://nmap.org/download.html)
   - Install Go from [golang.org](https://golang.org/dl/)
   - Use WSL for Linux-based tools

## ⚙️ Configuration

### Shodan API Key (Optional but Recommended)

1. **Get a free API key** from [Shodan.io](https://account.shodan.io/)

2. **Set environment variable**:
   ```bash
   # Linux/macOS
   export SHODAN_API_KEY="your_api_key_here"
   
   # Windows
   set SHODAN_API_KEY=your_api_key_here
   ```

3. **Or create a file** (alternative method):
   ```bash
   echo "your_api_key_here" > shodan_api_key.txt
   ```

## 🎯 Usage

### Basic Usage

```bash
python main_script.py
```

The tool will guide you through each phase:

1. **Enter target domain** (e.g., `example.com`)
2. **Wikipedia Information Gathering** - Automatic
3. **WHOIS & SSL Analysis** - Optional
4. **Shodan Intelligence** - Optional (requires API key)
5. **CDN Detection** - Optional
6. **Subdomain Discovery** - Optional
7. **Website Mirroring** - Optional
8. **Nmap Port Scanning** - Optional

### Advanced Usage

```bash
# Run with specific options
python main_script.py

# The tool provides interactive prompts for each phase
# You can skip any phase by answering 'n' to the prompts
```

## 📁 Project Structure

```
fmc-footprinting-master/
├── main_script.py           # Main entry point
├── domain_recon.py          # Core reconnaissance orchestrator
├── info_gatherer.py         # Information gathering modules
├── subdomain_enumerator.py  # Subdomain discovery engines
├── utils_module.py          # Utility functions and helpers
├── shodan_api_key.txt       # Shodan API key (optional)
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

### Module Overview

- **`main_script.py`** - Entry point with banner, dependency checking, and main execution
- **`domain_recon.py`** - Main orchestrator class that coordinates all reconnaissance phases
- **`info_gatherer.py`** - Contains specialized gatherers for Wikipedia, WHOIS, SSL, CDN, Shodan, and Nmap
- **`subdomain_enumerator.py`** - Multiple subdomain discovery sources and website mirroring
- **`utils_module.py`** - Shared utilities for formatting, file management, and user interface

## 🔍 Features in Detail

### 1. Wikipedia Company Information
- Searches Wikipedia for company pages
- Extracts structured data from infoboxes
- Maps company information to standardized fields
- Provides ASN lookup integration

### 2. WHOIS & SSL Analysis
- **IP Resolution** - Domain to IP mapping
- **SSL Certificate Analysis** - Subject, issuer, validity, SANs
- **WHOIS Data** - Registrar, dates, nameservers, contact info
- **Comprehensive Parsing** - Handles multiple WHOIS formats

### 3. Shodan Intelligence
- **Domain Profile** - Subdomains and related domains
- **Host Information** - IPs, hostnames, organization details
- **Port Scanning** - Open ports and services
- **Vulnerability Data** - CVEs and security tags
- **Geographic Data** - Country, city, ISP information

### 4. CDN Detection
- **CNAME Analysis** - DNS record inspection
- **Nameserver Detection** - CDN-specific nameservers
- **HTTP Header Analysis** - CDN-specific headers
- **Multi-Provider Support** - Cloudflare, Akamai, AWS, etc.

### 5. Subdomain Discovery
- **RapidDNS** - DNS enumeration
- **Assetfinder** - Go-based subdomain discovery
- **Crt.sh** - Certificate transparency logs
- **Wayback Machine** - Historical subdomain data
- **HackerTarget** - Additional DNS sources

### 6. Website Mirroring
- **HTTrack Integration** - Full website mirroring
- **Headless Fallback** - Playwright-based alternative
- **Progress Tracking** - Real-time mirroring status
- **Error Handling** - Graceful fallback options

### 7. Nmap Port Scanning
- **Stealth SYN Scan** - `-sS` for stealth
- **Service Detection** - `-sV` for service identification
- **Live Output** - Real-time scan results
- **Fast Mode** - `-F` option for quicker scans

## 📄 Output Files

The tool creates organized output in a timestamped directory:

```
outputs/
└── example.com_2024-01-15_14-30-25/
    ├── Company_Info_example.com.txt      # Wikipedia data
    ├── WHOIS_example.com.txt             # WHOIS & SSL info
    ├── Shodan_example.com.txt            # Shodan intelligence
    ├── CDNs_example.com.txt              # CDN detection results
    ├── subdomains_example.com.txt        # Discovered subdomains
    ├── Active_example.com.txt            # Live subdomains (httprobe)
    ├── scan_example.com.txt              # Nmap scan results
    └── example.com/                      # Mirrored website (if enabled)
```

## 🐛 Troubleshooting

### Common Issues

1. **"nmap not found"**
   ```bash
   # Linux/macOS
   sudo apt install nmap
   
   # Windows
   choco install nmap
   ```

2. **"httprobe not found"**
   ```bash
   go install github.com/tomnomnom/httprobe@latest
   ```

3. **"assetfinder not found"**
   ```bash
   go install github.com/tomnomnom/assetfinder@latest
   ```

4. **"HTTrack not found"**
   ```bash
   sudo apt install httrack
   ```

5. **Shodan API errors**
   - Verify your API key is correct
   - Check your Shodan account credits
   - Ensure the API key is set in environment variables

6. **Permission errors**
   ```bash
   # Make scripts executable
   chmod +x main_script.py
   ```

### Performance Tips

- Use **fast mode** for Nmap scans on large targets
- Skip optional phases if you only need specific information
- Consider using a VPN for sensitive reconnaissance
- Monitor your Shodan API usage to avoid rate limits

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/talha3117/Footprinting-Tool.git

# Install development dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest tests/

# Run linting
python -m flake8 *.py
```

## ⚠️ Legal Disclaimer

This tool is for **educational and authorized testing purposes only**. Users are responsible for:

- Obtaining proper authorization before testing any systems
- Complying with local laws and regulations
- Using the tool ethically and responsibly
- Respecting terms of service of target websites

The authors are not responsible for any misuse of this tool.

## 📞 Support

- **Issues**: https://github.com/talha3117/Footprinting-Tool/issues
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/fmc-footprinting-master/discussions)
- **Email**: talzzz.mza@gmail.com

## 🙏 Acknowledgments

- **Shodan.io** - For providing the intelligence API
- **Wikipedia** - For company information data
- **TomNomNom** - For assetfinder and httprobe tools
- **Nmap Project** - For the powerful port scanner
- **HTTrack** - For website mirroring capabilities

---

<div align="center">

**Made with ❤️ by TALHA AHMED**

*CoreBridge - Empowering Cybersecurity Professionals*

</div>

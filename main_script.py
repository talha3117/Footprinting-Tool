#!/usr/bin/env python3
"""
FMC (Footprinting Master by CoreBridge)
A comprehensive domain investigation tool for cybersecurity professionals.

Author: TALHA AHMED
Version: 2.0
License: MIT

Features:
- Wikipedia company information gathering
- WHOIS and SSL certificate analysis
- CDN detection and analysis
- Multi-source subdomain discovery
- Active subdomain verification
- Website mirroring capabilities

Requirements:
- Python 3.6+
- Required Python packages: requests, beautifulsoup4
- Optional tools: assetfinder, httprobe, httrack
"""

import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from domain_recon import DomainReconnaissanceTool


def print_cb_logo():
    """Print the CoreBridge (CB) ASCII logo."""
    blue = "\033[34m"
    white = "\033[37m"
    reset = "\033[0m"
    
    logo = f"""
{blue}                    ███████╗███╗   ███╗ ██████╗
{blue}                    ██╔════╝████╗ ████║██╔════╝
{blue}                    █████╗  ██╔████╔██║██║     
{blue}                    ██╔══╝  ██║╚██╔╝██║██║     
{blue}                    ██║     ██║ ╚═╝ ██║╚██████╗
{blue}                    ╚═╝     ╚═╝     ╚═╝ ╚═════╝
{reset}
{white}                    Footprinting Master by CoreBridge
{white}                              Author: TALHA AHMED
{reset}
"""
    print(logo)


def print_banner():
    """Print the tool banner with ANSI colors."""
    red = "\033[31m"
    yellow = "\033[33m"
    reset = "\033[0m"
    inner_width = 66
    top = f"{yellow}╔" + "═" * inner_width + f"╗{reset}"
    sep = f"{yellow}╠" + "═" * inner_width + f"╣{reset}"
    bot = f"{yellow}╚" + "═" * inner_width + f"╝{reset}"

    def pad(content: str) -> str:
        content = content[:inner_width]
        return content.ljust(inner_width)

    title_text = pad("  FMC (Footprinting Master by CoreBridge)")
    ver_text = pad("  Version 2.1")
    feat_hdr_text = pad("  Features:")

    title = f"{yellow}║{reset}{red}{title_text}{reset}{yellow}║{reset}"
    ver = f"{yellow}║{reset}{red}{ver_text}{reset}{yellow}║{reset}"
    feat_hdr = f"{yellow}║{reset}{red}{feat_hdr_text}{reset}{yellow}║{reset}"
    features = [
        "• Wikipedia Company Information",
        "• WHOIS & SSL Analysis",
        "• Shodan Intelligence",
        "• CDN Detection",
        "• Multi-Source Subdomain Discovery",
        "• Active Subdomain Verification",
        "• Website Mirroring (HTTrack/wget, Headless fallback)",
        "• Nmap Stealth Port Scan (-sS, -sV) with live output",
    ]
    body_lines = []
    for line in features:
        body_lines.append(f"{yellow}║{reset}" + pad(f"  {line}") + f"{yellow}║{reset}")
    banner_lines = [top, title, ver, sep, feat_hdr] + body_lines + [bot]
    print("\n".join(banner_lines))


def check_dependencies():
    """Check for required dependencies."""
    missing_deps = []
    
    try:
        import requests
    except ImportError:
        missing_deps.append("requests")
    
    try:
        import bs4
    except ImportError:
        missing_deps.append("beautifulsoup4")
    
    if missing_deps:
        print("❌ Missing required dependencies:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print("\n📦 Install with: pip install " + " ".join(missing_deps))
        return False
    
    return True


def check_optional_tools():
    """Check for optional tools and provide installation hints."""
    import subprocess
    
    tools = {
        'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
        'httprobe': 'go install github.com/tomnomnom/httprobe@latest',
        'httrack': 'sudo apt update && sudo apt install httrack',
        'wget': 'sudo apt update && sudo apt install wget',
        'whois': 'sudo apt update && sudo apt install whois',
        'nmap': 'sudo apt update && sudo apt install nmap',
        'playwright': 'pip install playwright && python -m playwright install chromium'
    }
    
    print("🔧 Optional Tools Status:")
    for tool, install_cmd in tools.items():
        try:
            subprocess.run([tool, '--help'], 
                         capture_output=True, timeout=5)
            print(f"   ✅ {tool} - Available")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"   ❌ {tool} - Not found")
            print(f"      Install: {install_cmd}")
    print()


def main():
    """Main entry point."""
    try:
        print_cb_logo()
        print_banner()
        
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)
        
        print("✅ All required dependencies found!")
        print()
        
        # Check optional tools
        check_optional_tools()
        
        # Run the reconnaissance tool
        recon_tool = DomainReconnaissanceTool()
        recon_tool.run()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

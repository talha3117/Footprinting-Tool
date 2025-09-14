import socket
import ssl
import subprocess
import re
import json
from bs4 import BeautifulSoup
from utils import SessionManager


class WikipediaInfoGatherer:
    """Gathers company information from Wikipedia."""
    
    def __init__(self):
        self.session = SessionManager.make_session()
    
    def get_company_info(self, domain):
        """Extract company information from Wikipedia."""
        try:
            # Search for Wikipedia page
            search_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={domain}&format=json"
            resp = self.session.get(search_url, timeout=10)
            if resp.status_code != 200:
                return {}
            
            data = resp.json()
            search_results = data.get("query", {}).get("search", [])
            if not search_results:
                return {}
            
            # Get the first result
            page_title = search_results[0]["title"]
            page_url = f"https://en.wikipedia.org/wiki/{page_title.replace(' ', '_')}"
            
            # Fetch page content
            resp = self.session.get(page_url, timeout=10)
            if resp.status_code != 200:
                return {}
            
            return self._parse_infobox(resp.text, domain)
        
        except Exception as e:
            print(f"Wikipedia error: {e}")
            return {}
    
    def _parse_infobox(self, html_content, domain):
        """Parse Wikipedia infobox for company information."""
        soup = BeautifulSoup(html_content, "html.parser")
        infobox = soup.find("table", class_="infobox")
        if not infobox:
            return {}
        
        info = {}
        rows = infobox.find_all("tr")
        
        # Key mapping for standardization
        key_mapping = {
            "Formerly": "Formerly",
            "Type": "Company type",
            "Traded as": "Traded as",
            "ISIN": "ISIN",
            "Industry": "Industry",
            "Founded": "Founded",
            "Founder": "Founders",
            "Founders": "Founders",
            "Headquarters": "Headquarters",
            "Number of locations": "Number of locations",
            "Area served": "Area served",
            "Key people": "Key people",
            "Products": "Products",
            "Production output": "Production output",
            "Services": "Services",
            "Revenue": "Revenue",
            "Operating income": "Operating income",
            "Net income": "Net income",
            "Total assets": "Total assets",
            "Total equity": "Total equity",
            "Owner": "Owner",
            "Number of employees": "Number of employees",
            "Subsidiaries": "Subsidiaries",
            "Website": "Website"
        }
        
        for row in rows:
            th = row.find("th")
            td = row.find("td")
            if th and td:
                key = th.get_text(strip=True).rstrip(":")
                value = td.get_text(strip=True)
                
                if key in key_mapping:
                    info[key_mapping[key]] = value
        
        # Try to get basic ASN info
        try:
            asn_url = f"https://dns.google/resolve?name={domain}&type=A"
            resp = self.session.get(asn_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                if answers:
                    ip = answers[0].get("data")
                    if ip:
                        info["ASN"] = f"IP: {ip} (ASN lookup needed)"
        except:
            pass
        
        return info


class WhoisInfoGatherer:
    """Gathers WHOIS, IP, and SSL certificate information."""
    
    def get_whois_info(self, domain):
        """Get comprehensive WHOIS and SSL information."""
        info = {}
        
        # Get IP information
        info.update(self._get_ip_info(domain))
        
        # Get SSL certificate information
        info.update(self._get_ssl_info(domain))
        
        # Get WHOIS information
        info.update(self._get_whois_data(domain))
        
        return info
    
    def _get_ip_info(self, domain):
        """Get IP address information."""
        try:
            ip = socket.gethostbyname(domain)
            return {"IP Address": ip}
        except Exception:
            return {"IP Address": "Not available"}
    
    def _get_ssl_info(self, domain):
        """Get SSL certificate information."""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate details
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    ssl_info.update({
                        "SSL Subject": subject.get('commonName', 'Not available'),
                        "SSL Issuer": issuer.get('organizationName', 'Not available'),
                        "SSL Valid From": cert.get('notBefore', 'Not available'),
                        "SSL Valid Until": cert.get('notAfter', 'Not available'),
                        "SSL Serial Number": cert.get('serialNumber', 'Not available')
                    })
                    
                    # Get SAN (Subject Alternative Names)
                    san_list = []
                    for ext in cert.get('subjectAltName', []):
                        if ext[0] == 'DNS':
                            san_list.append(ext[1])
                    ssl_info["SSL SAN"] = ", ".join(san_list) if san_list else "None"
                    
        except Exception:
            ssl_fields = ["SSL Subject", "SSL Issuer", "SSL Valid From", 
                         "SSL Valid Until", "SSL Serial Number", "SSL SAN"]
            for field in ssl_fields:
                ssl_info[field] = "Not available"
        
        return ssl_info
    
    def _get_whois_data(self, domain):
        """Get WHOIS information using system whois command."""
        whois_info = {}
        whois_fields = [
            "Registrar", "Registrar URL", "Creation Date", "Updated Date",
            "Expiry Date", "Name Servers", "Status", "Registrant Organization",
            "Registrant Country", "Admin Email"
        ]
        
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                whois_text = result.stdout
                
                # Parse common WHOIS fields
                field_patterns = {
                    "Registrar": r"Registrar:\s*(.+)",
                    "Registrar URL": r"Registrar URL:\s*(.+)",
                    "Creation Date": r"Creation Date:\s*(.+)",
                    "Updated Date": r"Updated Date:\s*(.+)",
                    "Expiry Date": r"Registry Expiry Date:\s*(.+)",
                    "Name Servers": r"Name Server:\s*(.+)",
                    "Status": r"Status:\s*(.+)",
                    "Registrant Organization": r"Registrant Organization:\s*(.+)",
                    "Registrant Country": r"Registrant Country:\s*(.+)",
                    "Admin Email": r"Admin Email:\s*(.+)"
                }
                
                for field, pattern in field_patterns.items():
                    match = re.search(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
                    whois_info[field] = match.group(1).strip() if match else "Not available"
            else:
                for field in whois_fields:
                    whois_info[field] = "Not available"
                    
        except Exception:
            for field in whois_fields:
                whois_info[field] = "Not available"
        
        return whois_info


class CDNDetector:
    """Detects CDN usage through various methods."""
    
    def __init__(self):
        self.session = SessionManager.make_session()
        self.cdn_patterns = [
            "cloudflare.com", "cloudflare.net", "cdn.cloudflare.net",
            "cloudfront.net", "akamai.net", "akamaiedge.net",
            "edgekey.net", "edgesuite.net", "fastly.net", "fastlylb.net",
            "stackpathdns.com", "stackpathcdn.com", "cdn77.org", "cdn77.com",
            "azureedge.net", "hwcdn.net", "netdna-cdn.com", "cachefly.net",
            "incapdns.net", "impervadns.net", "cdnetworks.net", "edgecastcdn.net"
        ]
    
    def detect_cdn(self, domain):
        """Comprehensive CDN detection."""
        detected = set()
        hosts = [domain, f"www.{domain}"]
        cname_map = {}
        nameservers = []
        headers_info = {}
        
        # CNAME analysis
        for host in hosts:
            cnames = self._get_cnames(host)
            cname_map[host] = cnames
            detected.update(self._match_patterns(cnames))
        
        # Nameserver analysis
        nameservers = self._get_nameservers(domain)
        if nameservers:
            detected.update(self._match_patterns(nameservers))
        
        # HTTP header analysis
        headers_info, final_url = self._analyze_headers(domain)
        if headers_info:
            detected.update(self._match_patterns(list(headers_info.values())))
        
        return {
            "detected_cdns": sorted(detected),
            "cname_map": cname_map,
            "nameservers": nameservers,
            "headers": headers_info,
            "final_url": final_url
        }
    
    def _get_cnames(self, hostname):
        """Get CNAME records from multiple DNS over HTTPS providers."""
        cnames = []
        
        # Google DNS
        try:
            url = f"https://dns.google/resolve?name={hostname}&type=CNAME"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", []) or []
                for ans in answers:
                    if ans.get("type") == 5 and ans.get("data"):
                        cnames.append(ans["data"].rstrip("."))
        except Exception:
            pass
        
        # Cloudflare DNS
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=CNAME"
            headers = {"accept": "application/dns-json"}
            resp = self.session.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", []) or []
                for ans in answers:
                    if ans.get("type") == 5 and ans.get("data"):
                        cnames.append(ans["data"].rstrip("."))
        except Exception:
            pass
        
        return sorted(set(cnames))
    
    def _get_nameservers(self, domain):
        """Get nameserver records."""
        try:
            url = f"https://dns.google/resolve?name={domain}&type=NS"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", []) or []
                nameservers = []
                for ans in answers:
                    if ans.get("type") == 2 and ans.get("data"):
                        nameservers.append(ans["data"].rstrip("."))
                return nameservers
        except Exception:
            pass
        return []
    
    def _analyze_headers(self, domain):
        """Analyze HTTP headers for CDN indicators."""
        header_whitelist = {
            "Server", "CF-RAY", "Via", "X-Cache", "X-Cache-Status",
            "X-Served-By", "X-Akamai-Transformed", "X-Edge-Location",
            "X-Fastly-Request-ID", "cf-mitigated", "CDN-Cache-Status"
        }
        
        selected_headers = {}
        final_url = None
        
        for scheme in ("https://", "http://"):
            url = f"{scheme}{domain}"
            try:
                resp = self.session.get(url, timeout=10, allow_redirects=True)
                final_url = resp.url
                for k, v in resp.headers.items():
                    if k in header_whitelist or k.lower().startswith("cf-"):
                        selected_headers[k] = v
                break
            except Exception:
                continue
        
        return selected_headers, final_url
    
    def _match_patterns(self, strings):
        """Match strings against known CDN patterns."""
        matches = set()
        for s in strings:
            s_lower = str(s).lower()
            for pattern in self.cdn_patterns:
                if pattern in s_lower:
                    matches.add(pattern)
        return matches


class ShodanInfoGatherer:
    """Gathers intelligence from the Shodan API for a given domain."""
    
    def __init__(self, api_key=None):
        self.session = SessionManager.make_session()
        # Cache API key if provided; otherwise will read from environment
        self.api_key = api_key
    
    def get_shodan_info(self, domain):
        """Fetch and normalize Shodan data for the target domain.
        
        Tries multiple Shodan endpoints and consolidates results into a single dict.
        Requires SHODAN_API_KEY in environment.
        """
        import os
        import socket
        api_key = self.api_key or os.environ.get("SHODAN_API_KEY")
        if not api_key:
            return {"Error": "SHODAN_API_KEY not set in environment"}
        
        base = "https://api.shodan.io"
        results = {
            "Domain": domain,
            "IPs": [],
            "Hostnames": [],
            "Organization": "Not available",
            "ISP": "Not available",
            "Country": "Not available",
            "City": "Not available",
            "Operating System": "Not available",
            "ASN": "Not available",
            "Open Ports": [],
            "Products": [],
            "Tags": [],
            "Last Update": "Not available",
            "Vulnerabilities": [],
            "CVEs": [],
            "Shodan Domains": [],
            "Shodan Subdomains": []
        }
        
        def safe_get(url, params=None, timeout=10):
            try:
                resp = self.session.get(url, params=params or {}, timeout=timeout)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass
            return None
        
        # Resolve domain to IP(s) via Shodan DNS resolve (prefer Shodan path first for consistency)
        try:
            resolve = safe_get(f"{base}/dns/resolve", params={"hostnames": domain, "key": api_key})
            if isinstance(resolve, dict):
                ip_candidate = resolve.get(domain)
                if ip_candidate:
                    results["IPs"].append(ip_candidate)
        except Exception:
            pass
        
        # Fallback to system DNS if Shodan resolve failed
        if not results["IPs"]:
            try:
                results["IPs"].append(socket.gethostbyname(domain))
            except Exception:
                pass
        
        # Shodan domain profile (subdomains, related domains)
        try:
            domain_info = safe_get(f"{base}/dns/domain/{domain}", params={"key": api_key})
            if isinstance(domain_info, dict):
                # Subdomains
                subs = domain_info.get("subdomains") or []
                results["Shodan Subdomains"] = sorted({f"{s}.{domain}" for s in subs if s})
                # Related domains list
                data_records = domain_info.get("data") or []
                related_domains = set()
                for rec in data_records:
                    d = rec.get("rrname")
                    if d:
                        related_domains.add(d)
                if related_domains:
                    results["Shodan Domains"] = sorted(related_domains)
        except Exception:
            pass
        
        # Host search by hostname:domain to aggregate multiple IPs/hosts under the domain
        try:
            # Use facets to reduce volume; paginate lightly
            query = f"hostname:{domain}"
            page = 1
            max_pages = 2
            aggregated_ports = set()
            aggregated_products = set()
            aggregated_tags = set()
            aggregated_cves = set()
            while page <= max_pages:
                search = safe_get(f"{base}/shodan/host/search", params={"key": api_key, "query": query, "page": page})
                if not search or not isinstance(search, dict):
                    break
                matches = search.get("matches") or []
                if not matches:
                    break
                for item in matches:
                    ip_str = item.get("ip_str")
                    if ip_str:
                        results["IPs"].append(ip_str)
                    hostnames = item.get("hostnames") or []
                    results["Hostnames"].extend(hostnames)
                    org = item.get("org") or item.get("data", "")
                    if org and results["Organization"] == "Not available":
                        results["Organization"] = org
                    isp = item.get("isp")
                    if isp and results["ISP"] == "Not available":
                        results["ISP"] = isp
                    loc = item.get("location") or {}
                    country = loc.get("country_name") or item.get("location.country_name")
                    city = loc.get("city") or item.get("location.city")
                    if country and results["Country"] == "Not available":
                        results["Country"] = country
                    if city and results["City"] == "Not available":
                        results["City"] = city
                    os_name = item.get("os")
                    if os_name and results["Operating System"] == "Not available":
                        results["Operating System"] = os_name
                    asn = item.get("asn")
                    if asn and results["ASN"] == "Not available":
                        results["ASN"] = asn
                    # Ports and product banners
                    port = item.get("port")
                    if port:
                        aggregated_ports.add(port)
                    product = item.get("product") or item.get("_shodan", {}).get("module")
                    if product:
                        aggregated_products.add(str(product))
                    # Tags
                    for t in item.get("tags") or []:
                        aggregated_tags.add(t)
                    # Vulns
                    for cve in (item.get("vulns") or {}).keys():
                        aggregated_cves.add(cve)
                    # Last update
                    last_update = item.get("timestamp") or item.get("_shodan", {}).get("module")
                    if last_update and results["Last Update"] == "Not available":
                        results["Last Update"] = last_update
                page += 1
            if aggregated_ports:
                results["Open Ports"] = sorted(aggregated_ports)
            if aggregated_products:
                results["Products"] = sorted(aggregated_products)
            if aggregated_tags:
                results["Tags"] = sorted(aggregated_tags)
            if aggregated_cves:
                results["Vulnerabilities"] = sorted(aggregated_cves)
                results["CVEs"] = sorted(aggregated_cves)
        except Exception:
            pass
        
        # Direct host lookup for each resolved IP (fills missing details)
        try:
            unique_ips = sorted({ip for ip in results["IPs"] if ip})
            for ip in unique_ips[:5]:  # limit lookups
                host = safe_get(f"{base}/shodan/host/{ip}", params={"key": api_key})
                if not host or not isinstance(host, dict):
                    continue
                if host.get("org") and results["Organization"] == "Not available":
                    results["Organization"] = host.get("org")
                if host.get("isp") and results["ISP"] == "Not available":
                    results["ISP"] = host.get("isp")
                if host.get("os") and results["Operating System"] == "Not available":
                    results["Operating System"] = host.get("os")
                if host.get("asn") and results["ASN"] == "Not available":
                    results["ASN"] = host.get("asn")
                loc = host.get("location") or {}
                if loc.get("country_name") and results["Country"] == "Not available":
                    results["Country"] = loc.get("country_name")
                if loc.get("city") and results["City"] == "Not available":
                    results["City"] = loc.get("city")
                if host.get("last_update") and results["Last Update"] == "Not available":
                    results["Last Update"] = host.get("last_update")
                # Ports
                ports = host.get("ports") or []
                if ports:
                    merged = set(results["Open Ports"]) | set(ports)
                    results["Open Ports"] = sorted(merged)
                # Tags
                for t in host.get("tags") or []:
                    if t not in results["Tags"]:
                        results["Tags"].append(t)
                # Vulns
                for cve in (host.get("vulns") or {}).keys():
                    if cve not in results["Vulnerabilities"]:
                        results["Vulnerabilities"].append(cve)
                        results["CVEs"].append(cve)
        except Exception:
            pass
        
        # Normalize lists and deduplicate
        results["IPs"] = ", ".join(sorted(set(results["IPs"])) or []) or "Not available"
        results["Hostnames"] = ", ".join(sorted(set(results["Hostnames"])) or []) or "Not available"
        results["Open Ports"] = ", ".join(map(str, results["Open Ports"])) or "None"
        results["Products"] = ", ".join(results["Products"]) or "None"
        results["Tags"] = ", ".join(results["Tags"]) or "None"
        results["Vulnerabilities"] = ", ".join(results["Vulnerabilities"]) or "None"
        results["CVEs"] = ", ".join(results["CVEs"]) or "None"
        results["Shodan Domains"] = ", ".join(results["Shodan Domains"]) or "None"
        results["Shodan Subdomains"] = ", ".join(results["Shodan Subdomains"]) or "None"
        
        return results


class NmapScanner:
    """Runs Nmap scans in stealth mode (-sS) with verbose output and captures results."""
    
    def __init__(self):
        pass
    
    def scan(self, target, output_file, fast=False):
        """Run a stealthy SYN scan against the target.
        
        - target: hostname or IP
        - output_file: path to save normal output (text)
        - fast: if True, use -F (fast mode, fewer ports)
        
        Returns a tuple: (success:boolean, stdout:str, stderr:str)
        """
        import subprocess
        import shlex
        
        # Base options for stealth, verbose, service detection, and reasonable speed
        options = ["-sS", "-Pn", "--open", "-T2", "-vv", "-sV"]
        if fast:
            options.append("-F")
        
        cmd = ["nmap"] + options + ["-oN", output_file, target]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # up to 30 minutes for broad scans
            )
            success = proc.returncode == 0
            return success, proc.stdout, proc.stderr
        except FileNotFoundError:
            return False, "", "nmap not found. Install it (e.g., sudo apt install nmap)."
        except subprocess.TimeoutExpired:
            return False, "", "nmap scan timed out. Try fast mode or narrower port range."
        except Exception as e:
            return False, "", f"nmap error: {e}"

    def scan_stream(self, target, fast=False, extra_args=None, on_line=None):
        """Run Nmap and stream output line-by-line to on_line callback.
        Returns (returncode:int, full_output:str)
        """
        import subprocess
        
        options = ["-sS", "-Pn", "--open", "-T2", "-vv", "-sV"]
        if fast:
            options.append("-F")
        if extra_args:
            options.extend(extra_args)
        cmd = ["nmap"] + options + [target]
        full_output = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            for line in proc.stdout:
                if line is None:
                    continue
                full_output.append(line)
                if on_line:
                    try:
                        on_line(line.rstrip())
                    except Exception:
                        pass
            proc.wait()
            return proc.returncode, "".join(full_output)
        except FileNotFoundError:
            if on_line:
                on_line("nmap not found. Install it (e.g., sudo apt install nmap).")
            return 127, "nmap not found"
        except Exception as e:
            if on_line:
                on_line(f"nmap error: {e}")
            return 1, f"nmap error: {e}"

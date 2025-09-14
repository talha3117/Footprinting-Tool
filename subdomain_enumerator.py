import json
import subprocess
from bs4 import BeautifulSoup
from utils import SessionManager


class SubdomainEnumerator:
    """Main class for coordinating subdomain discovery from multiple sources."""
    
    def __init__(self):
        self.sources = {
            'rapiddns': RapidDNSEnumerator(),
            'assetfinder': AssetfinderEnumerator(),
            'crtsh': CrtShEnumerator(),
            'wayback': WaybackEnumerator(),
            'hackertarget': HackerTargetEnumerator()
        }
    
    def enumerate_all(self, domain):
        """Run all subdomain enumeration sources."""
        results = {}
        all_subdomains = set()
        
        for source_name, enumerator in self.sources.items():
            try:
                subdomains = enumerator.enumerate(domain)
                results[source_name] = subdomains
                all_subdomains.update(subdomains)
                print(f"[+] {source_name.capitalize()}: {len(subdomains)} subdomains")
            except Exception as e:
                print(f"[-] {source_name.capitalize()} error: {e}")
                results[source_name] = []
        
        return results, list(all_subdomains)
    
    def run_httprobe(self, subdomains):
        """Run httprobe on discovered subdomains to find active ones."""
        try:
            subdomains_input = "\n".join(sorted(subdomains))
            proc = subprocess.run(
                ["httprobe"],
                input=subdomains_input,
                text=True,
                capture_output=True,
                timeout=120
            )
            
            active = set()
            for line in proc.stdout.splitlines():
                url = line.strip()
                if url:
                    active.add(url)
            
            return list(active)
        
        except FileNotFoundError:
            raise Exception("httprobe not found. Install it first.")
        except subprocess.TimeoutExpired:
            raise Exception("httprobe timeout (120 seconds)")
        except Exception as e:
            raise Exception(f"httprobe error: {e}")


class BaseEnumerator:
    """Base class for subdomain enumerators."""
    
    def __init__(self):
        self.session = SessionManager.make_session()
    
    def enumerate(self, domain):
        """Override this method in subclasses."""
        raise NotImplementedError


class RapidDNSEnumerator(BaseEnumerator):
    """RapidDNS subdomain enumerator."""
    
    def enumerate(self, domain):
        """Enumerate subdomains from RapidDNS."""
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        subdomains = set()
        
        try:
            # Attempt 1: full page
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            for td in soup.find_all("td"):
                text = td.get_text(strip=True)
                if text and domain in text:
                    subdomains.add(text)
            
            # If nothing found, try lite page
            if not subdomains:
                alt_url = f"https://rapiddns.io/subdomain/{domain}"
                resp2 = self.session.get(alt_url, timeout=10)
                soup2 = BeautifulSoup(resp2.text, "html.parser")
                
                # Try td elements
                for td in soup2.find_all("td"):
                    text = td.get_text(strip=True)
                    if text and domain in text:
                        subdomains.add(text)
                
                # Fallback to anchor tags
                if not subdomains:
                    for a in soup2.find_all("a", href=True):
                        text = a.get_text(strip=True)
                        if text and domain in text:
                            subdomains.add(text)
            
            return list(subdomains)
        
        except Exception as e:
            raise Exception(f"RapidDNS error: {e}")


class AssetfinderEnumerator(BaseEnumerator):
    """Assetfinder subdomain enumerator."""
    
    def enumerate(self, domain):
        """Enumerate subdomains using assetfinder tool."""
        try:
            result = subprocess.run(
                ["assetfinder", "--subs-only", domain],
                capture_output=True, text=True, timeout=15
            )
            
            subdomains = set()
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and domain in line:
                    subdomains.add(line)
            
            return list(subdomains)
        
        except FileNotFoundError:
            raise Exception("assetfinder not found")
        except subprocess.TimeoutExpired:
            raise Exception("assetfinder timeout")
        except Exception as e:
            raise Exception(f"assetfinder error: {e}")


class CrtShEnumerator(BaseEnumerator):
    """Certificate Transparency logs enumerator via crt.sh."""
    
    def enumerate(self, domain):
        """Enumerate subdomains from Certificate Transparency logs."""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code != 200:
                return []
            
            subdomains = set()
            
            # Parse JSON response (handle multiple JSON objects)
            try:
                data = resp.json()
                rows = data if isinstance(data, list) else []
            except json.JSONDecodeError:
                # Handle concatenated JSON objects
                rows = []
                for line in resp.text.splitlines():
                    line = line.strip().rstrip(",")
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        rows.append(obj)
                    except Exception:
                        continue
            
            for row in rows:
                name_value = row.get("name_value", "")
                for entry in name_value.split("\n"):
                    entry = entry.strip().lstrip("*.")
                    if entry and domain in entry:
                        subdomains.add(entry)
            
            return list(subdomains)
        
        except Exception as e:
            raise Exception(f"crt.sh error: {e}")


class WaybackEnumerator(BaseEnumerator):
    """Wayback Machine subdomain enumerator."""
    
    def enumerate(self, domain):
        """Enumerate subdomains from Wayback Machine."""
        url = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            f"&output=json&fl=original&collapse=urlkey"
        )
        
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code != 200:
                return []
            
            data = resp.json()
            subdomains = set()
            
            for row in data[1:]:  # Skip header row
                original = row[0]
                if "//" in original:
                    host = original.split("/")[2]
                else:
                    host = original
                
                if domain in host:
                    subdomains.add(host)
            
            return list(subdomains)
        
        except Exception as e:
            raise Exception(f"Wayback error: {e}")


class HackerTargetEnumerator(BaseEnumerator):
    """HackerTarget API subdomain enumerator."""
    
    def enumerate(self, domain):
        """Enumerate subdomains from HackerTarget API."""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code != 200 or "error" in resp.text.lower():
                return []
            
            subdomains = set()
            for line in resp.text.splitlines():
                parts = line.split(",")
                if len(parts) >= 1:
                    host = parts[0].strip()
                    if domain in host:
                        subdomains.add(host)
            
            return list(subdomains)
        
        except Exception as e:
            raise Exception(f"HackerTarget error: {e}")


class WebsiteMirrorer:
    """Handles website mirroring using HTTrack."""
    
    def __init__(self, target_dir):
        self.target_dir = target_dir
    
    def mirror_website(self, domain):
        """Mirror website using HTTrack."""
        import os
        
        # Create mirror directory
        mirror_dir = os.path.join(self.target_dir, "mirrored_site")
        os.makedirs(mirror_dir, exist_ok=True)
        
        try:
            # Build filters to allow redirects to www and same-domain content
            filters = [
                f"+{domain}/*",
                f"+www.{domain}/*",
                f"+*.{domain}/*"
            ]

            # HTTrack command (robust defaults)
            httrack_cmd = [
                "httrack",
                f"https://{domain}",
                "http://{domain}".format(domain=domain),
                "-O", mirror_dir,
                "--quiet",
                "--keep-alive",
                "--robots=0",  # ignore robots if you have permission to test
                "-K0",  # keep original links
                "-A25000000",  # max transfer rate
                "-F", "Mozilla/5.0 (compatible; HTTrack/3.0)",  # user agent
            ] + filters
            
            result = subprocess.run(
                httrack_cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=self.target_dir
            )
            
            # Save logs for troubleshooting
            try:
                with open(os.path.join(mirror_dir, "httrack_stdout.log"), "w") as outlog:
                    outlog.write(result.stdout or "")
                with open(os.path.join(mirror_dir, "httrack_stderr.log"), "w") as errlog:
                    errlog.write(result.stderr or "")
            except Exception:
                pass

            # Consider success only if some files were actually mirrored
            has_files = False
            for root, dirs, files in os.walk(mirror_dir):
                # ignore the logs themselves
                files = [f for f in files if not f.startswith("httrack_")]
                if files:
                    has_files = True
                    break

            if result.returncode == 0 and has_files:
                return mirror_dir, "Success"
            elif result.returncode == 0 and not has_files:
                # Fallback to wget mirroring
                wget_cmd = [
                    "wget",
                    "--mirror",
                    "--convert-links",
                    "--adjust-extension",
                    "--page-requisites",
                    "--no-parent",
                    "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                    "--header=Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "--header=Accept-Language: en-US,en;q=0.9",
                    "--header=Upgrade-Insecure-Requests: 1",
                    "--execute=robots=off",
                    f"--domains={domain},www.{domain}",
                    f"https://{domain}",
                    f"http://{domain}",
                    "-P", mirror_dir
                ]
                try:
                    wres = subprocess.run(
                        wget_cmd,
                        capture_output=True,
                        text=True,
                        timeout=420,
                        cwd=self.target_dir
                    )
                    # Save wget logs
                    try:
                        with open(os.path.join(mirror_dir, "wget_stdout.log"), "w") as outlog:
                            outlog.write(wres.stdout or "")
                        with open(os.path.join(mirror_dir, "wget_stderr.log"), "w") as errlog:
                            errlog.write(wres.stderr or "")
                    except Exception:
                        pass
                    # Check again for files
                    has_files_wget = False
                    for root, dirs, files in os.walk(mirror_dir):
                        files = [f for f in files if not f.startswith("httrack_") and not f.startswith("wget_")]
                        if files:
                            has_files_wget = True
                            break
                    if wres.returncode == 0 and has_files_wget:
                        return mirror_dir, "Success (wget fallback)"
                    elif wres.returncode != 0:
                        # Try headless browser fallback (Playwright) if available
                        try:
                            from playwright.sync_api import sync_playwright
                            html_path = os.path.join(mirror_dir, "index.html")
                            screenshot_path = os.path.join(mirror_dir, "screenshot.png")
                            with sync_playwright() as p:
                                browser = p.chromium.launch(headless=True)
                                context = browser.new_context(
                                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
                                )
                                page = context.new_page()
                                try:
                                    page.goto(f"https://{domain}", wait_until="domcontentloaded", timeout=20000)
                                except Exception:
                                    page.goto(f"http://{domain}", wait_until="domcontentloaded", timeout=20000)
                                # Give some time for JS-based protections to settle
                                try:
                                    page.wait_for_load_state("networkidle", timeout=10000)
                                except Exception:
                                    pass
                                content = page.content()
                                with open(html_path, "w", encoding="utf-8") as f:
                                    f.write(content)
                                try:
                                    page.screenshot(path=screenshot_path, full_page=True)
                                except Exception:
                                    pass
                                context.close()
                                browser.close()
                            # Verify we saved something
                            if os.path.exists(html_path) and os.path.getsize(html_path) > 0:
                                return mirror_dir, "Success (headless browser)"
                            return None, "All mirror methods failed to fetch content."
                        except ImportError:
                            return None, "wget error and Playwright not installed. Install with: pip install playwright && playwright install chromium"
                        except Exception as e:
                            return None, f"Headless browser error: {e}"
                    else:
                        # wget returned 0 but no files found
                        return None, "HTTrack and wget finished but no files were mirrored. Site may block crawlers or requires JS. See logs in mirrored_site/."
                except FileNotFoundError:
                    return None, "HTTrack finished with no files and wget is not installed. Install wget or use a headless crawler."
                except subprocess.TimeoutExpired:
                    return mirror_dir, "wget fallback timed out. Partial data may exist."
            else:
                return None, f"HTTrack error: {result.stderr}"
                
        except FileNotFoundError:
            return None, "HTTrack not found. Install it first: sudo apt update && sudo apt install httrack"
        except subprocess.TimeoutExpired:
            return mirror_dir, "Timeout (5 minutes). Mirroring may be incomplete."
        except Exception as e:
            return None, f"HTTrack error: {e}"
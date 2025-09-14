import os
from utils import (TableFormatter, SpinnerManager, FileManager, 
                   UserInterface, Logger)
from info_gatherer import (WikipediaInfoGatherer, WhoisInfoGatherer, 
                          CDNDetector, ShodanInfoGatherer, NmapScanner)
from subdomain_enumerator import (SubdomainEnumerator, WebsiteMirrorer)


class DomainReconnaissanceTool:
    """Main class that orchestrates the domain reconnaissance process."""
    
    def __init__(self):
        self.logger = Logger()
        self.ui = UserInterface()
        self.table_formatter = TableFormatter()
        self.spinner = SpinnerManager()
        
        # Initialize gatherers
        self.wikipedia_gatherer = WikipediaInfoGatherer()
        self.whois_gatherer = WhoisInfoGatherer()
        self.cdn_detector = CDNDetector()
        self.subdomain_enumerator = SubdomainEnumerator()
        self.shodan_gatherer = ShodanInfoGatherer()
        self.nmap_scanner = NmapScanner()
        
        self.domain = None
        self.target_dir = None
    
    def run(self):
        """Main execution flow."""
        try:
            # Get domain input
            self.domain = self.ui.get_domain_input()
            
            # Create target directory
            self.target_dir = FileManager.create_target_directory(self.domain)
            self.logger.success(f"Created directory: {self.target_dir}/")
            
            # Run reconnaissance phases
            self._run_wikipedia_phase()
            self._run_whois_phase()
            self._run_shodan_phase()
            self._run_cdn_detection_phase()
            self._run_subdomain_discovery_phase()
            self._run_website_mirroring_phase()
            self._run_nmap_phase()
            
            self.logger.success("Domain reconnaissance completed!")
            
        except KeyboardInterrupt:
            self.logger.warning("Process interrupted by user")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
    
    def _run_wikipedia_phase(self):
        """Run Wikipedia information gathering phase."""
        self.spinner.start("Fetching Wikipedia company info")
        wiki_info = self.wikipedia_gatherer.get_company_info(self.domain)
        self.spinner.stop()
        
        # Prepare data for table
        fields = [
            "Formerly", "Company type", "Traded as", "ISIN", "Industry", "Founded", 
            "Founders", "Headquarters", "Number of locations", "Area served", 
            "Key people", "Products", "Production output", "Services", "Revenue", 
            "Operating income", "Net income", "Total assets", "Total equity", 
            "Owner", "Number of employees", "Subsidiaries", "ASN", "Website"
        ]
        
        wiki_rows = []
        for field in fields:
            value = wiki_info.get(field, "Not available")
            wiki_rows.append([field, value])
        
        # Create and display table
        wiki_table = self.table_formatter.create_table(
            ["Field", "Value"], wiki_rows, "Wikipedia Company Information"
        )
        
        # Save and display
        wiki_output = os.path.join(self.target_dir, f"Company_Info_{self.domain}.txt")
        FileManager.save_to_file(wiki_table + "\n", wiki_output)
        
        print(wiki_table)
        self.logger.success(f"Company info saved to {wiki_output}")
    
    def _run_whois_phase(self):
        """Run WHOIS information gathering phase."""
        if not self.ui.get_yes_no_input("Proceed to WHOIS information?"):
            return
        
        self.spinner.start("Collecting WHOIS information")
        whois_info = self.whois_gatherer.get_whois_info(self.domain)
        self.spinner.stop()
        
        # Prepare data for table
        whois_fields = [
            "IP Address", "SSL Subject", "SSL Issuer", "SSL Valid From", "SSL Valid Until",
            "SSL Serial Number", "SSL SAN", "Registrar", "Registrar URL", "Creation Date",
            "Updated Date", "Expiry Date", "Name Servers", "Status", "Registrant Organization",
            "Registrant Country", "Admin Email"
        ]
        
        whois_rows = []
        for field in whois_fields:
            value = whois_info.get(field, "Not available")
            whois_rows.append([field, value])
        
        # Create and display table
        whois_table = self.table_formatter.create_table(
            ["Field", "Value"], whois_rows, "WHOIS & SSL Information"
        )
        
        # Save and display
        whois_output = os.path.join(self.target_dir, f"WHOIS_{self.domain}.txt")
        FileManager.save_to_file(whois_table + "\n", whois_output)
        
        print(whois_table)
        self.logger.success(f"WHOIS info saved to {whois_output}")
    
    def _run_shodan_phase(self):
        """Run Shodan information gathering phase."""
        if not self.ui.get_yes_no_input("Proceed to Shodan intelligence?"):
            return
        
        # Ensure API key: if env missing, prompt user once
        import os
        api_key = os.environ.get("SHODAN_API_KEY")
        if not api_key:
            self.logger.warning("SHODAN_API_KEY not found in environment.")
            if self.ui.get_yes_no_input("Enter Shodan API key now?"):
                api_key = self.ui.get_text_input("Enter SHODAN_API_KEY")
                if api_key:
                    self.shodan_gatherer = ShodanInfoGatherer(api_key=api_key)
        
        self.spinner.start("Querying Shodan intelligence")
        shodan_info = self.shodan_gatherer.get_shodan_info(self.domain)
        self.spinner.stop()
        
        # Fields to display in a stable order
        shodan_fields = [
            "Domain", "IPs", "Hostnames", "Organization", "ISP", "Country", "City",
            "Operating System", "ASN", "Open Ports", "Products", "Tags", "Last Update",
            "Vulnerabilities", "CVEs", "Shodan Subdomains", "Shodan Domains", "Error"
        ]
        
        shodan_rows = []
        for field in shodan_fields:
            if field in shodan_info:
                shodan_rows.append([field, shodan_info.get(field, "Not available")])
        
        shodan_table = self.table_formatter.create_table(
            ["Field", "Value"], shodan_rows, "Shodan Intelligence"
        )
        
        # Save and display
        shodan_output = os.path.join(self.target_dir, f"Shodan_{self.domain}.txt")
        FileManager.save_to_file(shodan_table + "\n", shodan_output)
        
        print(shodan_table)
        self.logger.success(f"Shodan info saved to {shodan_output}")

    def _run_nmap_phase(self):
        """Ask user to run an Nmap stealth scan and handle execution and output."""
        if not self.ui.get_yes_no_input("Scan ports with Nmap (stealth SYN scan)?"):
            return
        
        # Choose fast mode to reduce time for large targets
        fast_mode = self.ui.get_yes_no_input("Use fast mode (-F, fewer ports) for quicker results?")
        
        output_file = os.path.join(self.target_dir, f"scan_{self.domain}.txt")
        
        # Stream output while showing spinner-like progress
        live_lines = []
        def on_line(line):
            live_lines.append(line)
            # Print incremental discoveries for ports/services
            if "/tcp" in line or "/udp" in line or line.lower().startswith("nmap scan report for"):
                print(line)
        
        self.spinner.start("Running Nmap (-sS -sV -vv)... streaming results below")
        returncode, full_output = self.nmap_scanner.scan_stream(self.domain, fast=fast_mode, on_line=on_line)
        self.spinner.stop()
        
        # Save transcript
        try:
            FileManager.save_to_file(full_output, output_file)
        except Exception:
            pass
        
        if returncode == 0:
            self.logger.success(f"Nmap scan complete. Results saved to {output_file}")
        elif returncode == 127:
            self.logger.error("nmap not found. Install it: sudo apt install nmap")
        else:
            self.logger.error("Nmap scan encountered errors. See saved output for details.")
    
    def _run_cdn_detection_phase(self):
        """Run CDN detection phase."""
        if not self.ui.get_yes_no_input("Proceed to CDN detection?"):
            return
        
        self.spinner.start("Collecting CDN signals")
        cdn_results = self.cdn_detector.detect_cdn(self.domain)
        self.spinner.stop()
        
        # Prepare data for table
        def compact_list(lst, max_items=3):
            if not lst:
                return "None"
            if len(lst) <= max_items:
                return ", ".join(lst)
            return ", ".join(lst[:max_items]) + f" (+{len(lst)-max_items} more)"
        
        cdn_rows = [
            ["Target", self.domain],
            ["Detected CDNs", ", ".join(cdn_results["detected_cdns"]) if cdn_results["detected_cdns"] else "None detected"],
            ["Nameservers", compact_list(cdn_results["nameservers"])],
            [f"CNAMEs for {self.domain}", compact_list(cdn_results["cname_map"].get(self.domain, []))],
            [f"CNAMEs for www.{self.domain}", compact_list(cdn_results["cname_map"].get(f"www.{self.domain}", []))]
        ]
        
        if cdn_results["headers"]:
            header_lines = [f"{k}: {v}" for k, v in cdn_results["headers"].items()]
            cdn_rows.append(["HTTP headers", "\n".join(header_lines)])
        else:
            cdn_rows.append(["HTTP headers", "None"])
        
        # Create and display table
        cdn_table = self.table_formatter.create_table(
            ["Field", "Value"], cdn_rows, "CDN Detection Results"
        )
        
        # Save and display
        cdn_output = os.path.join(self.target_dir, f"CDNs_{self.domain}.txt")
        FileManager.save_to_file(cdn_table + "\n", cdn_output)
        
        print(cdn_table)
        self.logger.success(f"CDN results saved to {cdn_output}")
    
    def _run_subdomain_discovery_phase(self):
        """Run subdomain discovery phase."""
        if not self.ui.get_yes_no_input("Proceed to subdomain discovery?"):
            return
        
        self.spinner.start("Discovering subdomains")
        source_results, all_subdomains = self.subdomain_enumerator.enumerate_all(self.domain)
        self.spinner.stop()
        
        # Display summary
        self.ui.print_summary("Subdomain Discovery Summary", {
            source: len(subdomains) for source, subdomains in source_results.items()
        })
        self.logger.info(f"TOTAL UNIQUE: {len(all_subdomains)}")
        
        # Save results
        output_file = os.path.join(self.target_dir, f"subdomains_{self.domain}.txt")
        FileManager.save_list_to_file(all_subdomains, output_file)
        self.logger.success(f"Results saved to {output_file}")
        
        # Run httprobe if requested
        if self.ui.get_yes_no_input("Run httprobe on discovered subdomains?"):
            self._run_httprobe(all_subdomains)
    
    def _run_httprobe(self, subdomains):
        """Run httprobe on discovered subdomains."""
        try:
            self.spinner.start("Running httprobe on subdomains")
            active_urls = self.subdomain_enumerator.run_httprobe(subdomains)
            self.spinner.stop()
            
            # Save active URLs
            active_file = os.path.join(self.target_dir, f"Active_{self.domain}.txt")
            FileManager.save_list_to_file(active_urls, active_file)
            
            self.logger.info(f"Alive (httprobe): {len(active_urls)}")
            self.logger.success(f"Active URLs saved to {active_file}")
            
        except Exception as e:
            self.spinner.stop()
            self.logger.error(str(e))
            if "not found" in str(e).lower():
                self.logger.warning("Install httprobe: go install github.com/tomnomnom/httprobe@latest")
    
    def _run_website_mirroring_phase(self):
        """Run website mirroring phase."""
        if not self.ui.get_yes_no_input("Mirror the target website using HTTrack?"):
            return
        
        self.logger.warning("HTTrack Requirements:")
        self.logger.info("    Install HTTrack: sudo apt update && sudo apt install httrack")
        self.logger.info("    Or: sudo apt install httrack-webhttrack")
        self.logger.success("Starting website mirroring...")
        
        mirrorer = WebsiteMirrorer(self.target_dir)
        
        self.spinner.start("Mirroring website with HTTrack")
        mirror_dir, status = mirrorer.mirror_website(self.domain)
        self.spinner.stop()
        
        if mirror_dir:
            if "Success" in status:
                self.logger.success(f"Website successfully mirrored to: {mirror_dir}/")
                self.logger.success(f"Mirror files saved in: {os.path.abspath(mirror_dir)}")
            else:
                self.logger.warning(status)
                self.logger.success(f"Partial mirror saved to: {mirror_dir}/")
        else:
            self.logger.error(status)
            if "not found" in status.lower():
                self.logger.warning("Install HTTrack first:")
                self.logger.info("    sudo apt update && sudo apt install httrack")

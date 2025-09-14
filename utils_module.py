import sys
import time
import threading
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class TableFormatter:
    """Utility class for formatting tables with colors."""
    
    def __init__(self):
        self.red = "\033[31m"
        self.blue = "\033[34m"
        self.yellow = "\033[33m"
        self.reset = "\033[0m"
    
    def create_table(self, headers, rows, title=None):
        """Create a formatted table with headers and rows."""
        if not rows:
            return "No data available"
        
        # Calculate column widths
        col1 = max(len(headers[0]), max(len(str(r[0])) for r in rows))
        col2 = max(len(headers[1]), max(len(line) for r in rows for line in str(r[1]).split("\n")))
        
        table_lines = []
        
        # Add title if provided
        if title:
            title_line = f"{self.yellow}=== {title} ==={self.reset}"
            table_lines.append(title_line)
            table_lines.append("")
        
        # Create table
        table_lines.append(self._hline(col1, col2))
        table_lines.append(f"{self.yellow}|{self.reset} {self.red}{headers[0]:<{col1}}{self.reset} {self.yellow}|{self.reset} {self.red}{headers[1]:<{col2}}{self.reset} {self.yellow}|{self.reset}")
        table_lines.append(self._hline(col1, col2))
        
        for field, value in rows:
            parts = str(value).split("\n")
            table_lines.append(f"{self.yellow}|{self.reset} {self.blue}{field:<{col1}}{self.reset} {self.yellow}|{self.reset} {parts[0]:<{col2}} {self.yellow}|{self.reset}")
            for cont in parts[1:]:
                table_lines.append(f"{self.yellow}|{self.reset} {'':<{col1}} {self.yellow}|{self.reset} {cont:<{col2}} {self.yellow}|{self.reset}")
            table_lines.append(self._hline(col1, col2))
        
        return "\n".join(table_lines)
    
    def _hline(self, col1, col2):
        """Create a horizontal line for the table."""
        return f"{self.yellow}+" + "-" * (col1 + 2) + "+" + "-" * (col2 + 2) + f"+{self.reset}"


class SpinnerManager:
    """Thread-safe spinner for loading animations."""
    
    def __init__(self):
        self.stop_spinner = False
        self.spinner_thread = None
        self.yellow = "\033[33m"
        self.red = "\033[31m"
        self.reset = "\033[0m"
    
    def start(self, message="Processing..."):
        """Start the spinner with a custom message."""
        self.stop_spinner = False
        self.spinner_thread = threading.Thread(target=self._spin, args=(message,))
        self.spinner_thread.daemon = True
        self.spinner_thread.start()
    
    def stop(self):
        """Stop the spinner."""
        self.stop_spinner = True
        if self.spinner_thread:
            self.spinner_thread.join(timeout=0.2)
        # Clear the line
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()
    
    def _spin(self, message):
        """Internal spinner animation."""
        frames = ['|', '/', '-', '\\']
        idx = 0
        while not self.stop_spinner:
            sys.stdout.write(f"\r{self.yellow}{message}{self.reset} {self.red}{frames[idx % len(frames)]}{self.reset}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)


class SessionManager:
    """Manages HTTP sessions with retry logic."""
    
    @staticmethod
    def make_session():
        """Create a session with proper headers and retry logic."""
        session = requests.Session()
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SubdomainEnumerator/1.0)"}
        session.headers.update(headers)
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session


class FileManager:
    """Handles file operations and directory management."""
    
    @staticmethod
    def create_target_directory(domain):
        """Create and return the target directory path."""
        import os
        target_dir = domain.replace(".", "_")
        os.makedirs(target_dir, exist_ok=True)
        return target_dir
    
    @staticmethod
    def save_to_file(content, filepath, mode='w'):
        """Save content to a file."""
        try:
            with open(filepath, mode) as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"[-] Error saving to {filepath}: {e}")
            return False
    
    @staticmethod
    def save_list_to_file(data_list, filepath):
        """Save a list of items to a file, one per line."""
        try:
            with open(filepath, 'w') as f:
                for item in sorted(data_list):
                    f.write(f"{item}\n")
            return True
        except Exception as e:
            print(f"[-] Error saving list to {filepath}: {e}")
            return False


class UserInterface:
    """Handles user interactions and prompts."""
    
    @staticmethod
    def get_domain_input():
        """Get domain input from user."""
        return input("Enter target domain (e.g. example.com): ").strip()
    
    @staticmethod
    def get_yes_no_input(prompt):
        """Get yes/no input from user."""
        response = input(f"\n{prompt} (Y/N): ").strip().lower()
        return response in ("y", "yes")
    
    @staticmethod
    def get_text_input(prompt):
        """Get arbitrary text input from user."""
        return input(f"{prompt}: ").strip()
    
    @staticmethod
    def print_summary(title, data_dict):
        """Print a formatted summary."""
        print(f"\n=== {title} ===")
        for key, value in data_dict.items():
            print(f"{key:<15} {value}")
        print("-" * 30)


class Logger:
    """Simple logging utility."""
    
    def __init__(self):
        self.green = "\033[32m"
        self.red = "\033[31m"
        self.yellow = "\033[33m"
        self.reset = "\033[0m"
    
    def success(self, message):
        """Log success message."""
        print(f"{self.green}[+]{self.reset} {message}")
    
    def error(self, message):
        """Log error message."""
        print(f"{self.red}[-]{self.reset} {message}")
    
    def warning(self, message):
        """Log warning message."""
        print(f"{self.yellow}[!]{self.reset} {message}")
    
    def info(self, message):
        """Log info message."""
        print(f"[*] {message}")

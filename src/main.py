#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EG-Tool Pro++ - Advanced Security Scanner with Real-Time Dashboard
Developer: EGHackers
Version: 4.0
"""

import os
import sys
import json
import time
import threading
import queue
import requests
import socket
import re
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures

# Initialize colorama
init(autoreset=True)

class RealTimeDashboard:
    """Real-time dashboard for displaying scan progress and results"""
    
    def __init__(self):
        self.results_queue = queue.Queue()
        self.scan_start_time = None
        self.completed_tools = 0
        self.total_tools = 0
        self.critical_findings = []
        self.admin_panels_found = []
        self.status = "initializing"
        self.lock = threading.Lock()
        
    def start_scan(self, total_tools):
        """Initialize dashboard for new scan"""
        self.scan_start_time = datetime.now()
        self.total_tools = total_tools
        self.completed_tools = 0
        self.critical_findings = []
        self.admin_panels_found = []
        self.status = "running"
        
    def update_progress(self, tool_name, status, findings=None, admin_panel=None):
        """Update dashboard with tool results"""
        with self.lock:
            self.completed_tools += 1
            progress_percent = (self.completed_tools / self.total_tools) * 100
            
            # Add to queue for real-time display
            result = {
                "tool": tool_name,
                "status": status,
                "progress": progress_percent,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }
            
            if findings:
                result["findings"] = findings
                if status in ["critical", "warning"]:
                    self.critical_findings.append({
                        "tool": tool_name,
                        "findings": findings
                    })
            
            if admin_panel:
                result["admin_panel"] = admin_panel
                self.admin_panels_found.append(admin_panel)
            
            self.results_queue.put(result)
    
    def display_dashboard(self):
        """Display real-time dashboard"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                EG-Tool Pro++ - Real-Time Dashboard                ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Progress bar
        progress_bar_width = 50
        progress = min(100, max(0, self.completed_tools / self.total_tools * 100))
        filled = int(progress_bar_width * progress / 100)
        bar = f"{Fore.GREEN}{'█' * filled}{Fore.WHITE}{'░' * (progress_bar_width - filled)}{Style.RESET_ALL}"
        
        print(f"\n  📊 Progress: {bar} {progress:.1f}% ({self.completed_tools}/{self.total_tools} tools)")
        
        # Scan duration
        if self.scan_start_time:
            duration = datetime.now() - self.scan_start_time
            mins, secs = divmod(duration.total_seconds(), 60)
            print(f"  ⏱️  Duration: {int(mins)}m {int(secs)}s")
        
        # Status
        status_icon = "🟢" if self.status == "completed" else "🟡" if self.status == "running" else "🔴"
        print(f"  {status_icon} Status: {self.status.title()}")
        
        # Critical findings count
        critical_count = len([f for f in self.critical_findings])
        if critical_count > 0:
            print(f"  ⚠️  Critical Findings: {Fore.RED}{critical_count}{Style.RESET_ALL}")
        else:
            print(f"  ✅ Critical Findings: {Fore.GREEN}0{Style.RESET_ALL}")
        
        # Admin panels found
        if self.admin_panels_found:
            print(f"  🔑 Admin Panels Found: {Fore.YELLOW}{len(self.admin_panels_found)}{Style.RESET_ALL}")
        
        # Recent results (last 5)
        print(f"\n  📋 Recent Results:")
        print(f"  {'─' * 60}")
        
        # Get recent results from queue
        recent_results = []
        while not self.results_queue.empty() and len(recent_results) < 5:
            recent_results.append(self.results_queue.get())
        
        for result in recent_results[-5:]:  # Show last 5
            status_icon = "✅" if result["status"] == "success" else "⚠️" if result["status"] == "warning" else "❌"
            color = Fore.GREEN if result["status"] == "success" else Fore.YELLOW if result["status"] == "warning" else Fore.RED
            
            print(f"  {status_icon} {color}{result['tool']:30} {result['timestamp']}{Style.RESET_ALL}")
            
            if "findings" in result and result["findings"]:
                for finding in result["findings"][:2]:  # Show first 2 findings
                    print(f"      • {finding[:50]}...")
            
            if "admin_panel" in result:
                print(f"      🔑 {Fore.YELLOW}Admin Panel: {result['admin_panel']}{Style.RESET_ALL}")
        
        print(f"\n  {'─' * 60}")
        
        # Real-time alerts
        if self.critical_findings and len(self.critical_findings) <= 3:
            print(f"  🚨 {Fore.RED}CRITICAL ALERTS:{Style.RESET_ALL}")
            for finding in self.critical_findings[-3:]:  # Last 3 critical findings
                print(f"      • {finding['tool']}: {finding['findings'][0][:40]}...")
        
        if self.admin_panels_found:
            print(f"  🔐 {Fore.YELLOW}ADMIN PANELS DISCOVERED:{Style.RESET_ALL}")
            for panel in self.admin_panels_found[:3]:  # First 3 admin panels
                print(f"      • {panel}")
        
        print(f"\n{Fore.CYAN}  Press Ctrl+C to stop scanning...{Style.RESET_ALL}")

class SecurityScanner:
    def __init__(self):
        self.target_url = ""
        self.target_ip = ""
        self.target_domain = ""
        self.results = {}
        self.dashboard = RealTimeDashboard()
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Define all tools with enhanced real-time feedback
        self.all_tools = {
            "recon": [
                {"name": "WHOIS Lookup", "function": self.whois_lookup, "critical": False},
                {"name": "DNS Enumeration", "function": self.dns_enumeration, "critical": False},
                {"name": "Subdomain Scanner", "function": self.subdomain_scan, "critical": True},
                {"name": "Port Scanner", "function": self.port_scan, "critical": True},
                {"name": "IP Geolocation", "function": self.ip_geolocation, "critical": False},
            ],
            "web": [
                {"name": "HTTP Headers Analysis", "function": self.http_headers_analysis, "critical": True},
                {"name": "SSL/TLS Scanner", "function": self.ssl_tls_scanner, "critical": True},
                {"name": "Technology Detection", "function": self.technology_detection, "critical": False},
                {"name": "Directory Bruteforce", "function": self.directory_bruteforce, "critical": True},
                {"name": "Sensitive File Discovery", "function": self.sensitive_file_discovery, "critical": True},
                {"name": "SQL Injection Tester", "function": self.sql_injection_test, "critical": True},
                {"name": "XSS Vulnerability Scanner", "function": self.xss_scanner, "critical": True},
                {"name": "CORS Misconfiguration", "function": self.cors_test, "critical": True},
                {"name": "Security Headers Check", "function": self.security_headers_check, "critical": True},
                {"name": "Admin Panel Finder", "function": self.admin_panel_finder, "critical": True},
            ],
            "advanced": [
                {"name": "WordPress Scanner", "function": self.wordpress_scanner, "critical": True},
                {"name": "CMS Detection", "function": self.cms_detection, "critical": False},
                {"name": "Backup File Finder", "function": self.backup_file_finder, "critical": True},
                {"name": "Git Repository Scanner", "function": self.git_scanner, "critical": True},
                {"name": "Open Redirect Tester", "function": self.open_redirect_test, "critical": True},
                {"name": "SSRF Tester", "function": self.ssrf_test, "critical": True},
            ]
        }
        
    def print_banner(self):
        """Display enhanced banner"""
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  ███████╗ ██████╗      ████████╗ ██████╗  ██████╗ ██╗      ██████╗  ║
║  ██╔════╝██╔════╝      ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔═══██╗ ║
║  █████╗  ██║    █████╗    ██║   ██║   ██║██║   ██║██║     ██║   ██║ ║
║  ██╔══╝  ██║    ╚════╝    ██║   ██║   ██║██║   ██║██║     ██║   ██║ ║
║  ███████╗╚██████╗         ██║   ╚██████╔╝╚██████╔╝███████╗╚██████╔╝ ║
║  ╚══════╝ ╚═════╝         ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ║
║                                                                      ║
║                    EG-Tool Pro++ v4.0                               ║
║            Real-Time Security Scanner with Dashboard                ║
║                        Developed by: EGHackers                      ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def get_target(self):
        """Get target website from user"""
        print(f"{Fore.YELLOW}[!] IMPORTANT LEGAL DISCLAIMER:{Style.RESET_ALL}")
        print(f"{Fore.RED}══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.WHITE}1. Use this tool ONLY on websites you own or have explicit permission to test")
        print("2. Unauthorized scanning is illegal and unethical")
        print("3. You are solely responsible for your actions")
        print("4. This tool is for educational and authorized security testing only")
        print(f"══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        consent = input(f"{Fore.YELLOW}[?] Do you accept these terms? (yes/no): {Style.RESET_ALL}").strip().lower()
        
        if consent not in ["yes", "y", "yep", "yeah"]:
            print(f"{Fore.RED}[✗] Terms must be accepted to continue{Style.RESET_ALL}")
            sys.exit(1)
        
        print(f"\n{Fore.GREEN}[✓] Terms accepted{Style.RESET_ALL}")
        
        # Get target URL
        while True:
            self.target_url = input(f"{Fore.CYAN}[?] Enter target URL (e.g., https://example.com): {Style.RESET_ALL}").strip()
            
            if not self.target_url:
                print(f"{Fore.RED}[✗] Target URL is required{Style.RESET_ALL}")
                continue
            
            # Add protocol if missing
            if not self.target_url.startswith(('http://', 'https://')):
                self.target_url = 'https://' + self.target_url
                print(f"{Fore.YELLOW}[!] Added https:// automatically{Style.RESET_ALL}")
            
            try:
                # Validate URL
                parsed_url = urlparse(self.target_url)
                if not parsed_url.netloc:
                    print(f"{Fore.RED}[✗] Invalid URL format{Style.RESET_ALL}")
                    continue
                
                self.target_domain = parsed_url.netloc
                
                # Try to resolve IP
                try:
                    self.target_ip = socket.gethostbyname(self.target_domain)
                    print(f"{Fore.GREEN}[✓] Target resolved to IP: {self.target_ip}{Style.RESET_ALL}")
                except socket.gaierror:
                    print(f"{Fore.YELLOW}[!] Could not resolve domain to IP{Style.RESET_ALL}")
                    self.target_ip = None
                
                # Quick connectivity test
                try:
                    response = requests.get(self.target_url, timeout=5, allow_redirects=True, verify=False)
                    if response.status_code < 500:
                        print(f"{Fore.GREEN}[✓] Target is reachable (Status: {response.status_code}){Style.RESET_ALL}")
                        break
                    else:
                        print(f"{Fore.YELLOW}[!] Target returned status: {response.status_code}{Style.RESET_ALL}")
                        continue_option = input(f"{Fore.YELLOW}[?] Continue anyway? (yes/no): {Style.RESET_ALL}").strip().lower()
                        if continue_option in ["yes", "y"]:
                            break
                except requests.exceptions.RequestException as e:
                    print(f"{Fore.YELLOW}[!] Connectivity issue: {e}{Style.RESET_ALL}")
                    continue_option = input(f"{Fore.YELLOW}[?] Continue with limited scans? (yes/no): {Style.RESET_ALL}").strip().lower()
                    if continue_option in ["yes", "y"]:
                        break
                        
            except Exception as e:
                print(f"{Fore.RED}[✗] Error: {e}{Style.RESET_ALL}")
    
    def select_tools(self):
        """Let user select which tools to run"""
        print(f"\n{Fore.CYAN}[*] Available Scanning Tools:{Style.RESET_ALL}")
        
        categories = {
            "1": ("Reconnaissance Tools", "recon"),
            "2": ("Web Application Tools", "web"),
            "3": ("Advanced Tools", "advanced"),
            "4": ("Full Scan (All Tools)", "all")
        }
        
        for key, (name, _) in categories.items():
            tool_count = len(self.all_tools[categories[key][1]]) if key != "4" else sum(len(tools) for tools in self.all_tools.values())
            print(f"  {Fore.YELLOW}{key}. {name} ({tool_count} tools){Style.RESET_ALL}")
        
        selection = input(f"\n{Fore.CYAN}[?] Select category (1-4) or 'c' for custom selection: {Style.RESET_ALL}").strip().lower()
        
        if selection == "4" or selection == "all":
            # Select all tools
            self.available_tools = []
            for category in self.all_tools.values():
                self.available_tools.extend(category)
            print(f"{Fore.GREEN}[✓] Selected all {len(self.available_tools)} tools{Style.RESET_ALL}")
        
        elif selection == "c":
            # Custom selection
            self.custom_tool_selection()
        
        elif selection in categories:
            category = categories[selection][1]
            self.available_tools = self.all_tools[category]
            print(f"{Fore.GREEN}[✓] Selected {categories[selection][0]} ({len(self.available_tools)} tools){Style.RESET_ALL}")
        
        else:
            print(f"{Fore.YELLOW}[!] Defaulting to Web Application tools{Style.RESET_ALL}")
            self.available_tools = self.all_tools["web"]
    
    def run_scans_with_dashboard(self):
        """Run scans with real-time dashboard"""
        print(f"\n{Fore.CYAN}[*] Initializing scan on {self.target_url}{Style.RESET_ALL}")
        
        # Start dashboard
        total_tools = len(self.available_tools)
        self.dashboard.start_scan(total_tools)
        
        # Start dashboard update thread
        dashboard_thread = threading.Thread(target=self.update_dashboard_periodically)
        dashboard_thread.daemon = True
        dashboard_thread.start()
        
        # Create results directory
        results_dir = self.create_results_directory()
        
        # Run scans
        failed_tools = []
        
        for tool in self.available_tools:
            try:
                result = self.run_single_scan(tool)
                
                # Update dashboard with results
                findings = []
                admin_panel = None
                
                if result.status != "success":
                    findings.append(f"{result.status}: {result.output[:100]}")
                
                if "admin" in tool['name'].lower() and result.status == "success":
                    admin_panel = f"Found at {self.target_url}"
                
                self.dashboard.update_progress(
                    tool['name'], 
                    result.status,
                    findings,
                    admin_panel
                )
                
                self.results[tool['name']] = result
                self.save_tool_result(results_dir, tool['name'], result)
                
                # Small delay to allow dashboard updates
                time.sleep(0.1)
                
            except Exception as e:
                print(f"{Fore.RED}[✗] {tool['name']} failed: {e}{Style.RESET_ALL}")
                failed_tools.append(tool['name'])
                self.dashboard.update_progress(tool['name'], "error", [f"Error: {str(e)}"])
        
        # Mark scan as completed
        self.dashboard.status = "completed"
        time.sleep(1)  # Allow final dashboard update
        
        # Generate summary report
        summary_file = self.generate_summary_report(results_dir, failed_tools)
        
        return results_dir, summary_file, failed_tools
    
    def update_dashboard_periodically(self):
        """Update dashboard every second while scanning"""
        while self.dashboard.status == "running":
            self.dashboard.display_dashboard()
            time.sleep(1)
    
    def run_single_scan(self, tool):
        """Run a single tool scan with enhanced output"""
        try:
            print(f"\n{Fore.BLUE}[→] Running: {tool['name']}{Style.RESET_ALL}")
            result = tool['function']()
            
            # Display important findings immediately
            if result.status != "success":
                status_icon = "⚠️" if result.status == "warning" else "❌"
                color = Fore.YELLOW if result.status == "warning" else Fore.RED
                print(f"  {status_icon} {color}Important: {result.output[:100]}...{Style.RESET_ALL}")
            
            return result
        except Exception as e:
            return ToolResult(tool['name'], "error", f"Tool failed: {str(e)}")
    
    # ============================================================================
    # ENHANCED TOOL IMPLEMENTATIONS WITH REAL-TIME FEEDBACK
    # ============================================================================
    
    def admin_panel_finder(self):
        """Enhanced Admin Panel Finder with comprehensive search"""
        admin_paths = [
            "/admin", "/administrator", "/wp-admin", "/wp-login.php",
            "/admin/login", "/admincp", "/controlpanel", "/dashboard",
            "/manager", "/management", "/console", "/backend", "/backoffice",
            "/cpanel", "/webadmin", "/admin_area", "/panel", "/login",
            "/user/login", "/admin/login.php", "/admin/index.php",
            "/admin/admin.php", "/admin/account.php", "/admin/control.php",
            "/admin/home.php", "/admin/main.php", "/admin/manage.php",
            "/admin/panel.php", "/admin/admin_login.php", "/admin/controlpanel.php",
            "/cms", "/system", "/root", "/superadmin", "/secret", "/hidden",
            "/private", "/secure", "/auth", "/authentication", "/signin",
            "/sign-in", "/member", "/members", "/useradmin", "/user-admin",
            "/user", "/users", "/account", "/accounts", "/admin123", "/admin1",
            "/admin2", "/admin3", "/admin4", "/admin5", "/sysadmin", "/sys-admin",
            "/myadmin", "/my-admin", "/server", "/servers", "/client", "/clients",
            "/moderator", "/moderators", "/staff", "/staffs", "/employee", "/employees",
            "/owner", "/owners", "/director", "/directors", "/webmaster", "/webmasters",
            "/config", "/configuration", "/setup", "/install", "/installation",
            "/update", "/updates", "/upgrade", "/upgrades", "/debug", "/test",
            "/testing", "/demo", "/demos", "/beta", "/staging", "/dev", "/development",
            "/phpmyadmin", "/pma", "/myadmin", "/mysql", "/sql", "/database",
            "/db", "/dbadmin", "/dba", "/pgadmin", "/postgres", "/oracle",
            "/mongodb", "/redis", "/memcache", "/elastic", "/kibana",
            "/grafana", "/prometheus", "/jenkins", "/gitlab", "/bitbucket",
            "/redmine", "/jira", "/confluence", "/sonarqube", "/nexus",
            "/artifactory", "/harbor", "/rancher", "/kubernetes", "/k8s",
            "/openshift", "/docker", "/portainer", "/swagger", "/api-docs",
            "/graphql", "/graphiql", "/playground", "/voyager", "/altair",
            "/hasura", "/prisma", "/adminer", "/adminer.php", "/phppgadmin",
            "/phpsqliteadmin", "/sqlitemanager", "/websql", "/web-sql",
            "/webdb", "/web-db", "/dbadmin.php", "/phpMyAdmin", "/phpmyadmin/",
            "/administrator/index.php", "/administrator/login.php",
            "/administrator/admin.php", "/joomla/administrator",
            "/drupal/admin", "/magento/admin", "/prestashop/admin",
            "/opencart/admin", "/woocommerce/wp-admin", "/wordpress/wp-admin",
            "/wordpress/wp-login.php", "/wp/wp-admin", "/wp/wp-login.php",
            "/blog/wp-admin", "/blog/wp-login.php", "/cms/wp-admin",
            "/cms/wp-login.php", "/site/wp-admin", "/site/wp-login.php",
            "/web/wp-admin", "/web/wp-login.php", "/new/wp-admin",
            "/new/wp-login.php", "/old/wp-admin", "/old/wp-login.php",
            "/test/wp-admin", "/test/wp-login.php", "/backup/wp-admin",
            "/backup/wp-login.php", "/temp/wp-admin", "/temp/wp-login.php",
            "/tmp/wp-admin", "/tmp/wp-login.php", "/admin12345",
            "/admin123456", "/admin1234567", "/admin12345678",
            "/admin123456789", "/admin1234567890"
        ]
        
        found_panels = []
        
        print(f"  {Fore.CYAN}[*] Scanning for admin panels...{Style.RESET_ALL}")
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_path = {}
            
            for path in admin_paths:
                future = executor.submit(self.check_admin_path, path)
                future_to_path[future] = path
            
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result["found"]:
                        found_panels.append(result)
                        # Real-time alert
                        print(f"  {Fore.GREEN}[✓] Found: {path} (Status: {result['status']}){Style.RESET_ALL}")
                except:
                    pass
        
        output = f"Admin Panel Finder Results for {self.target_url}:\n\n"
        
        if found_panels:
            output += f"🚨 {Fore.RED}FOUND {len(found_panels)} ADMIN PANELS:{Style.RESET_ALL}\n\n"
            for panel in found_panels:
                output += f"🔐 {Fore.YELLOW}{panel['path']}{Style.RESET_ALL}\n"
                output += f"   URL: {panel['url']}\n"
                output += f"   Status: {panel['status']}\n"
                output += f"   Size: {panel['size']} bytes\n"
                
                # Check for login forms
                if panel['login_form']:
                    output += f"   {Fore.GREEN}✓ Login form detected{Style.RESET_ALL}\n"
                
                # Check for common CMS admin panels
                if any(cms in panel['path'].lower() for cms in ['wp-admin', 'wordpress']):
                    output += f"   {Fore.BLUE}→ WordPress Admin Panel{Style.RESET_ALL}\n"
                elif 'joomla' in panel['path'].lower():
                    output += f"   {Fore.BLUE}→ Joomla Admin Panel{Style.RESET_ALL}\n"
                elif 'drupal' in panel['path'].lower():
                    output += f"   {Fore.BLUE}→ Drupal Admin Panel{Style.RESET_ALL}\n"
                elif 'magento' in panel['path'].lower():
                    output += f"   {Fore.BLUE}→ Magento Admin Panel{Style.RESET_ALL}\n"
                
                output += "\n"
            
            output += f"\n⚠ {Fore.YELLOW}SECURITY RECOMMENDATIONS:{Style.RESET_ALL}\n"
            output += "1. Change default admin paths\n"
            output += "2. Implement IP whitelisting\n"
            output += "3. Use strong authentication\n"
            output += "4. Enable login attempt limiting\n"
            output += "5. Monitor access logs regularly\n"
            
            status = "critical"
        else:
            output += f"{Fore.GREEN}✅ No admin panels found{Style.RESET_ALL}\n"
            output += f"Scanned {len(admin_paths)} common admin paths\n"
            status = "success"
        
        return ToolResult("Admin Panel Finder", status, output, {
            "found_panels": found_panels,
            "total_scanned": len(admin_paths)
        })
    
    def check_admin_path(self, path):
        """Check a single admin path"""
        test_url = urljoin(self.target_url, path)
        
        try:
            response = requests.get(
                test_url, 
                timeout=3, 
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            # Check if page exists and looks like an admin panel
            if response.status_code < 400:
                html = response.text.lower()
                
                # Check for login form indicators
                login_indicators = [
                    '<form', 'login', 'password', 'username', 'sign in',
                    'admin', 'administrator', 'log in', 'signin', 'auth',
                    'authentication', 'wp-login', 'user_login', 'passwd'
                ]
                
                has_login_form = any(indicator in html for indicator in login_indicators)
                
                return {
                    "found": True,
                    "path": path,
                    "url": test_url,
                    "status": response.status_code,
                    "size": len(response.content),
                    "login_form": has_login_form
                }
        
        except requests.exceptions.RequestException:
            pass
        
        return {"found": False, "path": path}
    
    def whois_lookup(self):
        """WHOIS lookup with real-time display"""
        print(f"  {Fore.CYAN}[*] Performing WHOIS lookup...{Style.RESET_ALL}")
        
        try:
            # For Termux, we'll use whois command
            import subprocess
            
            result = subprocess.run(
                ['whois', self.target_domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout[:500]  # First 500 chars
                
                # Extract important information
                important_info = []
                
                # Look for important fields
                important_fields = ['Domain Name:', 'Creation Date:', 'Updated Date:', 
                                  'Registry Expiry Date:', 'Registrar:', 'Name Server:']
                
                for line in output.split('\n'):
                    for field in important_fields:
                        if field in line:
                            important_info.append(line.strip())
                            break
                
                # Display important info immediately
                if important_info:
                    print(f"  {Fore.GREEN}[✓] Found WHOIS information:{Style.RESET_ALL}")
                    for info in important_info[:5]:  # Show first 5 important lines
                        print(f"      {info}")
                
                return ToolResult("WHOIS Lookup", "success", output, {
                    "important_fields": important_info
                })
            else:
                return ToolResult("WHOIS Lookup", "warning", "WHOIS lookup failed or timed out")
                
        except Exception as e:
            return ToolResult("WHOIS Lookup", "warning", f"WHOIS error: {str(e)}")
    
    def sql_injection_test(self):
        """SQL Injection test with real-time results"""
        print(f"  {Fore.CYAN}[*] Testing for SQL Injection vulnerabilities...{Style.RESET_ALL}")
        
        test_params = ["id", "page", "user", "product", "category"]
        vulnerable_params = []
        
        for param in test_params:
            payloads = [
                f"{param}='",
                f"{param}=\"",
                f"{param}=1' OR '1'='1",
                f"{param}=1 OR 1=1",
                f"{param}=1' AND SLEEP(2)--"
            ]
            
            for payload in payloads:
                test_url = f"{self.target_url}?{payload}"
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    # Check for SQL error indicators
                    error_indicators = [
                        "sql", "mysql", "syntax", "database", "error",
                        "warning", "exception", "unclosed", "quote",
                        "you have an error", "mysql_fetch", "mysqli_",
                        "postgresql", "oracle", "sqlite", "mssql"
                    ]
                    
                    page_text = response.text.lower()
                    
                    for indicator in error_indicators:
                        if indicator in page_text:
                            if param not in vulnerable_params:
                                vulnerable_params.append(param)
                            
                            # Real-time alert
                            print(f"  {Fore.RED}[!] Potential SQLi in parameter: {param}{Style.RESET_ALL}")
                            print(f"      Payload: {payload}")
                            print(f"      Indicator: {indicator}")
                            break
                    
                except:
                    continue
        
        output = f"SQL Injection Test Results for {self.target_url}:\n\n"
        
        if vulnerable_params:
            output += f"🚨 {Fore.RED}POTENTIAL SQL INJECTION VULNERABILITIES:{Style.RESET_ALL}\n\n"
            output += f"Affected parameters: {', '.join(vulnerable_params)}\n"
            output += f"\n⚠ {Fore.YELLOW}RECOMMENDATIONS:{Style.RESET_ALL}\n"
            output += "1. Use parameterized queries\n"
            output += "2. Implement input validation\n"
            output += "3. Use stored procedures\n"
            output += "4. Apply principle of least privilege\n"
            output += "5. Use Web Application Firewall\n"
            
            status = "critical"
        else:
            output += f"{Fore.GREEN}✅ No SQL Injection vulnerabilities detected{Style.RESET_ALL}\n"
            output += f"Tested parameters: {', '.join(test_params)}\n"
            status = "success"
        
        return ToolResult("SQL Injection Tester", status, output, {
            "vulnerable_params": vulnerable_params,
            "tested_params": test_params
        })
    
    def xss_scanner(self):
        """XSS scanner with real-time feedback"""
        print(f"  {Fore.CYAN}[*] Testing for XSS vulnerabilities...{Style.RESET_ALL}")
        
        test_params = ["q", "search", "name", "email", "message"]
        vulnerable_params = []
        
        for param in test_params:
            payloads = [
                f"{param}=<script>alert('XSS')</script>",
                f"{param}=\"><script>alert('XSS')</script>",
                f"{param}='><script>alert('XSS')</script>",
                f"{param}=javascript:alert('XSS')",
                f"{param}=<img src=x onerror=alert('XSS')>"
            ]
            
            for payload in payloads[:2]:  # Test only first 2 payloads
                test_url = f"{self.target_url}?{payload}"
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    # Check if payload is reflected in response
                    if payload.split('=')[1] in response.text:
                        if param not in vulnerable_params:
                            vulnerable_params.append(param)
                        
                        # Real-time alert
                        print(f"  {Fore.RED}[!] Potential XSS in parameter: {param}{Style.RESET_ALL}")
                        print(f"      Payload: {payload.split('=')[1][:20]}...")
                        break
                    
                except:
                    continue
        
        output = f"XSS Scanner Results for {self.target_url}:\n\n"
        
        if vulnerable_params:
            output += f"🚨 {Fore.RED}POTENTIAL XSS VULNERABILITIES:{Style.RESET_ALL}\n\n"
            output += f"Affected parameters: {', '.join(vulnerable_params)}\n"
            output += f"\n⚠ {Fore.YELLOW}RECOMMENDATIONS:{Style.RESET_ALL}\n"
            output += "1. Implement input validation\n"
            output += "2. Use output encoding\n"
            output += "3. Enable Content Security Policy (CSP)\n"
            output += "4. Use security libraries (DOMPurify, etc.)\n"
            output += "5. Regular security testing\n"
            
            status = "critical"
        else:
            output += f"{Fore.GREEN}✅ No XSS vulnerabilities detected{Style.RESET_ALL}\n"
            output += f"Tested parameters: {', '.join(test_params)}\n"
            status = "success"
        
        return ToolResult("XSS Vulnerability Scanner", status, output, {
            "vulnerable_params": vulnerable_params,
            "tested_params": test_params
        })
    
    def directory_bruteforce(self):
        """Enhanced directory brute force with real-time results"""
        print(f"  {Fore.CYAN}[*] Brute forcing directories...{Style.RESET_ALL}")
        
        # Common directories for various technologies
        common_dirs = [
            "/admin", "/administrator", "/wp-admin", "/wp-login.php",
            "/login", "/logout", "/register", "/signup", "/signin",
            "/dashboard", "/controlpanel", "/cpanel", "/webadmin",
            "/config", "/configuration", "/backup", "/backups",
            "/database", "/db", "/sql", "/mysql", "/phpmyadmin",
            "/test", "/testing", "/dev", "/development", "/staging",
            "/api", "/api/v1", "/api/v2", "/graphql", "/rest",
            "/uploads", "/upload", "/files", "/images", "/img",
            "/css", "/js", "/assets", "/static", "/media",
            "/download", "/downloads", "/docs", "/documents",
            "/vendor", "/vendors", "/lib", "/libs", "/library",
            "/include", "/includes", "/src", "/source", "/sources",
            "/tmp", "/temp", "/cache", "/caches", "/session",
            "/sessions", "/logs", "/log", "/error", "/errors",
            "/debug", "/debugging", "/console", "/terminal",
            "/shell", "/cmd", "/command", "/exec", "/execute",
            "/system", "/systems", "/app", "/apps", "/application",
            "/applications", "/webapp", "/webapps", "/service",
            "/services", "/api-docs", "/swagger", "/swagger-ui",
            "/redoc", "/graphiql", "/voyager", "/altair",
            "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
            "/.env", "/.git", "/.svn", "/.hg", "/.bzr",
            "/.well-known", "/.well-known/security.txt",
            "/robots.txt", "/sitemap.xml", "/sitemap.txt",
            "/sitemap", "/sitemap_index.xml", "/sitemap-index.xml",
            "/crossdomain.xml", "/clientaccesspolicy.xml"
        ]
        
        found_dirs = []
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dir = {}
            
            for directory in common_dirs[:50]:  # Limit to first 50 for speed
                future = executor.submit(self.check_directory, directory)
                future_to_dir[future] = directory
            
            for future in as_completed(future_to_dir):
                directory = future_to_dir[future]
                try:
                    result = future.result()
                    if result["found"]:
                        found_dirs.append(result)
                        # Real-time alert for sensitive directories
                        if any(sensitive in directory for sensitive in ['admin', 'config', 'backup', '.env', '.git']):
                            print(f"  {Fore.RED}[!] Sensitive directory found: {directory}{Style.RESET_ALL}")
                        else:
                            print(f"  {Fore.GREEN}[✓] Found: {directory}{Style.RESET_ALL}")
                except:
                    pass
        
        output = f"Directory Bruteforce Results for {self.target_url}:\n\n"
        
        if found_dirs:
            output += f"📁 {Fore.YELLOW}FOUND {len(found_dirs)} DIRECTORIES:{Style.RESET_ALL}\n\n"
            
            # Categorize directories
            sensitive_dirs = [d for d in found_dirs if any(s in d['path'] for s in ['admin', 'config', 'backup', '.env', '.git'])]
            api_dirs = [d for d in found_dirs if 'api' in d['path']]
            asset_dirs = [d for d in found_dirs if any(s in d['path'] for s in ['css', 'js', 'img', 'assets', 'static'])]
            other_dirs = [d for d in found_dirs if d not in sensitive_dirs + api_dirs + asset_dirs]
            
            if sensitive_dirs:
                output += f"🔴 {Fore.RED}SENSITIVE DIRECTORIES ({len(sensitive_dirs)}):{Style.RESET_ALL}\n"
                for dir_info in sensitive_dirs:
                    output += f"   {dir_info['path']} ({dir_info['status']}) - {dir_info['size']} bytes\n"
                output += "\n"
            
            if api_dirs:
                output += f"🔵 {Fore.BLUE}API ENDPOINTS ({len(api_dirs)}):{Style.RESET_ALL}\n"
                for dir_info in api_dirs:
                    output += f"   {dir_info['path']} ({dir_info['status']})\n"
                output += "\n"
            
            if asset_dirs:
                output += f"🟢 {Fore.GREEN}ASSET DIRECTORIES ({len(asset_dirs)}):{Style.RESET_ALL}\n"
                for dir_info in asset_dirs:
                    output += f"   {dir_info['path']} ({dir_info['status']})\n"
                output += "\n"
            
            if other_dirs:
                output += f"⚪ OTHER DIRECTORIES ({len(other_dirs)}):{Style.RESET_ALL}\n"
                for dir_info in other_dirs[:10]:  # Show first 10
                    output += f"   {dir_info['path']} ({dir_info['status']})\n"
                if len(other_dirs) > 10:
                    output += f"   ... and {len(other_dirs) - 10} more\n"
            
            status = "warning" if sensitive_dirs else "success"
        else:
            output += f"{Fore.GREEN}✅ No directories found{Style.RESET_ALL}\n"
            output += f"Scanned {len(common_dirs[:50])} common directories\n"
            status = "success"
        
        return ToolResult("Directory Bruteforce", status, output, {
            "found_dirs": found_dirs,
            "sensitive_count": len([d for d in found_dirs if any(s in d['path'] for s in ['admin', 'config', 'backup', '.env', '.git'])])
        })
    
    def check_directory(self, directory):
        """Check a single directory"""
        test_url = urljoin(self.target_url, directory)
        
        try:
            response = requests.get(
                test_url, 
                timeout=2, 
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            if response.status_code < 400:
                return {
                    "found": True,
                    "path": directory,
                    "url": test_url,
                    "status": response.status_code,
                    "size": len(response.content)
                }
        
        except requests.exceptions.RequestException:
            pass
        
        return {"found": False, "path": directory}
    
    def port_scan(self):
        """Enhanced port scanner with service detection"""
        print(f"  {Fore.CYAN}[*] Scanning ports...{Style.RESET_ALL}")
        
        if not self.target_ip:
            return ToolResult("Port Scanner", "error", "No IP address available for scanning")
        
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt2",
            9000: "PHP-FPM",
            9200: "Elasticsearch",
            27017: "MongoDB"
        }
        
        open_ports = []
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    open_ports.append((port, service))
                    # Real-time alert for critical ports
                    if port in [21, 22, 23, 25, 3306, 3389]:
                        print(f"  {Fore.RED}[!] Critical port open: {port} ({service}){Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.GREEN}[✓] Port open: {port} ({service}){Style.RESET_ALL}")
                
                sock.close()
            except:
                pass
        
        output = f"Port Scan Results for {self.target_ip}:\n\n"
        
        if open_ports:
            output += f"🔓 {Fore.YELLOW}OPEN PORTS ({len(open_ports)}):{Style.RESET_ALL}\n\n"
            output += f"{'PORT':<8} {'SERVICE':<15} {'STATUS':<10}\n"
            output += f"{'-'*35}\n"
            
            for port, service in open_ports:
                status = "CRITICAL" if port in [21, 22, 23, 25, 3306, 3389] else "OPEN"
                color = Fore.RED if status == "CRITICAL" else Fore.YELLOW
                output += f"{port:<8} {service:<15} {color}{status}{Style.RESET_ALL}\n"
            
            # Security analysis
            output += f"\n⚠ {Fore.YELLOW}SECURITY ANALYSIS:{Style.RESET_ALL}\n"
            
            critical_services = [s for p, s in open_ports if p in [21, 22, 23, 25, 3306, 3389]]
            if critical_services:
                output += f"🔴 {Fore.RED}Critical services exposed:{Style.RESET_ALL}\n"
                for service in critical_services:
                    output += f"   - {service}\n"
            
            # Recommendations
            output += f"\n🔒 {Fore.GREEN}RECOMMENDATIONS:{Style.RESET_ALL}\n"
            output += "1. Close unnecessary ports\n"
            output += "2. Use firewall rules\n"
            output += "3. Implement network segmentation\n"
            output += "4. Regular port scanning\n"
            output += "5. Monitor network traffic\n"
            
            status = "warning" if open_ports else "success"
        else:
            output += f"{Fore.GREEN}✅ No open ports detected{Style.RESET_ALL}\n"
            output += f"Scanned {len(common_ports)} common ports\n"
            status = "success"
        
        return ToolResult("Port Scanner", status, output, {
            "open_ports": open_ports,
            "critical_ports": [p for p, s in open_ports if p in [21, 22, 23, 25, 3306, 3389]]
        })
    
    def ssl_tls_scanner(self):
        """Enhanced SSL/TLS scanner with grade assessment"""
        print(f"  {Fore.CYAN}[*] Analyzing SSL/TLS configuration...{Style.RESET_ALL}")
        
        try:
            import ssl
            import OpenSSL
            
            parsed = urlparse(self.target_url)
            if parsed.scheme != 'https':
                output = f"{Fore.YELLOW}⚠ Target not using HTTPS{Style.RESET_ALL}\n"
                return ToolResult("SSL/TLS Scanner", "warning", output)
            
            hostname = parsed.netloc.split(':')[0]
            
            # Get certificate
            cert = ssl.get_server_certificate((hostname, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Analyze certificate
            subject = x509.get_subject()
            issuer = x509.get_issuer()
            
            # Validity period
            not_before = x509.get_notBefore().decode('utf-8')
            not_after = x509.get_notAfter().decode('utf-8')
            
            from datetime import datetime
            fmt = '%Y%m%d%H%M%SZ'
            valid_from = datetime.strptime(not_before, fmt)
            valid_to = datetime.strptime(not_after, fmt)
            days_left = (valid_to - datetime.now()).days
            
            # Check for issues
            issues = []
            
            if days_left < 30:
                issues.append("Certificate expiring soon")
                print(f"  {Fore.RED}[!] Certificate expires in {days_left} days{Style.RESET_ALL}")
            
            if days_left < 0:
                issues.append("Certificate expired")
            
            # Check subject alternative names
            san = ""
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if 'subjectAltName' in str(ext.get_short_name()):
                    san = str(ext)
                    break
            
            output = f"SSL/TLS Certificate Analysis for {hostname}:\n\n"
            
            output += f"🔐 {Fore.CYAN}CERTIFICATE INFORMATION:{Style.RESET_ALL}\n"
            output += f"   Subject: {subject.CN if subject.CN else 'N/A'}\n"
            output += f"   Issuer: {issuer.CN if issuer.CN else 'N/A'}\n"
            output += f"   Valid From: {valid_from.strftime('%Y-%m-%d')}\n"
            output += f"   Valid Until: {valid_to.strftime('%Y-%m-%d')}\n"
            output += f"   Days Remaining: {days_left}\n"
            
            if san:
                output += f"   Subject Alternative Names: {san[:100]}...\n"
            
            # Grade calculation (simplified)
            grade = "A"
            if issues:
                grade = "C" if days_left < 0 else "B"
            
            output += f"\n📊 {Fore.CYAN}SECURITY GRADE: {Fore.GREEN}{grade}{Style.RESET_ALL}\n"
            
            if issues:
                output += f"\n⚠ {Fore.YELLOW}ISSUES DETECTED:{Style.RESET_ALL}\n"
                for issue in issues:
                    output += f"   • {issue}\n"
            
            output += f"\n🔒 {Fore.GREEN}RECOMMENDATIONS:{Style.RESET_ALL}\n"
            output += "1. Renew certificate before expiration\n"
            output += "2. Use strong encryption (TLS 1.2/1.3)\n"
            output += "3. Implement HSTS\n"
            output += "4. Disable weak ciphers\n"
            output += "5. Regular SSL testing\n"
            
            status = "warning" if issues else "success"
            
            return ToolResult("SSL/TLS Scanner", status, output, {
                "grade": grade,
                "days_remaining": days_left,
                "issues": issues,
                "subject": str(subject),
                "issuer": str(issuer)
            })
            
        except Exception as e:
            output = f"SSL/TLS Scanner error: {str(e)}\n"
            return ToolResult("SSL/TLS Scanner", "error", output)
    
    # ============================================================================
    # OTHER TOOL IMPLEMENTATIONS (simplified for brevity)
    # ============================================================================
    
    def dns_enumeration(self):
        """DNS enumeration"""
        print(f"  {Fore.CYAN}[*] Enumerating DNS records...{Style.RESET_ALL}")
        
        try:
            import dns.resolver
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            results = {}
            
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(self.target_domain, rtype)
                    results[rtype] = [str(r) for r in answers]
                    
                    # Display important records
                    if rtype in ['A', 'MX', 'TXT']:
                        print(f"  {Fore.GREEN}[✓] {rtype} records found: {len(answers)}{Style.RESET_ALL}")
                        
                except:
                    results[rtype] = []
            
            output = f"DNS Records for {self.target_domain}:\n\n"
            
            for rtype, values in results.items():
                if values:
                    output += f"{rtype}:\n"
                    for value in values[:3]:  # Show first 3 values
                        output += f"  {value}\n"
                    if len(values) > 3:
                        output += f"  ... and {len(values)-3} more\n"
                    output += "\n"
            
            return ToolResult("DNS Enumeration", "success", output, results)
            
        except Exception as e:
            output = f"DNS Enumeration failed: {str(e)}\n"
            return ToolResult("DNS Enumeration", "warning", output)
    
    def subdomain_scan(self):
        """Subdomain scanner"""
        print(f"  {Fore.CYAN}[*] Scanning for subdomains...{Style.RESET_ALL}")
        
        common_subs = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging",
            "api", "blog", "shop", "store", "support", "portal", "webmail",
            "secure", "vpn", "ns1", "ns2", "mx", "cdn", "static",
            "assets", "img", "images", "media", "download", "uploads"
        ]
        
        found_subs = []
        
        for sub in common_subs:
            test_domain = f"{sub}.{self.target_domain}"
            try:
                socket.gethostbyname(test_domain)
                found_subs.append(test_domain)
                print(f"  {Fore.GREEN}[✓] Found: {test_domain}{Style.RESET_ALL}")
            except:
                pass
        
        output = f"Subdomain Scan Results for {self.target_domain}:\n\n"
        
        if found_subs:
            output += f"🌐 {Fore.YELLOW}FOUND {len(found_subs)} SUBDOMAINS:{Style.RESET_ALL}\n\n"
            for sub in found_subs:
                output += f"  • {sub}\n"
            
            output += f"\n⚠ {Fore.YELLOW}SECURITY NOTE:{Style.RESET_ALL}\n"
            output += "Each subdomain is a potential attack vector.\n"
            output += "Ensure all subdomains are properly secured.\n"
            
            status = "warning"
        else:
            output += f"{Fore.GREEN}✅ No subdomains found{Style.RESET_ALL}\n"
            status = "success"
        
        return ToolResult("Subdomain Scanner", status, output, {
            "found_subs": found_subs,
            "total_scanned": len(common_subs)
        })
    
    def sensitive_file_discovery(self):
        """Sensitive file discovery"""
        print(f"  {Fore.CYAN}[*] Looking for sensitive files...{Style.RESET_ALL}")
        
        sensitive_files = [
            ".env", ".git/config", ".htpasswd", ".htaccess",
            "config.php", "config.json", "config.yaml",
            "database.sql", "backup.zip", "backup.tar",
            "wp-config.php", "settings.py", "secrets.json",
            "docker-compose.yml", "dockerfile", "compose.yaml",
            "package.json", "composer.json", "pom.xml",
            "web.config", "application.properties",
            "credentials.json", "key.pem", "cert.pem",
            "id_rsa", "id_dsa", "authorized_keys",
            "known_hosts", "bash_history", "mysql_history"
        ]
        
        found_files = []
        
        for file in sensitive_files:
            test_url = urljoin(self.target_url, file)
            try:
                response = requests.get(test_url, timeout=2, verify=False)
                if response.status_code == 200 and len(response.content) > 0:
                    found_files.append({
                        "file": file,
                        "url": test_url,
                        "size": len(response.content)
                    })
                    
                    # Real-time critical alert
                    if any(ext in file for ext in ['.env', '.git', 'config', 'key', 'secret']):
                        print(f"  {Fore.RED}[!] CRITICAL: Sensitive file found: {file}{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.YELLOW}[!] Sensitive file found: {file}{Style.RESET_ALL}")
            except:
                pass
        
        output = f"Sensitive File Discovery for {self.target_url}:\n\n"
        
        if found_files:
            output += f"🚨 {Fore.RED}FOUND {len(found_files)} SENSITIVE FILES:{Style.RESET_ALL}\n\n"
            
            for file_info in found_files:
                output += f"🔴 {file_info['file']}\n"
                output += f"   URL: {file_info['url']}\n"
                output += f"   Size: {file_info['size']} bytes\n\n"
            
            output += f"⚠ {Fore.RED}CRITICAL SECURITY ISSUE:{Style.RESET_ALL}\n"
            output += "Sensitive files should never be publicly accessible!\n\n"
            
            output += f"🔒 {Fore.GREEN}IMMEDIATE ACTIONS REQUIRED:{Style.RESET_ALL}\n"
            output += "1. Remove these files from public access\n"
            output += "2. Rotate all exposed credentials/keys\n"
            output += "3. Review server configuration\n"
            output += "4. Implement proper access controls\n"
            output += "5. Audit all file permissions\n"
            
            status = "critical"
        else:
            output += f"{Fore.GREEN}✅ No sensitive files found{Style.RESET_ALL}\n"
            status = "success"
        
        return ToolResult("Sensitive File Discovery", status, output, {
            "found_files": found_files
        })
    
    # ============================================================================
    # UTILITY METHODS
    # ============================================================================
    
    def create_results_directory(self):
        """Create directory for scan results"""
        clean_domain = re.sub(r'[^\w\-]', '_', self.target_domain)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = "scan_results"
        
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        
        results_dir = os.path.join(base_dir, f"{clean_domain}_{timestamp}")
        os.makedirs(results_dir)
        
        return results_dir
    
    def save_tool_result(self, results_dir, tool_name, result):
        """Save individual tool results"""
        clean_tool_name = re.sub(r'[^\w\-]', '_', tool_name.lower())
        
        # Save as JSON
        json_file = os.path.join(results_dir, f"{clean_tool_name}.json")
        result_dict = {
            "tool": result.tool_name,
            "status": result.status,
            "timestamp": result.timestamp,
            "output": result.output,
            "details": result.details
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, ensure_ascii=False)
    
    def generate_summary_report(self, results_dir, failed_tools):
        """Generate comprehensive summary report"""
        summary_file = os.path.join(results_dir, "SUMMARY.md")
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# Security Scan Summary Report\n\n")
            
            f.write(f"**Scan ID**: {self.scan_id}\n")
            f.write(f"**Target URL**: {self.target_url}\n")
            f.write(f"**Domain**: {self.target_domain}\n")
            if self.target_ip:
                f.write(f"**IP Address**: {self.target_ip}\n")
            f.write(f"**Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            
            total_tools = len(self.available_tools)
            successful = len([r for r in self.results.values() if r.status == "success"])
            warnings = len([r for r in self.results.values() if r.status == "warning"])
            critical = len([r for r in self.results.values() if r.status == "critical"])
            errors = len([r for r in self.results.values() if r.status == "error"])
            
            f.write(f"- **Total Tools Executed**: {total_tools}\n")
            f.write(f"- **Successful Scans**: {successful}\n")
            f.write(f"- **Warnings Found**: {warnings}\n")
            f.write(f"- **Critical Findings**: {critical}\n")
            f.write(f"- **Errors**: {errors}\n")
            
            # Risk Assessment
            f.write("\n## Risk Assessment\n\n")
            
            if critical > 0:
                f.write(f"**Overall Risk Level**: 🔴 HIGH\n")
                f.write("**Critical issues requiring immediate attention**\n")
            elif warnings > 0:
                f.write(f"**Overall Risk Level**: 🟡 MEDIUM\n")
                f.write("**Issues requiring attention**\n")
            else:
                f.write(f"**Overall Risk Level**: 🟢 LOW\n")
                f.write("**No critical issues detected**\n")
            
            # Critical Findings
            if critical > 0:
                f.write("\n## Critical Findings\n\n")
                
                for tool_name, result in self.results.items():
                    if result.status == "critical":
                        f.write(f"### {tool_name}\n")
                        f.write(f"```\n{result.output[:500]}...\n```\n\n")
            
            # Admin Panels Found
            if self.dashboard.admin_panels_found:
                f.write("## Admin Panels Discovered\n\n")
                f.write("**WARNING**: The following admin panels were found:\n\n")
                for panel in self.dashboard.admin_panels_found:
                    f.write(f"- {panel}\n")
            
            # Recommendations
            f.write("\n## Security Recommendations\n\n")
            
            recommendations = [
                "1. **Immediate Actions**:",
                "   - Change all default credentials",
                "   - Remove sensitive files from public access",
                "   - Close unnecessary ports",
                "   - Update all software to latest versions",
                "",
                "2. **Short-term Actions (1-2 weeks)**:",
                "   - Implement Web Application Firewall (WAF)",
                "   - Enable security headers (CSP, HSTS, etc.)",
                "   - Configure proper access controls",
                "   - Set up logging and monitoring",
                "",
                "3. **Long-term Actions (1-3 months)**:",
                "   - Regular security audits and penetration testing",
                "   - Employee security training",
                "   - Incident response planning",
                "   - Implement security automation",
                "",
                "4. **Continuous Actions**:",
                "   - Regular vulnerability scanning",
                "   - Monitor security advisories",
                "   - Keep backups secure and tested",
                "   - Review and update security policies",
            ]
            
            for rec in recommendations:
                f.write(f"{rec}\n")
            
            f.write("\n## Detailed Results\n\n")
            f.write("All tool results are saved in individual files in this directory.\n")
            f.write(f"Total files generated: {len(os.listdir(results_dir))}\n")
        
        print(f"\n{Fore.GREEN}[✓] Summary report saved: {summary_file}{Style.RESET_ALL}")
        return summary_file
    
    def print_final_summary(self, results_dir, failed_tools):
        """Print final scan summary"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN COMPLETED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        # Calculate statistics
        total_tools = len(self.available_tools)
        successful = len([r for r in self.results.values() if r.status == "success"])
        warnings = len([r for r in self.results.values() if r.status == "warning"])
        critical = len([r for r in self.results.values() if r.status == "critical"])
        errors = len([r for r in self.results.values() if r.status == "error"])
        
        print(f"\n📊 {Fore.CYAN}SCAN STATISTICS:{Style.RESET_ALL}")
        print(f"   Target: {Fore.WHITE}{self.target_url}{Style.RESET_ALL}")
        print(f"   Tools Executed: {Fore.WHITE}{total_tools}{Style.RESET_ALL}")
        print(f"   ✅ Successful: {Fore.GREEN}{successful}{Style.RESET_ALL}")
        print(f"   ⚠️  Warnings: {Fore.YELLOW}{warnings}{Style.RESET_ALL}")
        print(f"   🚨 Critical: {Fore.RED}{critical}{Style.RESET_ALL}")
        print(f"   ❌ Errors: {Fore.RED}{errors}{Style.RESET_ALL}")
        
        # Display critical findings
        if critical > 0:
            print(f"\n🚨 {Fore.RED}CRITICAL FINDINGS:{Style.RESET_ALL}")
            for tool_name, result in self.results.items():
                if result.status == "critical":
                    print(f"   • {tool_name}: {result.output[:80]}...")
        
        # Display admin panels found
        if self.dashboard.admin_panels_found:
            print(f"\n🔑 {Fore.YELLOW}ADMIN PANELS FOUND:{Style.RESET_ALL}")
            for panel in self.dashboard.admin_panels_found:
                print(f"   • {panel}")
        
        print(f"\n📁 {Fore.CYAN}RESULTS SAVED IN:{Style.RESET_ALL}")
        print(f"   {results_dir}")
        
        print(f"\n🔒 {Fore.GREEN}NEXT STEPS:{Style.RESET_ALL}")
        print("   1. Review the detailed reports")
        print("   2. Address critical findings immediately")
        print("   3. Implement security recommendations")
        print("   4. Schedule regular security scans")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    def run(self):
        """Main execution method"""
        try:
            self.print_banner()
            self.get_target()
            self.select_tools()
            
            print(f"\n{Fore.YELLOW}[!] Starting scan in 3 seconds...{Style.RESET_ALL}")
            time.sleep(3)
            
            # Run scans with dashboard
            results_dir, summary_file, failed_tools = self.run_scans_with_dashboard()
            
            # Final summary
            self.print_final_summary(results_dir, failed_tools)
            
            # Ask to open results
            open_results = input(f"\n{Fore.CYAN}[?] Open results directory? (yes/no): {Style.RESET_ALL}").strip().lower()
            if open_results in ["yes", "y"]:
                try:
                    if os.name == 'nt':  # Windows
                        os.startfile(results_dir)
                    elif os.name == 'posix':  # Linux/macOS
                        os.system(f'xdg-open "{results_dir}"')
                except:
                    print(f"{Fore.YELLOW}[!] Could not open directory{Style.RESET_ALL}")
            
            # Ask for another scan
            another = input(f"\n{Fore.CYAN}[?] Scan another website? (yes/no): {Style.RESET_ALL}").strip().lower()
            if another in ["yes", "y"]:
                print("\n" + "="*70)
                scanner = SecurityScanner()
                scanner.run()
            else:
                print(f"\n{Fore.GREEN}[✓] Thank you for using EG-Tool Pro++!{Style.RESET_ALL}")
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
            sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}[✗] Unexpected error: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

class ToolResult:
    """Class to store tool results"""
    def __init__(self, tool_name, status, output, details=None):
        self.tool_name = tool_name
        self.status = status  # success, warning, critical, error
        self.output = output
        self.details = details or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def main():
    """Main entry point"""
    # Check requirements
    try:
        import requests
        import colorama
    except ImportError:
        print(f"{Fore.RED}[✗] Required libraries not installed{Style.RESET_ALL}")
        print("Install using: pip install requests colorama")
        sys.exit(1)
    
    # Run scanner
    scanner = SecurityScanner()
    scanner.run()

if __name__ == "__main__":
    main()

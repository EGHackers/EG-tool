#!/data/data/com.termux/files/usr/bin/python3
"""
السكريبت الرئيسي لفحص OBinance
"""

import os
import sys
import json
import argparse
from datetime import datetime

# إضافة مسار src للمكتبات
sys.path.append(os.path.join(os.path.dirname(__file__)))

from utils.logger import setup_logger
from scanners.port_scanner import PortScanner
from scanners.web_scanner import WebScanner
from scanners.whois_scanner import WhoisScanner
from reports.report_generator import ReportGenerator

class OBinanceScanner:
    def __init__(self, target="obinance.com"):
        self.target = target
        self.logger = setup_logger("OBinanceScanner")
        self.config = self.load_config()
        
        # الماسحات الضوئية
        self.port_scanner = PortScanner(target, self.config)
        self.web_scanner = WebScanner(target, self.config)
        self.whois_scanner = WhoisScanner(target, self.config)
        
        # مولد التقارير
        self.reporter = ReportGenerator(target, self.config)
    
    def load_config(self):
        """تحميل الإعدادات"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 
            "config", 
            "settings.json"
        )
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except:
            # الإعدادات الافتراضية
            return {
                "output_dir": "/data/data/com.termux/files/home/storage/downloads/security_scans",
                "scan_options": {
                    "ports": [25, 80, 443, 8080, 8443],
                    "threads": 5,
                    "timeout": 30
                }
            }
    
    def quick_scan(self):
        """فحص سريع"""
        self.logger.info(f"بدء الفحص السريع لـ {self.target}")
        
        results = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "quick",
            "results": {}
        }
        
        # 1. معلومات WHOIS
        self.logger.info("جمع معلومات WHOIS...")
        results["results"]["whois"] = self.whois_scanner.scan()
        
        # 2. فحص المنافذ الأساسية
        self.logger.info("فحص المنافذ الأساسية...")
        results["results"]["ports"] = self.port_scanner.quick_scan()
        
        # 3. فحص الويب الأساسي
        self.logger.info("فحص الويب الأساسي...")
        results["results"]["web"] = self.web_scanner.basic_scan()
        
        # حفظ النتائج
        report_path = self.reporter.generate_report(results, "quick")
        
        self.logger.info(f"تم حفظ التقرير في: {report_path}")
        return results
    
    def full_scan(self):
        """فحص كامل"""
        self.logger.info(f"بدء الفحص الكامل لـ {self.target}")
        
        results = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "full",
            "results": {}
        }
        
        # جميع الفحوصات
        scan_functions = [
            ("whois", self.whois_scanner.scan),
            ("ports", self.port_scanner.full_scan),
            ("web", self.web_scanner.full_scan),
            ("ssl", self.web_scanner.scan_ssl),
            ("headers", self.web_scanner.scan_headers),
            ("directories", self.web_scanner.scan_directories)
        ]
        
        for name, scan_func in scan_functions:
            try:
                self.logger.info(f"جاري: {name}...")
                results["results"][name] = scan_func()
            except Exception as e:
                self.logger.error(f"خطأ في {name}: {str(e)}")
                results["results"][name] = {"error": str(e)}
        
        # حفظ النتائج
        report_path = self.reporter.generate_report(results, "full")
        
        self.logger.info(f"تم الفحص الكامل!")
        self.logger.info(f"التقرير: {report_path}")
        
        return results
    
    def custom_scan(self, scan_types):
        """فحص مخصص"""
        self.logger.info(f"بدء فحص مخصص: {scan_types}")
        
        results = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "custom",
            "results": {}
        }
        
        scan_map = {
            "whois": self.whois_scanner.scan,
            "ports": self.port_scanner.quick_scan,
            "web": self.web_scanner.basic_scan,
            "ssl": self.web_scanner.scan_ssl,
            "headers": self.web_scanner.scan_headers
        }
        
        for scan_type in scan_types:
            if scan_type in scan_map:
                try:
                    self.logger.info(f"جاري: {scan_type}...")
                    results["results"][scan_type] = scan_map[scan_type]()
                except Exception as e:
                    self.logger.error(f"خطأ في {scan_type}: {str(e)}")
                    results["results"][scan_type] = {"error": str(e)}
        
        report_path = self.reporter.generate_report(results, "custom")
        
        self.logger.info(f"تم الفحص المخصص!")
        return results

def main():
    """الدالة الرئيسية"""
    parser = argparse.ArgumentParser(description="OBinance Security Scanner")
    parser.add_argument("--target", default="obinance.com", help="الموقع المستهدف")
    parser.add_argument("--quick", action="store_true", help="فحص سريع")
    parser.add_argument("--full", action="store_true", help="فحص كامل")
    parser.add_argument("--custom", nargs="+", help="فحص مخصص (whois, ports, web, ssl, headers)")
    
    args = parser.parse_args()
    
    # إنشاء الماسح
    scanner = OBinanceScanner(args.target)
    
    # تحديد نوع الفحص
    if args.full:
        scanner.full_scan()
    elif args.custom:
        scanner.custom_scan(args.custom)
    else:
        scanner.quick_scan()
    
    print("\n✅ تم الانتهاء من الفحص!")
    print("📁 التقارير محفوظة في: ~/storage/downloads/security_scans/")

if __name__ == "__main__":
    main()

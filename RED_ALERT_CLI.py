#!/usr/bin/env python3
import sys
import os
import socket
import argparse
import nmap
import json
import requests
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
from tabulate import tabulate
from tqdm import tqdm
import html

# Initialize colorama for cross-platform colored terminal output
init()

class VulnerabilityScanner:
    def __init__(self, target, ports=None, threads=10, timeout=2):
        self.target = target
        self.ports = ports or "1-1000"  # Default scan first 1000 ports if not specified
        self.threads = threads
        self.timeout = timeout
        self.nm = nmap.PortScanner()
        self.open_ports = []
        self.service_info = {}
        self.vulnerabilities = {}
        self.scan_start_time = None
        self.scan_end_time = None
        
    def resolve_host(self):
        """Resolve hostname to IP address"""
        try:
            print(f"{Fore.BLUE}[*] Resolving hostname {self.target}...{Style.RESET_ALL}")
            ip = socket.gethostbyname(self.target)
            print(f"{Fore.GREEN}[+] Hostname resolved to {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}[!] Could not resolve hostname {self.target}{Style.RESET_ALL}")
            return self.target
    
    def is_port_open(self, port):
        """Check if a port is open using socket"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        result = s.connect_ex((self.target, port))
        s.close()
        return result == 0
    
    def quick_scan(self):
        """Perform a quick scan to find open ports"""
        print(f"{Fore.BLUE}[*] Starting quick port scan on {self.target}...{Style.RESET_ALL}")
        
        # Parse port range
        if "-" in self.ports:
            start_port, end_port = map(int, self.ports.split("-"))
            port_list = range(start_port, end_port + 1)
        else:
            port_list = [int(p) for p in self.ports.split(",")]
        
        # Use ThreadPoolExecutor with tqdm progress bar for parallel scanning
        with tqdm(total=len(port_list), desc="Scanning ports", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Create a list to store results and ports
                results = []
                for port in port_list:
                    future = executor.submit(self.is_port_open, port)
                    results.append((port, future))
                
                # Process results as they complete
                for port, future in results:
                    is_open = future.result()
                    if is_open:
                        self.open_ports.append(port)
                    pbar.update(1)
        
        if self.open_ports:
            print(f"{Fore.GREEN}[+] Found {len(self.open_ports)} open ports: {', '.join(map(str, self.open_ports))}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No open ports found{Style.RESET_ALL}")
    
    def detailed_scan(self):
        """Perform detailed scan on open ports to get service information"""
        if not self.open_ports:
            return
        
        print(f"{Fore.BLUE}[*] Starting detailed service scan on open ports...{Style.RESET_ALL}")
        
        # Convert list of ports to nmap format
        ports_str = ",".join(map(str, self.open_ports))
        
        try:
            # Run nmap scan with service detection and show progress
            print(f"{Fore.BLUE}[*] Running Nmap service detection...{Style.RESET_ALL}")
            with tqdm(total=len(self.open_ports), desc="Identifying services", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
                self.nm.scan(self.target, ports=ports_str, arguments="-sV")
                pbar.update(len(self.open_ports))
            
            # Process results
            for port in self.open_ports:
                port = str(port)
                if self.target in self.nm.all_hosts() and 'tcp' in self.nm[self.target] and int(port) in self.nm[self.target]['tcp']:
                    service_info = self.nm[self.target]['tcp'][int(port)]
                    self.service_info[port] = {
                        'name': service_info['name'],
                        'product': service_info.get('product', ''),
                        'version': service_info.get('version', ''),
                        'extrainfo': service_info.get('extrainfo', '')
                    }
                    print(f"{Fore.GREEN}[+] Port {port}: {self.service_info[port]['name']} - {self.service_info[port]['product']} {self.service_info[port]['version']} {self.service_info[port]['extrainfo']}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error during detailed scan: {str(e)}{Style.RESET_ALL}")
    
    def check_vulnerabilities(self):
        """Check for vulnerabilities in detected services"""
        if not self.service_info:
            return
        
        print(f"{Fore.BLUE}[*] Checking for vulnerabilities...{Style.RESET_ALL}")
        
        # Create progress bar for vulnerability checking
        with tqdm(total=len(self.service_info), desc="Checking vulnerabilities", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for port, service in self.service_info.items():
                product = service['product']
                version = service['version']
                
                if not product:
                    pbar.update(1)
                    continue
                    
                # Query the NVD API for vulnerabilities
                self.vulnerabilities[port] = self.query_nvd(product, version)
                
                if self.vulnerabilities[port]:
                    print(f"{Fore.GREEN}[+] Found {len(self.vulnerabilities[port])} vulnerabilities for {product} {version} on port {port}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] No known vulnerabilities found for {product} {version} on port {port}{Style.RESET_ALL}")
                
                pbar.update(1)
    
    def query_nvd(self, product, version):
        """Query the NVD database for vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Format the search query
            search_term = f"{product}"
            if version:
                search_term += f" {version}"
                
            # Use the NVD API to search for vulnerabilities
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage=10"
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                
                # Process the results
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        cve_item = vuln['cve']
                        cve_id = cve_item['id']
                        description = cve_item['descriptions'][0]['value'] if cve_item['descriptions'] else "No description available"
                        
                        # Get CVSS score if available
                        cvss_score = "N/A"
                        severity = "N/A"
                        
                        if 'metrics' in cve_item:
                            metrics = cve_item['metrics']
                            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 'N/A')
                                severity = cvss_data.get('baseSeverity', 'N/A')
                            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 'N/A')
                                severity = 'N/A'
                        
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'description': description,
                            'cvss_score': cvss_score,
                            'severity': severity
                        })
        except Exception as e:
            print(f"{Fore.RED}[!] Error querying NVD: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def run_scan(self):
        """Run the full vulnerability scan"""
        self.scan_start_time = datetime.datetime.now()
        
        # Resolve hostname to IP if needed
        if not self.is_ip_address(self.target):
            self.target = self.resolve_host()
        
        # Run quick scan to find open ports
        self.quick_scan()
        
        # If open ports found, run detailed scan
        if self.open_ports:
            self.detailed_scan()
            self.check_vulnerabilities()
        
        self.scan_end_time = datetime.datetime.now()
        
        # Generate report
        self.generate_report()
    
    def is_ip_address(self, address):
        """Check if the given address is an IP address"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False
    
    def generate_report(self):
        """Generate a report of the scan results"""
        self.print_console_report()
    
    def print_console_report(self):
        """Print a formatted report to the console"""
        scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}VULNERABILITY SCAN REPORT{Style.RESET_ALL}")
        print("=" * 80)
        
        # Print scan information
        print(f"\n{Fore.CYAN}SCAN INFORMATION:{Style.RESET_ALL}")
        scan_info = [
            ["Target", self.target],
            ["Scan Start Time", self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Scan End Time", self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Duration", f"{scan_duration:.2f} seconds"],
            ["Ports Scanned", self.ports],
            ["Open Ports Found", len(self.open_ports)]
        ]
        print(tabulate(scan_info, tablefmt="pretty"))
        
        if not self.open_ports:
            print(f"\n{Fore.YELLOW}No open ports found.{Style.RESET_ALL}")
            return
        
        # Print open ports and services
        print(f"\n{Fore.CYAN}OPEN PORTS AND SERVICES:{Style.RESET_ALL}")
        
        port_data = []
        for port in self.open_ports:
            port_str = str(port)
            if port_str in self.service_info:
                service = self.service_info[port_str]
                port_data.append([
                    port,
                    service['name'],
                    service['product'],
                    service['version'],
                    service['extrainfo']
                ])
            else:
                port_data.append([port, "Unknown", "", "", ""])
        
        print(tabulate(port_data, headers=["Port", "Service", "Product", "Version", "Extra Info"], tablefmt="pretty"))
        
        # Print vulnerabilities
        print(f"\n{Fore.CYAN}VULNERABILITIES:{Style.RESET_ALL}")
        
        vuln_found = False
        for port in self.open_ports:
            port_str = str(port)
            if port_str in self.vulnerabilities and self.vulnerabilities[port_str]:
                vuln_found = True
                service = self.service_info.get(port_str, {'name': 'Unknown', 'product': '', 'version': ''})
                print(f"\n{Fore.YELLOW}Port {port} - {service['name']} - {service['product']} {service['version']}{Style.RESET_ALL}")
                
                vuln_data = []
                for vuln in self.vulnerabilities[port_str]:
                    severity_color = Fore.GREEN
                    if vuln['severity'] == 'HIGH':
                        severity_color = Fore.RED
                    elif vuln['severity'] == 'MEDIUM':
                        severity_color = Fore.YELLOW
                    
                    # Truncate description if too long
                    description = vuln['description']
                    if len(description) > 100:
                        description = description[:97] + "..."
                    
                    vuln_data.append([
                        f"{Fore.RED}{vuln['cve_id']}{Style.RESET_ALL}",
                        f"{severity_color}{vuln['cvss_score']}{Style.RESET_ALL}",
                        f"{severity_color}{vuln['severity']}{Style.RESET_ALL}",
                        description
                    ])
                
                print(tabulate(vuln_data, headers=["CVE ID", "CVSS Score", "Severity", "Description"], tablefmt="pretty"))
        
        if not vuln_found:
            print(f"{Fore.GREEN}No vulnerabilities found for any service.{Style.RESET_ALL}")
    
    def save_report(self, output_file, format_type):
        """Save the scan report to a file in the specified format"""
        if format_type.lower() == 'txt':
            self.save_txt_report(output_file)
        elif format_type.lower() == 'json':
            self.save_json_report(output_file)
        elif format_type.lower() == 'html':
            self.save_html_report(output_file)
        else:
            print(f"{Fore.RED}[!] Unsupported report format: {format_type}{Style.RESET_ALL}")
    
    def save_txt_report(self, output_file):
        """Save the scan report in plain text format"""
        try:
            with open(output_file, 'w') as f:
                # Redirect stdout to the file
                original_stdout = sys.stdout
                sys.stdout = f
                
                # Generate a report without colors
                scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
                
                f.write("=" * 80 + "\n")
                f.write("VULNERABILITY SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Print scan information
                f.write("SCAN INFORMATION:\n")
                scan_info = [
                    ["Target", self.target],
                    ["Scan Start Time", self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")],
                    ["Scan End Time", self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S")],
                    ["Duration", f"{scan_duration:.2f} seconds"],
                    ["Ports Scanned", self.ports],
                    ["Open Ports Found", len(self.open_ports)]
                ]
                f.write(tabulate(scan_info, tablefmt="pretty") + "\n")
                
                if not self.open_ports:
                    f.write("\nNo open ports found.\n")
                    sys.stdout = original_stdout
                    return
                
                # Print open ports and services
                f.write("\nOPEN PORTS AND SERVICES:\n")
                
                port_data = []
                for port in self.open_ports:
                    port_str = str(port)
                    if port_str in self.service_info:
                        service = self.service_info[port_str]
                        port_data.append([
                            port,
                            service['name'],
                            service['product'],
                            service['version'],
                            service['extrainfo']
                        ])
                    else:
                        port_data.append([port, "Unknown", "", "", ""])
                
                f.write(tabulate(port_data, headers=["Port", "Service", "Product", "Version", "Extra Info"], tablefmt="pretty") + "\n")
                
                # Print vulnerabilities
                f.write("\nVULNERABILITIES:\n")
                
                vuln_found = False
                for port in self.open_ports:
                    port_str = str(port)
                    if port_str in self.vulnerabilities and self.vulnerabilities[port_str]:
                        vuln_found = True
                        service = self.service_info.get(port_str, {'name': 'Unknown', 'product': '', 'version': ''})
                        f.write(f"\nPort {port} - {service['name']} - {service['product']} {service['version']}\n")
                        
                        vuln_data = []
                        for vuln in self.vulnerabilities[port_str]:
                            # Truncate description if too long
                            description = vuln['description']
                            if len(description) > 100:
                                description = description[:97] + "..."
                            
                            vuln_data.append([
                                vuln['cve_id'],
                                vuln['cvss_score'],
                                vuln['severity'],
                                description
                            ])
                        
                        f.write(tabulate(vuln_data, headers=["CVE ID", "CVSS Score", "Severity", "Description"], tablefmt="pretty") + "\n")
                
                if not vuln_found:
                    f.write("No vulnerabilities found for any service.\n")
                
                # Restore stdout
                sys.stdout = original_stdout
                
            print(f"{Fore.GREEN}[+] Report saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving TXT report: {str(e)}{Style.RESET_ALL}")
    
    def save_json_report(self, output_file):
        """Save the scan report in JSON format"""
        try:
            report = {
                "scan_info": {
                    "target": self.target,
                    "start_time": self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "end_time": self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "duration": (self.scan_end_time - self.scan_start_time).total_seconds(),
                    "ports_scanned": self.ports,
                    "open_ports_count": len(self.open_ports)
                },
                "open_ports": self.open_ports,
                "services": self.service_info,
                "vulnerabilities": self.vulnerabilities
            }
            
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
            
            print(f"{Fore.GREEN}[+] Report saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving JSON report: {str(e)}{Style.RESET_ALL}")
    
    def save_html_report(self, output_file):
        """Save the scan report in HTML format"""
        try:
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
            
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {self.target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            text-align: center;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
        }}
        .section {{
            margin: 20px 0;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .severity-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .severity-low {{
            color: #27ae60;
            font-weight: bold;
        }}
        .cve-id {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .port-header {{
            background-color: #34495e;
            color: white;
            padding: 10px;
            margin-top: 20px;
            border-radius: 5px;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 0.8em;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Scan Report</h1>
        
        <div class="section">
            <h2>Scan Information</h2>
            <table>
                <tr>
                    <th>Property</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Target</td>
                    <td>{html.escape(self.target)}</td>
                </tr>
                <tr>
                    <td>Scan Start Time</td>
                    <td>{self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")}</td>
                </tr>
                <tr>
                    <td>Scan End Time</td>
                    <td>{self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S")}</td>
                </tr>
                <tr>
                    <td>Duration</td>
                    <td>{scan_duration:.2f} seconds</td>
                </tr>
                <tr>
                    <td>Ports Scanned</td>
                    <td>{html.escape(self.ports)}</td>
                </tr>
                <tr>
                    <td>Open Ports Found</td>
                    <td>{len(self.open_ports)}</td>
                </tr>
            </table>
        </div>
"""
            
            if not self.open_ports:
                html_content += """
        <div class="section">
            <h2>Open Ports and Services</h2>
            <p>No open ports found.</p>
        </div>
"""
            else:
                html_content += """
        <div class="section">
            <h2>Open Ports and Services</h2>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                    <th>Extra Info</th>
                </tr>
"""
                
                for port in self.open_ports:
                    port_str = str(port)
                    if port_str in self.service_info:
                        service = self.service_info[port_str]
                        html_content += f"""
                <tr>
                    <td>{port}</td>
                    <td>{html.escape(service['name'])}</td>
                    <td>{html.escape(service['product'])}</td>
                    <td>{html.escape(service['version'])}</td>
                    <td>{html.escape(service['extrainfo'])}</td>
                </tr>
"""
                    else:
                        html_content += f"""
                <tr>
                    <td>{port}</td>
                    <td>Unknown</td>
                    <td></td>
                    <td></td>
                    <td></td>
                </tr>
"""
                
                html_content += """
            </table>
        </div>
"""
                
                # Vulnerabilities section
                html_content += """
        <div class="section">
            <h2>Vulnerabilities</h2>
"""
                
                vuln_found = False
                for port in self.open_ports:
                    port_str = str(port)
                    if port_str in self.vulnerabilities and self.vulnerabilities[port_str]:
                        vuln_found = True
                        service = self.service_info.get(port_str, {'name': 'Unknown', 'product': '', 'version': ''})
                        
                        html_content += f"""
            <div class="port-header">
                <h3>Port {port} - {html.escape(service['name'])} - {html.escape(service['product'])} {html.escape(service['version'])}</h3>
            </div>
            <table>
                <tr>
                    <th>CVE ID</th>
                    <th>CVSS Score</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
"""
                        
                        for vuln in self.vulnerabilities[port_str]:
                            severity_class = "severity-low"
                            if vuln['severity'] == 'HIGH':
                                severity_class = "severity-high"
                            elif vuln['severity'] == 'MEDIUM':
                                severity_class = "severity-medium"
                            
                            html_content += f"""
                <tr>
                    <td class="cve-id">{html.escape(vuln['cve_id'])}</td>
                    <td class="{severity_class}">{html.escape(str(vuln['cvss_score']))}</td>
                    <td class="{severity_class}">{html.escape(vuln['severity'])}</td>
                    <td>{html.escape(vuln['description'])}</td>
                </tr>
"""
                        
                        html_content += """
            </table>
"""
                
                if not vuln_found:
                    html_content += """
            <p>No vulnerabilities found for any service.</p>
"""
                
                html_content += """
        </div>
"""
            
            # Footer
            html_content += f"""
        <div class="footer">
            <p>Report generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} by Vulnerability Scanner</p>
        </div>
    </div>
</body>
</html>
"""
            
            with open(output_file, 'w') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}[+] Report saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving HTML report: {str(e)}{Style.RESET_ALL}")


def print_banner():
    """Print an ASCII art banner for the tool"""
    banner = f"""
{Fore.RED}
==================================================
 ____  _____ ____     _    _     _____ ____ _____ 
|  _ \| ____|  _ \   / \  | |   | ____|  _ \_   _|
| |_) |  _| | | | | / _ \ | |   |  _| | |_) || |  
|  _ <| |___| |_| |/ ___ \| |___| |___|  _ < | |  
|_| \_\_____|____/_/   \_\_____|_____||_| \_\|_|  
==================================================                   
                                                            
{Style.RESET_ALL}
"""
    print(banner)
    print(f"{Fore.YELLOW}A comprehensive vulnerability scanning tool{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Version 1.1.0{Style.RESET_ALL}")
    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(description='Vulnerability Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan (e.g., 1-1000 or 22,80,443)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads for scanning')
    parser.add_argument('-T', '--timeout', type=float, default=1.0, help='Timeout for port scanning in seconds')
    parser.add_argument('-o', '--output', help='Output file to save the report')
    parser.add_argument('-f', '--format', choices=['txt', 'json', 'html'], default='txt', 
                        help='Report format (txt, json, or html)')
    
    args = parser.parse_args()
    
    print_banner()
    
    scanner = VulnerabilityScanner(
        target=args.target,
        ports=args.ports,
        threads=args.threads,
        timeout=args.timeout
    )
    
    scanner.run_scan()
    
    # Save report if output file is specified
    if args.output:
        scanner.save_report(args.output, args.format)

if __name__ == "__main__":
    main()

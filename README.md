# 🚨 RED ALERT CLI - Enhanced Vulnerability Scanner



### Core Scanning Capabilities
- **🔍 Port Scanning**: Fast multi-threaded port discovery using custom socket implementation
- **🔧 Service Detection**: Advanced service fingerprinting via Nmap integration
- **🛡️ CVE Lookup**: Real-time vulnerability database queries using NVD API
- **💥 Exploit Discovery**: Automatic exploit lookup using `searchsploit` integration
- **📊 Multiple Report Formats**: TXT, JSON, and HTML output with professional styling

### OWASP Top 10 Web Security Testing
- **💉 SQL Injection**: Parameter fuzzing with database error detection
- **🔗 Cross-Site Scripting (XSS)**: Reflected XSS vulnerability identification
- **🔐 Insecure Direct Object References (IDOR)**: Sequential resource access testing
- **⚙️ Security Misconfiguration**: HTTP methods, headers, and directory listing checks
- **🌐 Server-Side Request Forgery (SSRF)**: Internal/external URL injection testing
- **🚫 Broken Access Control**: Admin panel accessibility verification
- **🔑 Weak Authentication**: Default credential and brute-force testing

### Advanced Features
- **🎨 Colored Terminal Output**: Professional CLI interface with progress bars
- **⚡ Multi-threading**: Configurable thread count for optimal performance
- **🔄 Rate Limiting**: Built-in delays to avoid service disruption
- **📈 Progress Tracking**: Real-time scan progress with tqdm integration
- **🛠️ Remediation Guidance**: Actionable security recommendations for each finding

## 🚀 Installation

### Prerequisites
- **Operating System**: Linux (Ubuntu, Kali, CentOS, etc.)
- **Python**: Version 3.7 or higher
- **Nmap**: Network exploration tool
- **Searchsploit** (Optional): For exploit database queries

### Step 1: Install System Dependencies

\`\`\`bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip nmap exploitdb

# CentOS/RHEL
sudo yum install python3 python3-pip nmap
# Note: exploitdb may need manual installation on CentOS

# Arch Linux
sudo pacman -S python python-pip nmap exploitdb
\`\`\`

### Step 2: Clone Repository

\`\`\`bash
git clone https://github.com/yourusername/red-alert-cli.git
cd red-alert-cli
\`\`\`

### Step 3: Install Python Dependencies

\`\`\`bash
pip3 install -r requirements.txt
\`\`\`

### Step 4: Verify Installation

\`\`\`bash
python3 RED_ALERT_CLI.py --help
\`\`\`

## 💻 Usage

### Basic Scan
\`\`\`bash
python3 RED_ALERT_CLI.py target.com
\`\`\`

### OWASP Web Security Scan
\`\`\`bash
python3 RED_ALERT_CLI.py target.com --owasp
\`\`\`

### Full Security Audit with Report
\`\`\`bash
python3 RED_ALERT_CLI.py target.com --owasp -o security_report.html -f html
\`\`\`

## 🔧 Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `target` | - | Target IP address or hostname | Required |
| `--ports` | `-p` | Port range to scan (e.g., 1-1000 or 22,80,443) | 1-1000 |
| `--threads` | `-t` | Number of scanning threads | 10 |
| `--timeout` | `-T` | Port scanning timeout in seconds | 1.0 |
| `--output` | `-o` | Output file path for report | None |
| `--format` | `-f` | Report format (txt, json, html) | txt |
| `--owasp` | - | Enable OWASP Top 10 web vulnerability scanning | False |

## 📄 Output Formats

### 1. Console Output (Default)
- Colored terminal output with progress bars
- Real-time vulnerability discovery notifications
- Structured vulnerability cards with severity indicators

### 2. Plain Text Report (`.txt`)
\`\`\`bash
python3 RED_ALERT_CLI.py target.com --owasp -o report.txt -f txt
\`\`\`
- Clean, readable format for documentation
- Perfect for inclusion in security reports
- Easy to parse and share

### 3. JSON Report (`.json`)
\`\`\`bash
python3 RED_ALERT_CLI.py target.com --owasp -o report.json -f json
\`\`\`
- Machine-readable format for automation
- Integration with other security tools
- Programmatic analysis and processing

### 4. HTML Report (`.html`)
\`\`\`bash
python3 RED_ALERT_CLI.py target.com --owasp -o report.html -f html
\`\`\`
- Professional web-based report
- Interactive and visually appealing
- Easy to share with stakeholders
- Print-friendly for PDF conversion

## 🛡️ OWASP Top 10 Coverage

| OWASP Category | Test Coverage | Severity Detection |
|----------------|---------------|-------------------|
| **A01 - Broken Access Control** | ✅ Admin panel detection | HIGH |
| **A02 - Cryptographic Failures** | 🔄 Planned for v2.1 | - |
| **A03 - Injection** | ✅ SQL Injection testing | HIGH |
| **A04 - Insecure Design** | 🔄 Manual assessment | - |
| **A05 - Security Misconfiguration** | ✅ Headers, methods, directories | MEDIUM |
| **A06 - Vulnerable Components** | ✅ CVE database lookup | VARIES |
| **A07 - Authentication Failures** | ✅ Default credentials, brute force | HIGH |
| **A08 - Software Integrity Failures** | 🔄 Planned for v2.1 | - |
| **A09 - Logging Failures** | 🔄 Manual assessment | - |
| **A10 - SSRF** | ✅ URL parameter injection | HIGH |

**Additional Coverage:**
- **Cross-Site Scripting (XSS)**: Reflected XSS detection
- **IDOR**: Sequential resource access testing

## 📚 Examples

### Example 1: Basic Network Scan
\`\`\`bash
python3 RED_ALERT_CLI.py 192.168.1.100 -p 1-5000 -t 20
\`\`\`

### Example 2: Web Application Security Test
\`\`\`bash
python3 RED_ALERT_CLI.py webapp.example.com -p 80,443,8080,8443 --owasp
\`\`\`

### Example 3: Comprehensive Security Audit
\`\`\`bash
python3 RED_ALERT_CLI.py target.com --owasp -o audit_$(date +%Y%m%d).html -f html
\`\`\`

### Example 4: Bug Bounty Reconnaissance
\`\`\`bash
python3 RED_ALERT_CLI.py bounty-target.com -p 1-10000 --owasp -o bounty_report.json -f json
\`\`\`

### Example 5: Internal Network Assessment
\`\`\`bash
for ip in 192.168.1.{1..254}; do
    python3 RED_ALERT_CLI.py $ip -p 22,80,443,3389 --owasp -o "scan_$ip.txt" -f txt
done
\`\`\`

## 📊 Report Samples

### Console Output Sample
\`\`\`
🚨 RED ALERT CLI - VULNERABILITY SCAN REPORT
================================================================================

SCAN INFORMATION:
+------------------+-------------------------+
| Target           | example.com             |
| Scan Start Time  | 2024-01-15 14:30:25    |
| Scan End Time    | 2024-01-15 14:32:18    |
| Duration         | 113.45 seconds          |
| Ports Scanned    | 1-1000                  |
| Open Ports Found | 3                       |
| OWASP Scan       | Enabled                 |
+------------------+-------------------------+

[HIGH] SQL Injection
  URL: http://example.com?id=' OR '1'='1
  Parameter: id
  Evidence: MySQL syntax error detected
  Remediation: Use parameterized queries. Validate and sanitize all user inputs.
\`\`\`

### HTML Report Features
- 📱 Responsive design for mobile and desktop
- 🎨 Professional styling with severity color coding
- 📋 Expandable vulnerability details
- 🖨️ Print-friendly layout for PDF generation
- 📊 Executive summary with statistics

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Here's how you can help:

### Areas for Contribution
- 🔍 Additional OWASP vulnerability tests
- 🌐 New web application attack vectors
- 📊 Enhanced reporting features
- 🔧 Performance optimizations
- 📚 Documentation improvements

### Development Setup
\`\`\`bash
git clone https://github.com/yourusername/red-alert-cli.git
cd red-alert-cli
pip3 install -r requirements.txt
python3 -m pytest tests/  # Run tests
\`\`\`

## 🔒 Legal Disclaimer

**⚠️ IMPORTANT: This tool is for educational and authorized testing purposes only.**

### Authorized Use Only
- ✅ **Permitted**: Testing your own systems and networks
- ✅ **Permitted**: Authorized penetration testing with written permission
- ✅ **Permitted**: Educational and research purposes in controlled environments
- ✅ **Permitted**: Bug bounty programs with explicit scope authorization

### Prohibited Activities
- ❌ **Forbidden**: Scanning systems without explicit permission
- ❌ **Forbidden**: Using for malicious or illegal activities
- ❌ **Forbidden**: Violating terms of service or applicable laws
- ❌ **Forbidden**: Causing damage or disruption to services

### User Responsibility
By using RED ALERT CLI, you agree to:
- Obtain proper authorization before scanning any systems
- Comply with all applicable laws and regulations
- Use the tool responsibly and ethically
- Take full responsibility for your actions

**The developers of RED ALERT CLI are not responsible for any misuse of this tool.**

### Version 2.1 (Planned)
- 🔍 **XXE (XML External Entity) Testing**
- 🔐 **Insecure Deserialization Detection**
- 📱 **Mobile Application Security Testing**
- 🌐 **GraphQL Security Assessment**

### Version 2.2 (Planned)
- 🤖 **Machine Learning-based Anomaly Detection**
- 📊 **Advanced Reporting with Charts**
- 🔄 **Continuous Monitoring Mode**
- 🐳 **Docker Container Support**

## 🙏 Acknowledgments

- **OWASP Foundation** for security testing methodologies
- **NVD/NIST** for vulnerability database access
- **Exploit-DB** for exploit information
- **Indian Cybersecurity Community** for feedback and support
- **Open Source Contributors** who make tools like this possible

---


Absolutely! Here's a **clean, focused, and minimal version of your README** that includes only the **necessary things**:

---

# 🚨 RED ALERT CLI - Enhanced Vulnerability Scanner

A powerful and lightweight CLI-based vulnerability scanner written in Python, designed for ethical hacking, bug bounty, and internal assessments.

🔗 **GitHub:** [https://github.com/BreakingRohit/RED\_ALERT\_CLI](https://github.com/BreakingRohit/RED_ALERT_CLI)

---

## 🔥 What It Does

* 🚀 **Fast Multi-threaded Port Scanning** using raw sockets
* 🧠 **Service Detection** using `nmap`
* 🛡️ **CVE Detection** via NVD API with real exploit info from `searchsploit`
* 🌐 **OWASP Top 10 Detection** (SQLi, XSS, SSRF, Misconfig, Weak Auth, etc.)
* 📄 **Report Generation** in TXT, JSON, and HTML formats
* 🎯 Great for Bug Bounty, Recon, Internal Audits

---

## ⚙️ Installation

### 🧱 System Requirements

* Linux (Ubuntu, Kali, Parrot, etc.)
* Python 3.7+
* `nmap` (required)
* `searchsploit` (optional for exploit lookup)

### 📥 Install Instructions

```bash
# Clone the repo
git clone https://github.com/BreakingRohit/RED_ALERT_CLI.git
cd RED_ALERT_CLI

# Install Python dependencies
pip3 install -r requirements.txt

# (If not installed)
sudo apt install nmap exploitdb
```

---

## 🧪 How to Use

### Basic Scan

```bash
python3 RED_ALERT_CLI.py target.com
```

### Enable OWASP Scanning

```bash
python3 RED_ALERT_CLI.py target.com --owasp
```

### Save HTML Report

```bash
python3 RED_ALERT_CLI.py target.com --owasp -o report.html -f html
```

---

## 📁 Output Formats

* **TXT** – Clean CLI-style summary
* **JSON** – For integration/automation
* **HTML** – Professional styled report (print/PDF friendly)

---



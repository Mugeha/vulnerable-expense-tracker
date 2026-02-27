# 🔐 Vulnerable Expense Tracker - AppSec Learning Project

A deliberately vulnerable web application built to demonstrate common security vulnerabilities and their remediation. Part of my Application Security portfolio.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-OWASP%20Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)

---

## 🎯 Project Overview

This project is a **hands-on security learning exercise** where I:
1. Built a functional web application from scratch
2. Intentionally introduced security vulnerabilities
3. Exploited them using industry-standard tools
4. Documented findings professionally
5. Provided remediation guidance

**⚠️ WARNING:** This application contains intentional security vulnerabilities for educational purposes. **DO NOT deploy to production or expose to the internet.**

---

## 🛠️ Tech Stack

- **Backend:** Python 3.x + Flask
- **Database:** SQLite3
- **Frontend:** HTML5 + Jinja2 Templates
- **Testing Tools:** Burp Suite Community Edition

---

## 📚 Vulnerabilities Demonstrated

### Critical Severity
1. **SQL Injection (Authentication Bypass)** - CWE-89
   - Location: Login and Registration forms
   - Impact: Complete authentication bypass, database manipulation
   - CVSS: 9.8

2. **SQL Injection (Data Extraction)** - CWE-89
   - Location: User input fields
   - Impact: Database enumeration, data theft

3. **Business Logic Flaw** - CWE-89
   - Location: User input fields
   - Impact: Financial fraud

### High Severity
4. **Insecure Direct Object Reference (IDOR)** - CWE-639
   - Location: Expense viewing endpoint
   - Impact: Unauthorized access to other users' financial data

5. **Stored Cross-Site Scripting (XSS)** - CWE-79
   - Location: Expense description field
   - Impact: Session hijacking, account takeover, phishing

### Medium Severity
6. **Weak Session Configuration** - CWE-330
   - Hardcoded secret key
   - Missing httpOnly, Secure, SameSite flags
   - Impact: Session prediction and theft

### Low Severity
6. **Missing Security Headers**
   - No Content-Security-Policy
   - No X-Frame-Options
   - No X-Content-Type-Options

---

## 📂 Project Structure
```
vulnerable-expense-tracker/
├── app.py                          # Main Flask application (vulnerable)
├── database.py                     # Database initialization
├── templates/                      # HTML templates
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── add_expense.html
│   └── view_expense.html
├── screenshots/                    # Exploitation evidence
│   ├── sqli-burp-intercept.png
│   ├── idor-attack.png
│   └── xss-execution.png
├── VULNERABILITIES.md              # Detailed vulnerability documentation
├── FIXES.md                        # Remediation guide
├── PENETRATION_TEST_REPORT.md      # Professional security assessment
└── README.md                       # This file
```

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git

### Installation Steps
```bash
# 1. Clone the repository
git clone https://github.com/YOUR-USERNAME/vulnerable-expense-tracker.git
cd vulnerable-expense-tracker

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# 4. Install dependencies
pip install flask

# 5. Initialize database
python database.py

# 6. Run the application
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

---

## 🧪 Testing the Vulnerabilities

### SQL Injection Test
```bash
# Login with this payload:
Username: admin
Password: ' OR '1'='1
```

### IDOR Test
```bash
# After logging in, manually change URL:
http://127.0.0.1:5000/expense/1
http://127.0.0.1:5000/expense/2
# Access other users' expenses
```

### XSS Test
```html
<!-- Add expense with description: -->
<script>alert('XSS')</script>
<!-- View the expense - JavaScript executes -->
```

---

## 📖 Documentation

### Vulnerability Research
- **[VULNERABILITIES.md](VULNERABILITIES.md)** - Detailed analysis of each vulnerability
  - Root cause analysis
  - Exploitation steps with screenshots
  - Impact assessment
  - Real-world examples

### Security Fixes
- **[FIXES.md](FIXES.md)** - Comprehensive remediation guide
  - Secure code examples
  - Best practices
  - Defense-in-depth strategies
  - Implementation checklist

### Professional Assessment
- **[PENETRATION_TEST_REPORT.md](PENETRATION_TEST_REPORT.md)** - Complete pentest report
  - Executive summary
  - CVSS scoring
  - Proof of concept exploits
  - Risk ratings
  - Remediation timeline

---

## 🔍 Tools & Methodology

### Testing Tools Used
- **Burp Suite Community Edition** - HTTP interception and manipulation
- **Manual Code Review** - Source code analysis
- **Browser Developer Tools** - Client-side testing

### Testing Approach
1. **Black-box Testing** - Initial vulnerability discovery
2. **White-box Testing** - Source code analysis
3. **Manual Exploitation** - Proof of concept development
4. **Automated Scanning** - Burp Suite passive analysis
5. **Documentation** - Professional reporting

---

## 🎓 Learning Outcomes

Through this project, I gained hands-on experience with:

**Technical Skills:**
- ✅ Web application development (Flask framework)
- ✅ Database design and SQL operations
- ✅ Session management and authentication
- ✅ HTTP protocol and request/response analysis
- ✅ Burp Suite for security testing

**Security Skills:**
- ✅ OWASP Top 10 vulnerabilities
- ✅ SQL Injection exploitation techniques
- ✅ Authorization vs. Authentication concepts
- ✅ XSS attack vectors and payloads
- ✅ Secure coding practices
- ✅ Vulnerability assessment methodology
- ✅ Professional security documentation

**Professional Skills:**
- ✅ Technical report writing
- ✅ Risk assessment and prioritization
- ✅ Remediation recommendations
- ✅ Security evidence gathering
- ✅ Version control with Git

---

## 🛡️ Secure Version

The secure version implementing all fixes is documented in **[Fixes.md](Fixes.md)**. Key security improvements include:

- ✅ Parameterized SQL queries
- ✅ Authorization checks (user ownership validation)
- ✅ Input sanitization and output encoding
- ✅ Password hashing with bcrypt
- ✅ Secure session configuration
- ✅ Security headers (CSP, HSTS, X-Frame-Options)
- ✅ CSRF protection
- ✅ Rate limiting

---

## 📊 OWASP Top 10 Coverage

| OWASP Category | Demonstrated | Vulnerability |
|----------------|--------------|---------------|
| A01:2021 – Broken Access Control | ✅ | IDOR |
| A02:2021 – Cryptographic Failures | ✅ | Plain-text passwords |
| A03:2021 – Injection | ✅ | SQL Injection |
| A04:2021 – Insecure Design | ✅ | Missing auth checks |
| A05:2021 – Security Misconfiguration | ✅ | Weak session config |
| A06:2021 – Vulnerable Components | ⚠️ | N/A (minimal deps) |
| A07:2021 – Identification/Auth Failures | ✅ | SQL injection bypass |
| A08:2021 – Software and Data Integrity | ⚠️ | N/A |
| A09:2021 – Security Logging Failures | ✅ | No audit logs |
| A10:2021 – Server-Side Request Forgery | ❌ | Not applicable |

---

## 🤝 Contributing

This is a learning project and not open for contributions. However, feedback is welcome! If you're also learning AppSec, feel free to:
- Fork this repo for your own learning
- Reference it in your studies
- Share your own findings

---

## ⚠️ Legal Disclaimer

This application is created solely for **educational purposes** to demonstrate security vulnerabilities in a controlled environment. 

**DO NOT:**
- Deploy this application to production
- Expose it to the internet
- Use these techniques on systems you don't own
- Share credentials or sensitive data

**Unauthorized access to computer systems is illegal.** Always obtain proper authorization before conducting security testing.

---

## 📚 Resources & References

### Security Standards
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

### Learning Resources
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [HackTheBox](https://www.hackthebox.com/)

### Tools Documentation
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Flask Security](https://flask.palletsprojects.com/en/stable/security/)

---

## 👤 Author

**[Mugeha Jackline]**
- GitHub: [@your-username](https://github.com/Mugeha)
- LinkedIn: [Your Profile](https://linkedin.com/in/your-profile)
- Portfolio: [your-portfolio.com](https://your-portfolio.com)

---

## 📅 Project Timeline

- **Started:** February 2026
- **Completed:** February 2026
- **Duration:** 2 weeks
---

## ⭐ Acknowledgments

Built as part of a structured AppSec learning path, focusing on:
- Understanding vulnerabilities at a code level
- Practicing responsible disclosure
- Developing professional security documentation skills

---

**If you found this project helpful for your learning, consider giving it a ⭐!**

---

*This project demonstrates intentional security vulnerabilities for educational purposes only. Always practice ethical hacking and obtain proper authorization.*
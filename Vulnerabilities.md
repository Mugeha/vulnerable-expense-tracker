# Vulnerability Documentation

## SQL Injection in Login Form

### Vulnerability Description
The login route uses string formatting to build SQL queries, allowing attackers to inject malicious SQL code.

### Location
File: `app.py`
Function: `login()`
Line: `query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"`

### Proof of Concept

#### Attack 1: Authentication Bypass with OR
**Payload:**
- Username: `testuser`
- Password: `' OR '1'='1`

**Result:** Successfully logged in without valid password

**Malicious Query:**
```sql
SELECT * FROM users WHERE username = 'testuser' AND password = '' OR '1'='1'
```

#### Attack 2: Comment-based Bypass
**Payload:**
- Username: `testuser'--`
- Password: (any value)

**Result:** Password check completely bypassed

**Malicious Query:**
```sql
SELECT * FROM users WHERE username = 'testuser'--' AND password = 'anything'
```

### Impact
- **Severity:** CRITICAL
- Attackers can bypass authentication
- Access any user account
- Potential for data theft
- Potential for data manipulation

### Root Cause
Using Python f-strings to concatenate user input directly into SQL queries without sanitization or parameterization.

### Remediation
Use parameterized queries (prepared statements):
```python
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

---

**Tested by:** Mugeha Jackline(Jackie) 
**Date:** February 6, 2026
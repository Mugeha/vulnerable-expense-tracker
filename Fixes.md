# Security Fixes - Expense Tracker

This document outlines how to remediate each vulnerability found in this application.

---

## Fix #1: SQL Injection in Login and Registration

### Current Vulnerable Code (app.py)

**Registration route:**
```python
query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
cursor.execute(query)
```

**Login route:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
user = cursor.execute(query).fetchone()
```

### Why It's Vulnerable
User input is concatenated directly into SQL queries using f-strings, allowing attackers to inject malicious SQL code.

### The Fix: Parameterized Queries

**Secure Registration:**
```python
query = "INSERT INTO users (username, password) VALUES (?, ?)"
cursor.execute(query, (username, password))
```

**Secure Login:**
```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
user = cursor.execute(query, (username, password)).fetchone()
```

### How It Works
- The `?` placeholders separate SQL structure from data
- User input is passed as a tuple in the second parameter
- The database driver properly escapes special characters
- Input is treated as data, not executable code

### Additional Security Layer: Password Hashing
```python
import bcrypt

# When registering
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# When logging in
if bcrypt.checkpw(password.encode('utf-8'), user['password']):
    # Password correct
```

**Why hash passwords?**
- Even if database is compromised, passwords aren't exposed
- Industry standard practice
- Use bcrypt, argon2, or PBKDF2 (never SHA1 or MD5 alone)

---

## Fix #2: IDOR (Insecure Direct Object Reference)

### Current Vulnerable Code (app.py)
```python
@app.route('/expense/<int:expense_id>')
def view_expense(expense_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    expense = conn.execute(
        "SELECT * FROM expenses WHERE id = ?",
        (expense_id,)
    ).fetchone()
```

### Why It's Vulnerable
The function checks if user is logged in (authentication) but doesn't verify if the expense belongs to them (authorization).

### The Fix: Add Authorization Check
```python
@app.route('/expense/<int:expense_id>')
def view_expense(expense_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # ✅ Add user_id check to verify ownership
    expense = conn.execute(
        "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
        (expense_id, session['user_id'])
    ).fetchone()
    
    if expense:
        return render_template('view_expense.html', expense=expense)
    else:
        return "Expense not found or access denied", 403
```

### Key Principle: Authorization != Authentication
- **Authentication:** "Who are you?" (checking if logged in)
- **Authorization:** "What can you access?" (checking ownership)
- Always validate BOTH

---

## Fix #3: Stored XSS (Cross-Site Scripting)

### Current Vulnerable Code

**Template (view_expense.html):**
```html
<td>{{ expense.description | safe }}</td>
```

**Backend (app.py):**
```python
description = request.form['description']
# No sanitization
```

### Why It's Vulnerable
- The `| safe` filter disables Flask's auto-escaping
- User input stored directly in database
- Malicious JavaScript executes when viewed

### The Fix: Multiple Layers

**Layer 1: Remove | safe filter (view_expense.html)**
```html
<!-- Flask auto-escapes by default -->
<td>{{ expense.description }}</td>
```

**Layer 2: Server-side sanitization (app.py)**
```python
from markupsafe import escape

description = escape(request.form['description'])
```

**Layer 3: Content Security Policy Header**
```python
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response
```

### How Auto-Escaping Works
```
Input:  <script>alert('XSS')</script>
Stored: <script>alert('XSS')</script>
Output: &lt;script&gt;alert('XSS')&lt;/script&gt;
Result: Displays as text, doesn't execute
```

---

## Fix #4: Weak Session Configuration

### Current Vulnerable Code
```python
app.secret_key = 'super_secret_key_123'
```

### Why It's Vulnerable
- Hardcoded secret (visible in source code)
- Predictable (can be guessed)
- Allows session forgery if leaked
- Session cookies accessible via JavaScript (XSS risk)

### The Fix: Secure Session Configuration
```python
import os

# Generate secure random key
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

# Secure cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SECURE'] = True     # HTTPS only (production)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
```

### Environment Variable Setup

**Development (.env file):**
```bash
SECRET_KEY=randomly_generated_key_here_use_secrets.token_hex(32)
```

**Production (Railway/Render):**
Set in platform's environment variables dashboard.

**Generate secure key:**
```python
import secrets
print(secrets.token_hex(32))
```

---

## Additional Security Enhancements

### 1. CSRF Protection

**Install Flask-WTF:**
```bash
pip install flask-wtf
```

**Enable CSRF:**
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
```

**In forms:**
```html
<form method="POST">
    {{ csrf_token() }}
    <!-- form fields -->
</form>
```

### 2. Security Headers
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### 3. Rate Limiting

**Install Flask-Limiter:**
```bash
pip install flask-limiter
```

**Implement:**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force
def login():
    # ...
```

### 4. Input Validation
```python
import re

def validate_username(username):
    # Alphanumeric only, 3-20 characters
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False
    return True

def validate_amount(amount):
    try:
        amount = float(amount)
        if amount <= 0 or amount > 1000000:
            return False
        return True
    except ValueError:
        return False
```

---

## Testing Security Fixes

### SQL Injection Test
```python
# Should fail gracefully
username = "admin'--"
password = "' OR '1'='1"
# Result: Login denied (not SQL error)
```

### IDOR Test
```bash
# Try accessing another user's expense
curl http://localhost:5000/expense/1 -H "Cookie: session=other_user_session"
# Result: 403 Forbidden or "Access denied"
```

### XSS Test
```javascript
// Add expense with payload
description = "<script>alert('XSS')</script>"
// Result: Displayed as text, not executed
```

### Session Security Test
```javascript
// In browser console
document.cookie
// Result: Empty or no session cookie visible (httpOnly works)
```

---

## Secure Development Checklist

✅ Use parameterized queries for all database operations  
✅ Implement proper authorization checks  
✅ Never use `| safe` unless absolutely necessary  
✅ Hash passwords with bcrypt/argon2  
✅ Use environment variables for secrets  
✅ Enable httpOnly, Secure, SameSite on cookies  
✅ Implement CSRF protection  
✅ Add security headers  
✅ Validate and sanitize ALL user input  
✅ Implement rate limiting  
✅ Use HTTPS in production  
✅ Keep dependencies updated  
✅ Regular security audits

---

**Document Version:** 1.0  
**Last Updated:** February 2026  
**Author:** [Your Name]
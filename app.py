from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)


# Secret key for sessions - we'll make this insecure on purpose!
# ⚠️ VULNERABILITY: Hardcoded secret key
app.secret_key = 'super_secret_key_123'

# Helper function to connect to database
def get_db_connection():
    conn = sqlite3.connect('expenses.db')
    conn.row_factory = sqlite3.Row  # This lets us access columns by name
    return conn

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Basic validation
        if password != confirm_password:
            return "Passwords don't match! <a href='/register'>Try again</a>"
        
        # VULNERABLE CODE - SQL Injection vulnerability here!
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ⚠️ INSECURE: Using string formatting instead of parameterized queries
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
        
        try:
            cursor.execute(query)
            conn.commit()
            conn.close()
            return f"Account created for {username}! <a href='/login'>Login here</a>"
        except sqlite3.IntegrityError:
            return "Username already exists! <a href='/register'>Try again</a>"
        except Exception as e:
            return f"Error: {e}"
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE CODE - SQL Injection
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        user = cursor.execute(query).fetchone()
        conn.close()
        
        if user:
            # Create session - store user info
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials! <a href='/login'>Try again</a>"
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    username = session['username']
    
    # Get user's expenses
    conn = get_db_connection()
    expenses = conn.execute(
        "SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    
    return render_template('dashboard.html', username=username, expenses=expenses)

@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    return redirect(url_for('home'))

@app.route('/add-expense', methods=['GET', 'POST'])
def add_expense():
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user_id = session['user_id']
        description = request.form['description']
        amount = request.form['amount']
        date = request.form['date']
        
        # VULNERABLE CODE - No input validation/sanitization
        # This will be vulnerable to XSS!
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # At least we're using parameterized query here (not vulnerable to SQL injection)
        cursor.execute(
            "INSERT INTO expenses (user_id, description, amount, date) VALUES (?, ?, ?, ?)",
            (user_id, description, amount, date)
        )
        
        conn.commit()
        conn.close()
        
        return redirect(url_for('dashboard'))
    
    return render_template('add_expense.html')

if __name__ == '__main__':
    app.run(debug=True)
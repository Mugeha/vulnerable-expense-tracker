from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

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
        
        # VULNERABLE CODE - SQL Injection vulnerability here!
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ⚠️ INSECURE: Using string formatting
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        user = cursor.execute(query).fetchone()
        conn.close()
        
        if user:
            return f"Welcome back, {username}! <a href='/dashboard'>Go to dashboard</a>"
        else:
            return "Invalid credentials! <a href='/login'>Try again</a>"
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return "Dashboard - Your expenses will show here"

if __name__ == '__main__':
    app.run(debug=True)
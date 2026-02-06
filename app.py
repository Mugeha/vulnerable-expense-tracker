from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

# Show the login form (GET request)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # User submitted the form
        username = request.form['username']
        password = request.form['password']
        
        # For now, just show what they typed
        return f"You entered: {username} / {password}"
    
    # User just wants to see the form (GET request)
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return "Dashboard - Your expenses will show here"

if __name__ == '__main__':
    app.run(debug=True)
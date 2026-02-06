# Vulnerable Expense Tracker

A deliberately vulnerable web application for learning Application Security concepts.

## 🎯 Purpose
This project demonstrates common web vulnerabilities and their fixes as part of my AppSec learning journey.

## 🛠️ Tech Stack
- **Backend:** Python Flask
- **Database:** SQLite
- **Frontend:** HTML

## 📚 What I'm Learning
- HTTP protocols and methods
- Form handling and user input
- Database interactions with SQL
- Session management
- OWASP Top 10 vulnerabilities

## 🚀 Setup Instructions

### Prerequisites
- Python 3.8+
- pip

### Installation
```bash
# Clone the repository
git clone <your-repo-url>
cd vulnerable-expense-tracker

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install flask

# Initialize database
python database.py

# Run the application
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

## 📂 Project Structure
```
vulnerable-expense-tracker/
├── templates/          # HTML templates
│   ├── home.html
│   └── login.html
├── app.py             # Main Flask application
├── database.py        # Database setup
└── README.md          # This file
```

## 🔐 Security Note
**⚠️ WARNING:** This application contains intentional security vulnerabilities for educational purposes. **DO NOT** use in production or expose to the internet.

## 📅 Progress Log

### Week 1 - Foundations
- [x] Set up Flask application
- [x] Created basic routing
- [x] Built login form
- [x] Set up SQLite database
- [ ] Implement user registration
- [ ] Add session management
- [ ] Create expense tracking functionality

## 🎓 Learning Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [SQL Injection Tutorial](https://portswigger.net/web-security/sql-injection)

---

**Author:** Mugeha Jackline  
**Date Started:** February 6, 2026  
**Goal:** Build a comprehensive AppSec portfolio
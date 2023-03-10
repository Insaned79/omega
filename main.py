import datetime
import sqlite3
import hashlib
import re
import base64
import os
from flask import Flask, request, redirect, render_template, session

import config

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.secret_key = 'qqqq'


def generate_salt():
    random_bytes = os.urandom(16)
    salt = base64.b64encode(random_bytes).decode('utf-8')
    return salt


# Connect to the database
def connect_db():
    conn = sqlite3.connect(config.DB_NAME)
    c = conn.cursor()
    # Create the users table if it does not already exist
    c.execute(f'''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            registration_date TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
            last_login_date TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
            access_level INT DEFAULT 0,
            UNIQUE (username)
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_username ON users (username)")
    conn.commit()

    return conn
    return sqlite3.connect(config.DB_NAME)


# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        password2 = request.form['password2'].encode('utf-8')

        # Connect to the database
        conn = connect_db()
        c = conn.cursor()

        # Check if the username already exists in the database (case-insensitive)
        c.execute("SELECT * FROM users WHERE lower(username)=?", (username.lower(),))
        if c.fetchone():
            return "Error: This username is already taken."
        conn.close()

        # Check if the passwords match
        if password != password2:
            return "Error: Passwords do not match."

        # Check if the password is strong enough
        # if not re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', password.decode()):
        if len(password) < 8 or re.search("[a-z]+", password.decode()) is None or re.search("[A-Z]+",
                                                                                            password.decode()) is None \
                or re.search("[0-9]+", password.decode()) is None:
            return "Error: Password is not strong enough. It must contain at least 8 characters, including uppercase " \
                   "and lowercase letters, numbers, and symbols (@#$%^&+=)."

        # Generate a random salt
        salt = generate_salt()

        # Hash the password and salt

        hash_object = hashlib.sha256((password + salt.encode('utf-8')))
        hex_dig = hash_object.hexdigest()

        # Connect to the database
        conn = connect_db()
        c = conn.cursor()

        # Check if this is the first user
        c.execute("SELECT * FROM users")
        if c.fetchone() is None:
            access_level = 100
        else:
            access_level = 1

        # Add the user to the database
        c.execute("INSERT INTO users (username, password, salt, access_level) VALUES (?, ?, ?, ?)",
                  (username, hex_dig, salt, access_level))
        conn.commit()
        conn.close()

        return redirect('/login')

    return render_template('register.html')


# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Connect to the database
        conn = connect_db()
        c = conn.cursor()

        # Get the user from the database
        c.execute("SELECT id, username, password, access_level, salt FROM users WHERE lower(username)=?",
                  (username.lower(),))
        user = c.fetchone()
        conn.close()

        # Check if the user exists
        if not user:
            return "Error: User not found."

        # Hash the password with the salt
        salt = user[4]
        hash_object = hashlib.sha256((password + salt.encode('utf-8')))
        hex_dig = hash_object.hexdigest()

        # Check if the password is correct
        if hex_dig != user[2]:
            return "Error: Incorrect password."

        # Check if the user's access level is banned (0)
        if user[3] == 0:
            return "Error: Your account is banned."

        # Save the user's id and access level in the session
        session['user_id'] = user[0]
        session['access_level'] = user[3]

        # Update the last login date
        conn = connect_db()
        c = conn.cursor()
        current_date = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        c.execute("UPDATE users SET last_login_date=? WHERE id=?", (current_date, user[0]))
        conn.commit()
        return redirect('/')

    return render_template('login.html')

@app.route('/')
def index():
    if 'user_id' not in session or session['access_level'] <= 0:
        return redirect('/login')
    sections = [("Personal Messages", 1, "personal_messages"),
                ("Announcements", 2, "announcements"),
                ("Forums", 1, "forums"),
                ("User List", 2, "user_list"),
                ("Files", 1, "files"),
                ("Fill Out Questionnaire", 2, "questionnaire"),
                ("Admin Panel", 1, "admin_panel"),
                ("Logout", 2, "logout")]
    return render_template('index.html', sections=sections)

@app.route('/personal_messages')
def personal_messages():
    return "Personal Messages Page"

@app.route('/announcements')
def announcements():
    return "Announcements Page"

@app.route('/forums')
def forums():
    return "Forums Page"

@app.route('/user_list')
def user_list():
    return "User List Page"

@app.route('/files')
def files():
    return "Files Page"

@app.route('/questionnaire')
def questionnaire():
    return "Questionnaire Page"

@app.route('/admin_panel')
def admin_panel():
    return "Admin Panel Page"

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('access_level', None)
    return redirect('/login')


if __name__ == '__main__':
    connect_db()
    app.run(debug=False)

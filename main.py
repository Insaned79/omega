import sqlite3
import hashlib
import re
import random
import string
import base64
import os
from flask import Flask, request, redirect, render_template, session

import config

app = Flask(__name__)
app.secret_key = os.urandom(24)

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
        if not re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', password.decode()):
            return "Error: Password is not strong enough. It must contain at least 8 characters, including uppercase and lowercase letters, numbers, and symbols (@#$%^&+=)."

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
        c.execute("SELECT id, username, password, access_level, salt FROM users WHERE lower(username)=?", (username.lower(),))
        user = c.fetchone()
        conn.close()

        # Check if the user exists
        if not user:
            return "Error: User not found."

        # Hash the password with the salt
        salt = user[4]
        hash_object = hashlib.sha256((password + salt.encode('utf-8')))
        hex_dig = hash_object.hexdigest()
        print(salt)
        # Check if the password is correct
        if hex_dig != user[2]:
            return "Error: Incorrect password."

        # Save the user's id and access level in the session
        session['user_id'] = user[0]
        session['access_level'] = user[3]

        return redirect('/')

    return render_template('login.html')


if __name__ == '__main__':
    connect_db()
    app.run(debug=False)

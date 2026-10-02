import sqlite3
import os

def get_user(user_id):
    # SQL Injection vulnerability
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def ping_server(host):
    # Command injection vulnerability
    os.system(f"ping -c 4 {host}")

def connect_db():
    # Hardcoded secret vulnerability
    db_password = "super_secret_password_123!"
    return db_password

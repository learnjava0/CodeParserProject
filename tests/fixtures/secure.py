import sqlite3
import subprocess

def get_user_secure(user_id):
    # Fixed SQL Injection using parameterized queries
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

def ping_server_secure(host):
    # Fixed Command injection using subprocess with array
    subprocess.run(["ping", "-c", "4", host])

def connect_db_secure(env_password):
    # Fixed hardcoded secret by passing variable
    return env_password

import sqlite3

def get_user(username):
    # Deliberately vulnerable: raw string concatenation into a SQL query
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


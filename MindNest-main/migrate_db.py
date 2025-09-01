import sqlite3

# Connect to the database
conn = sqlite3.connect('journal.db')
cursor = conn.cursor()

# Add the password column to the users table
try:
    cursor.execute("ALTER TABLE users ADD COLUMN password VARCHAR(255)")
    print("Password column added successfully!")
except sqlite3.OperationalError as e:
    print(f"Error: {e}")

# Commit and close
conn.commit()
conn.close()

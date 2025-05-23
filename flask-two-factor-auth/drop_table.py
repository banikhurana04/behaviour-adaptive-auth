import sqlite3

conn = sqlite3.connect('app.db')  # Connect to your SQLite DB file
cursor = conn.cursor()

try:
    cursor.execute('DROP TABLE IF EXISTS alembic_version;')
    print("Table 'alembic_version' dropped successfully.")
except Exception as e:
    print("Error:", e)

conn.commit()
conn.close()

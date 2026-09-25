import psycopg
from getpass import getpass


password = getpass("Enter PostgreSQL password: ")

connection = psycopg.connect(
    host="localhost",
    port=5432,
    dbname="cti_platform",
    user="postgres",
    password=password
)

print("Connected to PostgreSQL successfully!")

cursor = connection.cursor()

cursor.execute("SELECT cve_id, vendor, product, source FROM vulnerabilities;")

rows = cursor.fetchall()

for row in rows:
    print(row)

cursor.close()
connection.close()

print("Connection closed.")
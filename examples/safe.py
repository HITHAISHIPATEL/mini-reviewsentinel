import os

api_key = os.getenv("SERVICE_API_KEY")
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

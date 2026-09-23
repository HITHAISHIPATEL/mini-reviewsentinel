# Deliberately vulnerable example for the demo; do not use in real applications.
api_key = "sk_live_A8f92LmPq7xZ"
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
result = eval(user_expression)

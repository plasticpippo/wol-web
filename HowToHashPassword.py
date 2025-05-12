#Run this Python script to obtain you hashed password

from werkzeug.security import generate_password_hash

password = "your_password"  # Replace with your actual password
hashed_password = generate_password_hash(password)
print(hashed_password)
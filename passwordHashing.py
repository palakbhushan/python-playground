import bcrypt

# Define the password to hash
password = b"hello@123"
BCRYPT_SALT_ROUNDS = 12
salt = bcrypt.gensalt(rounds=BCRYPT_SALT_ROUNDS)
hashed_password = bcrypt.hashpw(password, salt)
print(hashed_password.decode())

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory база: {username: {"username": ..., "hashed_password": ..., "role": ...}}
fake_users_db = {}
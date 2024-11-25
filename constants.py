from datetime import datetime, timedelta

# Constants
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# MongoDB Connection
MONGO_URI = "mongodb://localhost:27017"  # Replace with your MongoDB URI

MAX_TOKEN_EXPIRE_TIME = timedelta(hours=8)
MIN_TOKEN_EXPIRE_TIME = timedelta(hours=1)
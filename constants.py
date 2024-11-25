from datetime import datetime, timedelta

# Constants
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# MongoDB Connection
MONGO_URI = "mongodb://localhost:27017"  # Replace with your MongoDB URI

MAX_TOKEN_EXPIRE_TIME = timedelta(hours=8)
MIN_TOKEN_EXPIRE_TIME = timedelta(hours=1)

GOOGLE_CLIENT_ID = "100660879438-sit6kc7r57dan02tlvg8kkvghltm9n7p.apps.googleusercontent.com"

VALID_APPLICATION_IDS = ["app1", "app2","renote"]
VALID_CLIENT_IDS = ["client1", "client2","renote", "guest"]

SUBSCRIPTION_TYPE_FOR_GUEST = "guest"
COLLECTION_PUSH_NOTIFICATION = "push_notifications"
COLLECTION_GUEST_REGISTRATION = "guest_registration"
DEVICE_REGISTRATION_ENDPOINT = "/api/v1/register-device"

DEFAULT_AUTHORIZATION = {
    "enquiryForm": 10,
    "scheduleMeeting": 500,
    "toDo": 500,
    "visitorForm": 10,
    "mom": 500,
    "ocr": 500,
}
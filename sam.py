import random
import uuid
from datetime import datetime

import jwt
from bson.objectid import ObjectId  # Import ObjectId
from fastapi import FastAPI, Header, HTTPException
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient

# FastAPI and MongoDB setup
app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client.renote_application_database
user_collection = db.user_registration
permissions_collection = db.permissions
user_permissions_collection = db.user_permissions

# Mock send email function


# Pydantic model for user registration
class UserRegistration(BaseModel):
    email: EmailStr
    firstName: str
    lastName: str
    loginType: str = "Microsoft"
    verified: bool = True

@app.post("/user-registration")
async def register_user(
    token: str,
    applicationId: str = Header(...),
    clientId: str = Header(...)
):
    try:
        # Decode the token
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        email = decoded_token.get("upn") or decoded_token.get("email")
        first_name = decoded_token.get("given_name", "Unknown")
        last_name = decoded_token.get("family_name", "Unknown")
        
        if not email:
            raise HTTPException(status_code=400, detail="Email not found in token.")
        
        # Check if user already exists
        existing_user = user_collection.find_one({"email": email})
        if existing_user:
            return {"message": "User already exists."}

        # Generate a UUID for the user
        user_id = str(uuid.uuid4())

        # Fetch permissions from the database
        default_permissions = permissions_collection.find_one({"subscriptionType": "b2c_Free_basic" })
        default_permissions.pop("_id", None)
        if not default_permissions:
            raise HTTPException(status_code=500, detail="Default permissions not found.")

        # Update subscription type
        default_permissions["subscriptionType"] = "b2c_Free_basic"

        # Create the user record
        reset_token = str(random.randint(100000, 999999))  # Generate a reset token
        user_data = {
            "userId": user_id,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "loginType": "Microsoft",
            "verified": True,
            "subscriptionType": "b2c_Free_basic",
            "applicationId": applicationId,
            "clientId": clientId,
            "created_at": datetime.utcnow().isoformat(),
        }

        # Insert user record into `user_registration` collection
        user_collection.insert_one(user_data)

        # Create permissions record
        user_permissions_data = {
            "email": email,
            "userId": user_id,
            "permissions": default_permissions
        }

        # Insert permissions into `user_permissions` collection
        user_permissions_collection.insert_one(user_permissions_data)


        return {
            "message": "User registered successfully.",
            "user": user_data,
            "permissions": user_permissions_data,
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")

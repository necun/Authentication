import os
import random
import smtplib
import uuid
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTPException

import jose
import jwt
import requests
from bson.objectid import ObjectId
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from jose.exceptions import JWTError
from loguru import logger
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext

from constants import *
from logger import *
from models import *

client = AsyncIOMotorClient(MONGO_URI)
db = client["renote_application_database"]
guest_registration_collection = db["guest_registration"]
permissions_collection = db['permissions']
user_registration_collection = db['user_registration']
user_permissions_collection = db['user_permissions']
push_notification_collection = db[COLLECTION_PUSH_NOTIFICATION]
guest_registration_collection = db[COLLECTION_GUEST_REGISTRATION]


authentication = FastAPI()
################################### HELPER  ############################################


def format_success_response(message: str, message_key: str, data: dict, timestamp: str):
    return {
        "status": "200",
        "message": message,
        "messageKey": message_key,
        "data": data,
        "timeStamp": timestamp
    }
    
    
def format_error_response(status: int, message: str, message_key: str, details: str, error_type: str, code: str, instance: str):
    return {"error":{
        "status": status,
        "message": message,
        "messageKey": message_key,
        "details": details,
        "errorType": error_type,
        "code": code,
        "timeStamp": datetime.now().isoformat(),
        "instance": instance}}
    
    
    
# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Dependency to extract token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
def convert_objectid(data):
    if isinstance(data, list):
        return [convert_objectid(item) for item in data]
    if isinstance(data, dict):
        return {key: convert_objectid(value) for key, value in data.items()}
    if isinstance(data, ObjectId):
        return str(data)
    return data


def clean_data(data):
    """
    Recursively clean MongoDB data to make it JSON serializable.
    """
    if isinstance(data, dict):
        return {key: clean_data(value) for key, value in data.items() if key != "_id"}
    elif isinstance(data, list):
        return [clean_data(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    return data


# Function to hash the password with a custom salt
def hash_password_with_salt(password: str, salt: str = None) -> str:
    if not salt:
        # Generate a new salt if none is provided
        salt = os.urandom(16).hex()

    # Combine the password and salt
    salted_password = password + salt

    # Hash the salted password using bcrypt
    hashed_password = pwd_context.hash(salted_password)

    return hashed_password, salt

# Function to verify the password
def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    # Combine the password and salt
    salted_password = password + salt

    # Verify the password
    return pwd_context.verify(salted_password, hashed_password)


def decode_jwt_token(token: str):
    """
    Decodes a JWT token and validates it.

    Args:
        token (str): The JWT token to decode.

    Returns:
        dict: The decoded payload if the token is valid.

    Raises:
        HTTPException: If the token is invalid or expired.
    """
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    
    
def handle_general_exceptions(e: Exception):
    response = format_error_response(500, "Unexpected error", "unexpected-error", str(e), "UnexpectedError", 500105,"renote")
    raise HTTPException(status_code=500, detail=response)

async def send_verification_email(email: str, verification_token: int):
    """
    Helper function to send email verification link.
    Args:
        email (str): Recipient's email address.
        verification_token (int): Unique token for email verification.
    """
    try:
        # Extract the name from the email address
        name = email.split('@')[0]
        
        # SMTP server configuration
        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        smtp_username = 'noreply.renote.ai@gmail.com'
        smtp_password = 'ihde zzml kkip opng'

        # Email content
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = email
        msg['Subject'] = 'Verify Your Email Address'
        
        # Email body with verification link
        body = f"""
        Dear {name},

        yout verification code is: {verification_token}

        If you did not sign up for ReNote AI, please ignore this email.

        Regards,
        ReNote AI
        """
        msg.attach(MIMEText(body, 'plain'))

        # Sending the email
        logger.info("Connecting to SMTP server...")
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            logger.info("Logging into SMTP server...")
            server.login(smtp_username, smtp_password)
            logger.info("Sending verification email...")
            server.send_message(msg)
            logger.info("Verification email sent successfully to", email)

        return {"message": "Verification email sent successfully", "email": email}

    except SMTPException as smtp_err:
        logger.error("SMTPException occurred: %s", smtp_err)
        raise SMTPException("Failed to send verification email. Please try again later.")
    except Exception as e:
        logger.error("Unexpected error occurred: %s", e)
        raise Exception("An unexpected error occurred while sending verification email.")



async def send_reset_email(email: str, reset_token: str, type: str):
    name = email.split('@')[0]
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'noreply.renote.ai@gmail.com'
    smtp_password = 'ihde zzml kkip opng'

    subject = "Reset Your Password"
    body = f"""
    Dear {name},

    Your OTP for resetting your password is {reset_token}.
    Please use this OTP to reset your password.

    If you did not request a password reset, please ignore this email.

    Regards,
    ReNote AI
    """

    msg = MIMEMultipart()
    msg['From'] = smtp_username
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        
async def controller_user_register(uuid: str, status: str, application_id: str, client_id: str,push_notification_token:str):
   
    try:
        if application_id != "renote" or client_id != "demo":
            result  = {"status":400,"code":500400,"message":"Not the permitted headers sent"}
            return JSONResponse(status_code=400, content=result)
       
 
        query_to_insert_guest_registration = {"deviceId":uuid,"status":status,"applicationId":application_id,"clientId":client_id,"permissions":DEFAULT_AUTHORIZATION,"createdAt":datetime.now().strftime('%Y-%m-%d %H:%M:%S +0000')}
        query_to_insert_push_notification_data = {"deviceId":uuid,"subscriptionType":SUBSCRIPTION_TYPE_FOR_GUEST,"notificationToken":push_notification_token,"createdAt":datetime.now().strftime('%Y-%m-%d %H:%M:%S +0000'),"updatedAt":datetime.now().strftime('%Y-%m-%d %H:%M:%S +0000')}
       
        query = {"deviceId": uuid}
       
        checking_user_in_guest_registration_collection = await guest_registration_collection.find_one(query)
        check_user_in_push_notification_collection = await push_notification_collection.find_one(query)
       
       
       
        if checking_user_in_guest_registration_collection and check_user_in_push_notification_collection:
            await push_notification_collection.update_one(query,{"$set":{"notificationToken":push_notification_token,"updatedAt":datetime.now().strftime('%Y-%m-%d %H:%M:%S +0000')}})
            return JSONResponse(status_code=400, content={"status": "400",
                    "message": "UUID already exists and ",
                    "messageKey": "duplicate-entry-error",
                    "details": "1062 (23000): Duplicate entry '2020' for key 'users.PRIMARY'",
                    "errorType": "IntegrityError",
                    "code": 400102,
                    "timeStamp": "2024-08-01T19:25:09.730619",
                    "instance": "renote"})
       
         
        inserting_guest_user = await guest_registration_collection.insert_one(query_to_insert_guest_registration)
       
        inserting_pushNotification_data = await push_notification_collection.insert_one(query_to_insert_push_notification_data)
           
       
           
       
       
        if inserting_guest_user.acknowledged and inserting_pushNotification_data.acknowledged :
            token_data = {
                "deviceId": uuid,
                "applicationId": application_id,
                "clientId": client_id
            }
           
            formatted_response = format_success_response(
                message="Guest User inserted successfully",
                message_key="User_registered",
                data=token_data,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S +0000')
            )
           
            return JSONResponse(status_code=201,content=formatted_response)
 
   
    except HTTPException as he:
        raise he
    except Exception as e:
        handle_general_exceptions(e)

###############################################################################################
# @authentication.post('/guest-registration')
# async def register_guest_user(user: GuestUserRegistration,applicationId: str = Header(...),  
#     clientId: str = Header(...)):
#     # Validate input
#     if clientId != "guest":
#         raise HTTPException(status_code=400, detail="Only guest clients are allowed.")

#     # Create the payload for the token
#     payload = {
#         "deviceId": user.deviceId,
#         "applicationId": applicationId,
#         "clientId": clientId,
#         "exp": datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
#         "iat": datetime.now(),
#     }

#     # Generate JWT token
#     token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

#     # Save to MongoDB
#     guest_data = {
#         "deviceId": user.deviceId,
#         "applicationId": applicationId,
#         "clientId": clientId,
#         "created_at": datetime.now()
#     }
#     guest_permissions = await permissions_collection.find_one({"subscriptionType": "guest_user"})
#     if guest_permissions and "permissions" in guest_permissions:
#         # Append permissions to the guest_data
#         guest_data["permissions"] = guest_permissions["permissions"]
        
#     print(guest_data)

#     await guest_registration_collection.insert_one(guest_data)

#     # Return the token
#     return {"access_token": token, "token_type": "bearer"}

@authentication.post(DEVICE_REGISTRATION_ENDPOINT,
                 description="Use this endpoint for device registration. Submit a UUID, application ID, and client ID to register a device."
)
async def device_registration(
    uuid: str,
    push_notification_token: str,
    application_id: str = Header(...),
    client_id: str = Header(...),
   
):
    if isinstance(db, JSONResponse):
        return db
    logger_instance.info(f"  request received for UUID: {uuid}")
    status = 0
    # user_id = random.randint(10**8, (10**9)-1)
    try:
        response = await controller_user_register(uuid, status, application_id, client_id,push_notification_token)
       
        logger_instance.info(f"  successful for UUID: {uuid}")
        return response
    except HTTPException as he:
        logger_instance.error(f"HTTP error in  : {he.detail}")
        return JSONResponse(status_code=he.status_code, content=he.detail)
    except Exception as e:
        logger_instance.error(f"Error in  : {str(e)}")
        handle_general_exceptions(e)

#################################################################################
@authentication.post("/user-registration")
async def register_user(
    user: UserRegistration,
    applicationId: str = Header(...),
    clientId: str = Header(...)
):
    # Check if the email already exists
    existing_user = await user_registration_collection.find_one({"email": user.email})
    if existing_user:
        return {"message": "User already exists."}

    # Generate a 6-digit random reset token
    reset_token = str(random.randint(100000, 999999))

    # Hash the password if provided
    hashed_password = pwd_context.hash(user.password) if user.password else None

    # Create the user record without userId for now
    user_data = {
        "email": user.email,
        "firstName": user.firstName,
        "lastName": user.lastName,
        "password": hashed_password,
        "loginType": user.loginType,
        "verified": user.verified,
        "subscriptionType": user.subscriptionType,
        "resetToken": reset_token,
        "applicationId": applicationId,
        "clientId": clientId,
        "created_at": datetime.utcnow().isoformat()
    }

    # Insert the user record into MongoDB
    await user_registration_collection.insert_one(user_data)

    # Send the reset token via email
    await send_verification_email(user.email, reset_token)

    return {"message": "User registered successfully. Please verify your email."}

    
###################################################### MICROSOFT ###################################################
@authentication.post("/sso-user-registration")
async def sso_register_user(
    token: str,
    sso_type: str,
    applicationId: str = Header(...),
    clientId: str = Header(...)
):
    try:
        email = None
        first_name = "Unknown"
        last_name = "Unknown"
        account_type = None

        # Handle Microsoft SSO
        if sso_type.lower() == "microsoft":
            print("INNNNNNNNNNNN Microsoft")
            try:
                # Attempt to decode the token
                decoded_token = jwt.decode(token, options={"verify_signature": False})
                email = decoded_token.get("upn") or decoded_token.get("email")
                first_name = decoded_token.get("given_name", "Unknown")
                last_name = decoded_token.get("family_name", "Unknown")
                account_type = "microsoft_office"
            except jwt.InvalidTokenError:
                # Fallback to Microsoft Graph API if decoding fails
                graph_api_url = "https://graph.microsoft.com/v1.0/me"
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.get(graph_api_url, headers=headers)

                if response.status_code == 200:
                    user_info = response.json()
                    email = user_info.get("userPrincipalName") or user_info.get("mail")
                    first_name = user_info.get("givenName", "Unknown")
                    last_name = user_info.get("surname", "Unknown")
                    account_type = "microsoft_personal"
                else:
                    raise HTTPException(
                        status_code=401,
                        detail="Microsoft token validation failed: Unable to decode or fetch user details."
                    )

        # Handle Google SSO
        elif sso_type.lower() == "google":
            try:
                # Verify and decode Google token
                decoded_token = id_token.verify_oauth2_token(token, Request(), GOOGLE_CLIENT_ID)
                email = decoded_token.get("email")
                first_name = decoded_token.get("given_name", "Unknown")
                last_name = decoded_token.get("family_name", "Unknown")
                account_type = "google"
            except ValueError as e:
                # Handle invalid tokens
                raise HTTPException(status_code=400, detail=f"Google token validation failed: {str(e)}")

        else:
            raise HTTPException(status_code=400, detail="Unsupported SSO type.")

        # Validate extracted email
        if not email:
            raise HTTPException(status_code=400, detail="Email not found in token or API response.")

        # Check if user already exists
        existing_user = await user_registration_collection.find_one(
            {"email": email}, {"_id": 0}
        )
        if existing_user:  # User exists
            token_data = {
                "email": existing_user["email"],
                "userId": existing_user["userId"],
                "applicationId": applicationId,
                "clientId": clientId,
                "accountType": account_type,
                "tokenCreatedTime": datetime.utcnow().isoformat(),
                "tokenExpireTime": (datetime.utcnow() + MIN_TOKEN_EXPIRE_TIME).isoformat(),
            }
            auth_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

            # Clean data for serialization
            existing_user = clean_data(existing_user)

            return {
                "message": "User already exists.",
                "token": auth_token,
                "expiresIn": MIN_TOKEN_EXPIRE_TIME.total_seconds(),
                "user": existing_user
            }

        # Generate a UUID for the user
        user_id = str(uuid.uuid4())

        # Fetch permissions (exclude _id)
        default_permissions = await permissions_collection.find_one(
            {"subscriptionType": "b2c_Free_basic"}, {"_id": 0}
        )
        if not default_permissions:
            raise HTTPException(status_code=500, detail="Default permissions not found.")

        # Create user record
        user_data = {
            "userId": user_id,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "loginType": sso_type.capitalize(),
            "verified": True,
            "subscriptionType": "b2c_Free_basic",
            "applicationId": applicationId,
            "clientId": clientId,
            "accountType": account_type,
            "created_at": datetime.utcnow().isoformat(),
        }
        await user_registration_collection.insert_one(user_data)

        # Create permissions record
        user_permissions_data = {
            "email": email,
            "userId": user_id,
            "permissions": default_permissions
        }
        await user_permissions_collection.insert_one(user_permissions_data)

        # Generate token data
        token_data = {
            "email": user_data["email"],
            "userId": user_data["userId"],
            "applicationId": applicationId,
            "clientId": clientId,
            "accountType": account_type,
            "tokenCreatedTime": datetime.utcnow().isoformat(),
            "tokenExpireTime": (datetime.utcnow() + MIN_TOKEN_EXPIRE_TIME).isoformat(),
        }
        auth_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

        # Clean data for serialization
        user_data = clean_data(user_data)
        user_permissions_data = clean_data(user_permissions_data)

        return {
            "message": "User registered successfully.",
            "token": auth_token,
            "expiresIn": MIN_TOKEN_EXPIRE_TIME.total_seconds(),
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))











############################## VERIFICATION ###############################

@authentication.post("/verify-email")
async def verify_email(
    email: str,
    otp: str,
    applicationId: str = Header(...),  # Required application ID from headers
    clientId: str = Header(...)        # Required client ID from headers
):
    # Find the user by email
    user = await user_registration_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Check if the OTP matches
    if user.get("resetToken") != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP.")

    # Mark the user as verified and attach userId
    user_id = str(uuid.uuid4())
    await user_registration_collection.update_one(
        {"email": email},
        {
            "$set": {
                "verified": True,
                "userId": user_id,
                "applicationId": applicationId,
                "clientId": clientId
            },
            "$unset": {"resetToken": ""}  # Set resetToken to null
        }
    )
    
    payload = {
    "email": email,
    "userId": user_id,
    "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),  # Use UTC for expiration
    "iat": datetime.utcnow(),  # Use UTC for issued at
    }
    token = token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "message": "Email verified successfully.",
        "userId": user_id,
        "token": token  # Include the generated token in the response
    }


######################################################

@authentication.post("/set-password")
async def set_password(
    request: SetPasswordModel,
    token: str = Header(...)  # Token passed in headers
):
    # Decode and verify the token
    token = decode_jwt_token(token)

    # Ensure the email in the token matches the provided email
    if token.get("email") != request.email:
        raise HTTPException(status_code=401, detail="Unauthorized: Email does not match token.")

    # Check if the user exists
    user = await user_registration_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Ensure the user is verified
    if not user.get("verified", False):
        raise HTTPException(status_code=403, detail="Email is not verified. Please verify your email before setting the password.")

    # Ensure the password has not already been set
    if user.get("password"):
        raise HTTPException(status_code=400, detail="Password already set. Use update password instead.")

    # Validate passwords
    if request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Password and confirm password do not match.")

    # Hash the new password
    hashed_password = pwd_context.hash(request.password)

    # Update the password in the database
    await user_registration_collection.update_one(
        {"email": request.email},
        {"$set": {"password": hashed_password}}
    )

    # Fetch permissions for "b2c_Free_basic"
    permissions = await permissions_collection.find_one({"subscriptionType": "b2c_Free_basic"})
    # Remove the `_id` field from permissions
    permissions.pop("_id", None)
    if not permissions:
        raise HTTPException(status_code=500, detail="Permissions for subscription type 'b2c_Free_basic' not found.")

    # Generate the user permissions based on the document structure
    # Check if the user permissions already exist
    user_id = user.get("userId") or str(uuid.uuid4())  # Use existing userId or generate a new one
    existing_permissions = await user_permissions_collection.find_one({"email": request.email, "userId": user_id})

    if not existing_permissions:
        # Create user entry in users_permissions collection if it doesn't exist
        user_permissions = {
            "email": request.email,
            "userId": user_id,
            "permissions": permissions
        }
        
        await user_permissions_collection.insert_one(user_permissions)
    
    token_data = {
        "email": user["email"],
        "userId": user["userId"],
        "tokenCreatedTime": datetime.utcnow().isoformat(),
        "tokenExpireTime": (datetime.utcnow() + MIN_TOKEN_EXPIRE_TIME).isoformat()
    }

    # Encode the token
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

    # Update user's subscription type in the user_registration collection
    await user_registration_collection.update_one(
        {"email": request.email},
        {"$set": {"subscriptionType": "b2c_Free_basic"}}
    )

    return {
        "message": "Password set successfully and user permissions updated.",
        "token": token
    }





##################################################################
# Login route
@authentication.post("/login")
async def login(
    request: LoginRequest,
    applicationId: str = Header(...),  # Application ID from headers
    clientId: str = Header(...)        # Client ID from headers
):
    # Check if the user exists
    user = await user_registration_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Verify the password
    if not pwd_context.verify(request.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid password.")

    # Generate token with required fields
    token_data = {
        "email": user["email"],
        "userId": user["userId"],
        "applicationId": applicationId,
        "clientId": clientId,
        "tokenCreatedTime": datetime.utcnow().isoformat(),
        "tokenExpireTime": (datetime.utcnow() + MIN_TOKEN_EXPIRE_TIME).isoformat()
    }

    # Encode the token
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "message": "Login successful.",
        "token": token,
        "expiresIn": MIN_TOKEN_EXPIRE_TIME.total_seconds()
    }
    
    
    
#########################################################################################
@authentication.post("/refresh-token")
async def refresh_token(
    token: str = Header(...)  # Previous token passed in headers
):
    # Decode and validate the existing token
    try:
        token_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired. Please log in again.")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token.")

    # Extract required details from the token
    email = token_data.get("email")
    user_id = token_data.get("userId")
    token_created_time = datetime.fromisoformat(token_data.get("tokenCreatedTime"))
    token_expire_time = datetime.fromisoformat(token_data.get("tokenExpireTime"))

    # Check if the token has exceeded the maximum allowable lifespan
    current_time = datetime.utcnow()
    if current_time - token_created_time > MAX_TOKEN_EXPIRE_TIME:
        raise HTTPException(status_code=401, detail="Session has expired. Please log in again.")

    # Check if the token is within the minimum expiration time for renewal
    remaining_time = token_expire_time - current_time
    if remaining_time > MIN_TOKEN_EXPIRE_TIME:
        raise HTTPException(status_code=400, detail="Token is still valid and does not need to be refreshed.")

    # Generate a new token
    new_token_expire_time = current_time + MIN_TOKEN_EXPIRE_TIME
    new_token_data = {
        "email": email,
        "userId": user_id,
        "tokenCreatedTime": token_data.get("tokenCreatedTime"),  # Keep the original created time
        "tokenExpireTime": new_token_expire_time.isoformat()
    }

    new_token = jwt.encode(new_token_data, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "message": "Token refreshed successfully.",
        "token": new_token,
        "expiresIn": MIN_TOKEN_EXPIRE_TIME.total_seconds()
    }
    
    
    
##################################################################################################
# Helper function to decode and validate JWT token
def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has already expired.")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token.")

# Logout route to expire token immediately
@authentication.post("/logout")
async def logout(token: str = Header(...)):
    try:
        # Decode and validate the token
        payload = decode_jwt_token(token)

        # Set the expiration time to the current time
        payload["exp"] = datetime.utcnow()

        # Generate a new expired token
        expired_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return {
            "message": "Token expired successfully.",
            "expiredToken": expired_token
        }
    except jwt.ExpiredSignatureError:
        return {"message": "Token already expired.", "expiredToken": token}
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token.")
    
########################################################################

@authentication.post("/forgot-password/request-otp")
async def request_otp(email: str):
    # Check if the user exists
    user = await user_registration_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Generate a 6-digit OTP
    otp = str(random.randint(100000, 999999))

    # Store the OTP in the database with an expiry time (optional)
    await user_registration_collection.update_one(
        {"email": email},
        {"$set": {"resetToken": otp}}
    )

    # Send the OTP via email
    await send_reset_email(email, otp, type="reset")

    return {"message": "OTP sent successfully. Please check your email."}

############################################################################
@authentication.post("/forgot-password/verify-otp")
async def verify_otp(email: str, otp: str):
    # Check if the user exists
    user = await user_registration_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Check if the OTP matches
    if user.get("resetToken") != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP.")

    # Remove the OTP from the database after successful verification
    await user_registration_collection.update_one(
        {"email": email},
        {"$unset": {"resetToken": ""}}  # Remove the resetToken field
    )

    return {"message": "OTP verified successfully. You can now reset your password."}

############################################################################
@authentication.post("/forgot-password/reset")
async def reset_password(email: str, password: str, confirm_password: str):
    # Check if the user exists
    user = await user_registration_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Validate passwords
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Password and confirm password do not match.")

    # Hash the new password
    hashed_password = pwd_context.hash(password)

    # Update the password in the database
    await user_registration_collection.update_one(
        {"email": email},
        {"$set": {"password": hashed_password}}
    )

    return {"message": "Password reset successfully."}


################################################################################################
# Dependency to decode and validate the token
from functools import wraps


# Dependency for checking the token
# Dependency to validate the token
async def validate_token(token: str = Header(...)):
    """
    Decodes and validates the JWT token.
    """
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_expire_time = datetime.fromisoformat(payload.get("tokenExpireTime"))

        # Check if token has expired
        if datetime.utcnow() > token_expire_time:
            raise HTTPException(status_code=401, detail="Token has expired.")

        return payload  # Return the decoded payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")

# Dependency to validate applicationId and clientId
async def validate_app_and_client_id(
    applicationId: str = Header(...),
    clientId: str = Header(...)
):
    """
    Validates the applicationId and clientId headers.
    """
    if applicationId not in VALID_APPLICATION_IDS:
        raise HTTPException(status_code=400, detail="Invalid application ID.")
    if clientId not in VALID_CLIENT_IDS:
        raise HTTPException(status_code=400, detail="Invalid client ID.")
    return {"applicationId": applicationId, "clientId": clientId}

# Example route with both dependencies
@authentication.get("/")
async def read_root(
    token_data: dict = Depends(validate_token),
    app_client_data: dict = Depends(validate_app_and_client_id),
):
    """
    A public route that requires token and app/client validation.
    """
    return {
        "message": "Welcome to the FastAPI app",
        "token_data": token_data,
        "app_client_data": app_client_data,
    }

# Protected route example
@authentication.get("/protected-route")
async def protected_route(
    token_data: dict = Depends(validate_token),
    app_client_data: dict = Depends(validate_app_and_client_id),
):
    """
    A protected route that requires both token and app/client validation.
    """
    return {
        "message": "You have accessed a protected route!",
        "token_data": token_data,
        "app_client_data": app_client_data,
    }
from fastapi import FastAPI, HTTPException, Header, Depends
from jose import jwt, JWTError
from constants import *
from models import *
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
import uuid
from passlib.context import CryptContext
import os
from fastapi.security import OAuth2PasswordBearer
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from smtplib import SMTPException
from loguru import logger
import random



client = AsyncIOMotorClient(MONGO_URI)
db = client["renote_application_database"]
guest_registration_collection = db["guest_registration"]
permissions_collection = db['permissions']
user_registration_collection = db['user_registration']
user_permissions_collection = db['user_permissions']


authentication = FastAPI()
###############################################################################
# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Dependency to extract token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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

###############################################################################################
@authentication.post('/guest-registration')
async def register_guest_user(user: GuestUserRegistration,applicationId: str = Header(...),  
    clientId: str = Header(...)):
    # Validate input
    if clientId != "guest":
        raise HTTPException(status_code=400, detail="Only guest clients are allowed.")

    # Create the payload for the token
    payload = {
        "deviceId": user.deviceId,
        "applicationId": applicationId,
        "clientId": clientId,
        "exp": datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.now(),
    }

    # Generate JWT token
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    # Save to MongoDB
    guest_data = {
        "deviceId": user.deviceId,
        "applicationId": applicationId,
        "clientId": clientId,
        "created_at": datetime.now()
    }
    guest_permissions = await permissions_collection.find_one({"subscriptionType": "guest_user"})
    if guest_permissions and "permissions" in guest_permissions:
        # Append permissions to the guest_data
        guest_data["permissions"] = guest_permissions["permissions"]
        
    print(guest_data)

    await guest_registration_collection.insert_one(guest_data)

    # Return the token
    return {"access_token": token, "token_type": "bearer"}

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

    
######################################################


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
        "exp": datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.now(),
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
    token_data = decode_jwt_token(token)
    print(token_data)

    # Ensure the email in the token matches the provided email
    if token_data.get("email") != request.email:
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



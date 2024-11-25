from pydantic import BaseModel, EmailStr

class GuestUserRegistration(BaseModel):
    deviceId: str
    
    
# Pydantic model for User Registration
class UserRegistration(BaseModel):
    email: EmailStr
    firstName: str = None
    lastName: str = None
    password: str = None
    loginType: str = "ReNote"
    verified: bool = False
    subscriptionType: str = None
    resetToken: str = None
    
    
# Pydantic model for setting password
class SetPasswordModel(BaseModel):
    email: EmailStr
    password: str
    confirm_password: str
    
    
# Pydantic model for login
class LoginRequest(BaseModel):
    email: str
    password: str
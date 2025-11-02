from pydantic import BaseModel, EmailStr, model_validator

class RegisterRequest(BaseModel):
    username: str
    phone: str
    email: EmailStr
    password: str
    confirmPassword: str

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password != self.confirmPassword:
            raise ValueError("Passwords do not match")
        return self

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str
    password: str

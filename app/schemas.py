from pydantic import BaseModel,EmailStr
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class Register(BaseModel):
    name:str
    fullname:str
    email:EmailStr
    password:str

class Login(BaseModel):
    name:str
    password:str    

class Blog(BaseModel):
    name:str
    fullname:str
    email:EmailStr
    password:str 
    title:str
    body:str   

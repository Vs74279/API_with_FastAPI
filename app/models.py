from sqlalchemy import Column, Integer, String
from .database import Base
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    fullname = Column(String)
    email=Column(String,unique=True)
    password=Column(String)


class Blog(Base):
    __tablename__ = 'blogs'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    fullname = Column(String)
    email=Column(String,unique=True)
    title=Column(String) 
    body=Column(String)     
    
from fastapi import FastAPI,Depends,HTTPException,status

from . import schemas,models
from sqlalchemy.orm import Session
from .database import SessionLocal,engine
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta


# JWT Configuration
SECRET_KEY = "your_secret_key"  # Replace with a secure key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app=FastAPI()

models.Base.metadata.create_all(bind=engine)
def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()   

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# JWT Helper Functions
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(schemas.oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = db.query(models.User).filter(models.User.email == email).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post('/register',tags=['user'])
def register(request:schemas.Register,db:Session=Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == request.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    hashed_password=pwd_context.hash(request.password)

    user=models.User(name=request.name,fullname=request.fullname,email=request.email,password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post('/login',tags=['user'])
def login(request:schemas.Login,db:Session=Depends(get_db)):
    user=db.query(models.User).filter(models.User.name==request.name).first()
    if not user or not verify_password(request.password,user.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail='invalid credential')
     # Create a JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get('/protected-data', tags=['user'])
def get_protected_data(current_user: models.User = Depends(get_current_user)):
    return {"user": current_user.name, "email": current_user.email, "fullname": current_user.fullname}

@app.post('/create',tags=['blog'])
def create(request:schemas.Blog,db:Session=Depends(get_db)):
    existing_email=db.query(models.Blog).filter(models.Blog.email==request.email).first()
    if existing_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail='Email already exits')
    user=models.Blog(name=request.name,fullname=request.fullname,email=request.email,title=request.title,body=request.body)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.get('/get',tags=['blog'])
def get(db:Session=Depends(get_db)):
    user=db.query(models.Blog).all()
    return user

@app.get('/get/{id}',tags=['blog'])
def get_user(id,db:Session=Depends(get_db)):
    user=db.query(models.Blog).filter(models.Blog.id==id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail='user not found')
    return user

@app.delete('/delete/{id}',tags=['blog'])
def delete(id,db:Session=Depends(get_db)):
    user=db.query(models.Blog).filter(models.Blog.id==id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail='user not found')
    db.delete(user)
    db.commit()
    return 'User Deleted Sucessfullty'

@app.put('/update/{id}',tags=['blog'])
def update(id,request:schemas.Blog,db:Session=Depends(get_db)):
    user=db.query(models.Blog).filter(models.Blog.id==id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail='user not found')
    user.name=request.name
    user.fullname=request.fullname
    user.email=request.email
    user.title=request.title
    user.body=request.body

    db.commit()
    db.refresh(user)
    return 'User updated sucessfully'

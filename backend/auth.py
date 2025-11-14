import jwt, os, datetime
from passlib.context import CryptContext

JWT_SECRET = os.getenv("JWT_SECRET", "my-secret-change-this")
JWT_ALGO = "HS256"

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(pwd_raw):
    return pwd.hash(pwd_raw)


def verify_password(raw, hashed):
    return pwd.verify(raw, hashed)


def create_access_token(data: dict, expires_minutes=120):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)


def decode_access_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except:
        return None

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import datetime, os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./bytebloom.db")

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    scans = relationship("Scan", back_populates="owner")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    region = Column(String(64))
    summary_json = Column(Text)
    report_json = Column(Text)
    owner = relationship("User", back_populates="scans")


def init_db():
    Base.metadata.create_all(bind=engine)

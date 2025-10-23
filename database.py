from sqlalchemy import create_engine, Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import uuid

# Database URL - SQLite uchun
DATABASE_URL = "sqlite:///./chat.db"
# PostgreSQL uchun: "postgresql://user:password@localhost/chatdb"
# MySQL uchun: "mysql+pymysql://user:password@localhost/chatdb"

# Engine yaratish
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=True  # SQL query'larni ko'rsatadi (dev uchun)
)

# Session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class
Base = declarative_base()

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper function
def generate_uuid():
    return str(uuid.uuid4())

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(200), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_online = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    messages = relationship("Message", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(id='{self.id[:8]}...', username='{self.username}')>"


class Message(Base):
    __tablename__ = "messages"
    
    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    is_deleted = Column(Boolean, default=False)
    edited_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="messages")
    
    def __repr__(self):
        return f"<Message(id='{self.id[:8]}...', user='{self.user_id[:8]}...')>"


class ChatRoom(Base):
    __tablename__ = "chat_rooms"
    
    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    is_private = Column(Boolean, default=False)
    created_by = Column(String(36), ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    members = relationship("RoomMember", back_populates="room", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ChatRoom(id='{self.id[:8]}...', name='{self.name}')>"


class RoomMember(Base):
    __tablename__ = "room_members"
    
    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    room_id = Column(String(36), ForeignKey("chat_rooms.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    joined_at = Column(DateTime, default=datetime.utcnow)
    role = Column(String(50), default="member")  # admin, moderator, member
    
    # Relationships
    room = relationship("ChatRoom", back_populates="members")
    
    def __repr__(self):
        return f"<RoomMember(id='{self.id[:8]}...', role='{self.role}')>"


# Database yaratish
def init_db():
    """Barcha jadvallarni yaratish"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database va jadvallar yaratildi!")


# Database tozalash
def drop_db():
    """Barcha jadvallarni o'chirish"""
    Base.metadata.drop_all(bind=engine)
    print("🗑️ Barcha jadvallar o'chirildi!")


if __name__ == "__main__":
    # Database yaratish
    init_db()
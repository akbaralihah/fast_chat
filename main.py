from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from jose import jwt  # python-jose dan
from passlib.context import CryptContext

# Database import
from database import get_db, init_db, User, Message, ChatRoom, RoomMember, SessionLocal

app = FastAPI(title="Chat API with SQLAlchemy", version="2.0.0")

# Sozlamalar
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing - Argon2 (zamonaviyroq va xavfsizroq)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security = HTTPBearer()

# Pydantic schemas
class UserRegister(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str  # UUID
    username: str

class MessageCreate(BaseModel):
    message: str

class MessageResponse(BaseModel):
    id: int
    user_id: str
    username: str
    message: str
    created_at: datetime
    
    class Config:
        from_attributes = True

# Helper funksiyalar
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        username: str = payload.get("username")
        if user_id is None or username is None:
            return None
        return {"user_id": user_id, "username": username}
    except jwt.ExpiredSignatureError:
        return None
    except jwt.JWTError:
        return None

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    user_data = verify_token(token)
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token yaroqsiz yoki muddati tugagan"
        )
    
    # Database'dan user olish
    user = db.query(User).filter(User.id == user_data["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    
    return user

# Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def broadcast(self, message: dict, exclude_user: Optional[str] = None):
        for user_id, connection in list(self.active_connections.items()):
            if exclude_user and user_id == exclude_user:
                continue
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# Startup event
@app.on_event("startup")
async def startup():
    init_db()
    print("✅ Server ishga tushdi!")

# API Endpoints
@app.get("/")
async def root():
    return {
        "message": "Chat API v2.0 - SQLAlchemy + JWT",
        "endpoints": {
            "docs": "/docs",
            "register": "POST /auth/register",
            "login": "POST /auth/login",
            "messages": "GET /messages",
            "websocket": "WS /ws?token=YOUR_TOKEN"
        }
    }

@app.post("/auth/register", response_model=Token)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Ro'yxatdan o'tish"""
    # Username tekshirish
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Bu username band")
    
    # Yangi user (UUID avtomatik yaratiladi)
    new_user = User(
        username=user_data.username,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password)
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Token
    access_token = create_access_token(
        data={"user_id": new_user.id, "username": user_data.username}
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user_id=new_user.id,
        username=user_data.username
    )

@app.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Login"""
    user = db.query(User).filter(User.username == user_data.username).first()
    
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username yoki parol noto'g'ri"
        )
    
    access_token = create_access_token(
        data={"user_id": user.id, "username": user.username}
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user_id=user.id,
        username=user.username
    )

@app.get("/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Joriy user ma'lumotlari"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "online": current_user.is_online,
        "created_at": current_user.created_at,
        "last_seen": current_user.last_seen
    }

@app.get("/users")
async def get_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Barcha foydalanuvchilar"""
    users = db.query(User).filter(User.is_active == True).all()
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "full_name": u.full_name,
                "online": u.is_online,
                "last_seen": u.last_seen
            }
            for u in users
        ],
        "count": len(users)
    }

@app.get("/messages")
async def get_messages(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Xabarlar tarixi"""
    messages = db.query(Message).filter(
        Message.is_deleted == False
    ).order_by(Message.created_at.desc()).limit(limit).all()
    
    messages.reverse()  # Eskidan yangiga
    
    return {
        "messages": [
            {
                "id": m.id,
                "user_id": m.user_id,
                "username": m.user.username,
                "message": m.message,
                "created_at": m.created_at.isoformat()
            }
            for m in messages
        ],
        "count": len(messages)
    }

@app.post("/messages")
async def send_message(
    message_data: MessageCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Xabar yuborish"""
    new_message = Message(
        user_id=current_user.user_id,
        message=message_data.message
    )
    
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    
    # Broadcast
    await manager.broadcast({
        "type": "new_message",
        "data": {
            "id": new_message.id,
            "user_id": new_message.user_id,
            "username": current_user.username,
            "message": new_message.message,
            "created_at": new_message.created_at.isoformat()
        }
    })
    
    return {"message": "Yuborildi", "id": new_message.id}

@app.delete("/messages/{message_id}")
async def delete_message(
    message_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Xabar o'chirish"""
    message = db.query(Message).filter(Message.id == message_id).first()
    
    if not message:
        raise HTTPException(status_code=404, detail="Xabar topilmadi")
    
    if message.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Faqat o'z xabaringizni o'chira olasiz")
    
    message.is_deleted = True
    db.commit()
    
    await manager.broadcast({
        "type": "message_deleted",
        "message_id": message_id
    })
    
    return {"message": "O'chirildi"}

# WebSocket
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    """WebSocket ulanish"""
    user_data = verify_token(token)
    if not user_data:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    user_id = user_data["user_id"]
    
    # User ni database'dan olish
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        
        username = user.username
        
        # Online qilish
        user.is_online = True
        user.last_seen = datetime.utcnow()
        db.commit()
    finally:
        db.close()
    
    await manager.connect(user_id, websocket)
    
    await manager.broadcast({
        "type": "user_joined",
        "user_id": user_id,
        "username": username,
        "timestamp": datetime.utcnow().isoformat()
    })
    
    try:
        while True:
            try:
                data = await websocket.receive_json()
            except:
                text_data = await websocket.receive_text()
                data = {"type": "message", "message": text_data}
            
            if data.get("type") == "message":
                # Har bir xabar uchun yangi session
                db = SessionLocal()
                try:
                    new_message = Message(
                        user_id=user_id,
                        message=data["message"]
                    )
                    
                    db.add(new_message)
                    db.commit()
                    db.refresh(new_message)
                    
                    await manager.broadcast({
                        "type": "new_message",
                        "data": {
                            "id": new_message.id,
                            "user_id": user_id,
                            "username": username,
                            "message": new_message.message,
                            "created_at": new_message.created_at.isoformat()
                        }
                    })
                finally:
                    db.close()
            
            elif data.get("type") == "typing":
                await manager.broadcast({
                    "type": "user_typing",
                    "user_id": user_id,
                    "username": username
                }, exclude_user=user_id)
            
            elif data.get("type") == "ping":
                # Heartbeat uchun
                await websocket.send_json({"type": "pong"})
    
    except WebSocketDisconnect:
        manager.disconnect(user_id)
        
        # Offline qilish
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.is_online = False
                user.last_seen = datetime.utcnow()
                db.commit()
        finally:
            db.close()
        
        await manager.broadcast({
            "type": "user_left",
            "user_id": user_id,
            "username": username,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(user_id)

@app.get("/stats")
async def get_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Statistika"""
    total_users = db.query(User).count()
    online_users = db.query(User).filter(User.is_online == True).count()
    total_messages = db.query(Message).filter(Message.is_deleted == False).count()
    
    return {
        "total_messages": total_messages,
        "total_users": total_users,
        "online_users": online_users,
        "active_connections": len(manager.active_connections)
    }


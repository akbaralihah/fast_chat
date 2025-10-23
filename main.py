from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from jose import jwt
from passlib.context import CryptContext
import asyncio

# Database import
from database import get_db, init_db, User, Message, ChatRoom, RoomMember, SessionLocal

app = FastAPI(title="Chat API with SQLAlchemy", version="2.0.0")

# Sozlamalar
SECRET_KEY = "bla-bla-bar"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 soat (1 kun)

# Tashkent timezone (UTC+5)
TASHKENT_TZ = timezone(timedelta(hours=5))

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
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
    user_id: str
    username: str


class MessageCreate(BaseModel):
    message: str


class MessageResponse(BaseModel):
    id: str
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
    # Tashkent vaqtida expire
    now = datetime.now(TASHKENT_TZ)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": int(expire.timestamp())})
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

    # Database'dan user olish (user_id string UUID)
    user = db.query(User).filter(User.id == user_data["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")

    return user


def get_tashkent_time():
    """Joriy Tashkent vaqtini qaytaradi"""
    return datetime.now(TASHKENT_TZ)


# Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        # Connection'ni darhol qo'shamiz
        self.active_connections[user_id] = websocket
        # Qisqa kuting, connection to'liq barqaror bo'lishi uchun
        import asyncio
        await asyncio.sleep(0.1)

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def broadcast(self, message: dict, exclude_user: Optional[str] = None):
        # Copy qilamiz, iteratsiya vaqtida o'zgarmasligi uchun
        connections = list(self.active_connections.items())

        # Barcha userlarga parallel yuborish
        tasks = []
        for user_id, connection in connections:
            if exclude_user and user_id == exclude_user:
                continue
            tasks.append(self._send_to_user(user_id, connection, message))

        # Barcha tasklar parallel bajariladi
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_to_user(self, user_id: str, connection, message: dict):
        """Bitta userga xabar yuborish"""
        try:
            await connection.send_json(message)
            print(f"✅ Sent to user {user_id}: {message.get('type')}")
        except Exception as e:
            print(f"❌ Broadcast error for user {user_id}: {e}")
            # Ulanish buzilgan bo'lsa, o'chiramiz
            self.disconnect(user_id)


manager = ConnectionManager()


# Startup event
@app.on_event("startup")
async def startup():
    init_db()
    print("✅ Server ishga tushdi!")
    print(f"🕐 Tashkent vaqti: {get_tashkent_time()}")
    print(f"⏰ Token amal qilish muddati: {ACCESS_TOKEN_EXPIRE_MINUTES} daqiqa")


# API Endpoints
@app.get("/")
async def root():
    return {
        "message": "Chat API v2.0 - SQLAlchemy + JWT (Tashkent TZ)",
        "current_time": get_tashkent_time().isoformat(),
        "timezone": "UTC+5 (Tashkent)",
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

    # Yangi user
    new_user = User(
        username=user_data.username,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Token (user.id allaqachon string UUID)
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

    # Token (user.id allaqachon string UUID)
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
        "id": current_user.id,  # allaqachon string
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
                "id": u.id,  # allaqachon string
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
                "id": m.id,  # allaqachon string
                "user_id": m.user_id,  # allaqachon string
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
    """Xabar yuborish (HTTP orqali - ishlatilmasligi kerak, faqat testing uchun)"""
    # current_user.id allaqachon string UUID
    new_message = Message(
        user_id=current_user.id,
        message=message_data.message
    )

    db.add(new_message)
    db.commit()
    db.refresh(new_message)

    # MUHIM: Broadcast await bilan chaqirilishi kerak!
    # Lekin bu sync function, shuning uchun background task ishlatamiz
    import asyncio

    # Agar event loop bo'lmasa, yaratamiz
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # Background task sifatida broadcast
    asyncio.create_task(manager.broadcast({
        "type": "new_message",
        "data": {
            "id": new_message.id,
            "user_id": new_message.user_id,
            "username": current_user.username,
            "message": new_message.message,
            "created_at": new_message.created_at.isoformat()
        }
    }))

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

    # Ikkalasi ham string UUID
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

    user_id = user_data["user_id"]  # string UUID

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
        user.last_seen = get_tashkent_time().replace(tzinfo=None)  # Database uchun naive datetime
        db.commit()
    finally:
        db.close()

    await manager.connect(user_id, websocket)

    # Ulanish tasdiqini yuborish
    await websocket.send_json({
        "type": "connection_success",
        "user_id": user_id,
        "username": username,
        "timestamp": get_tashkent_time().isoformat()
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
                        user_id=user_id,  # string UUID
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
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": get_tashkent_time().isoformat()
                })

    except WebSocketDisconnect:
        manager.disconnect(user_id)

        # Offline qilish
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.is_online = False
                user.last_seen = get_tashkent_time().replace(tzinfo=None)
                db.commit()
        finally:
            db.close()

        await manager.broadcast({
            "type": "user_left",
            "user_id": user_id,
            "username": username,
            "timestamp": get_tashkent_time().isoformat()
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
        "active_connections": len(manager.active_connections),
        "current_time": get_tashkent_time().isoformat()
    }


@app.get("/health")
async def health_check():
    """Server holati"""
    return {
        "status": "ok",
        "timezone": "UTC+5 (Tashkent)",
        "current_time": get_tashkent_time().isoformat(),
        "uptime": "running"
    }
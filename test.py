import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

app = FastAPI(title="In-Memory Chat API", version="3.1.0")

# JWT settings
SECRET_KEY = "bla-bla-bar"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 1 kun

# Tashkent TZ
TASHKENT_TZ = timezone(timedelta(hours=5))
security = HTTPBearer()
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# 🧠 In-memory "database"
USERS = {}  # {user_id: {...}}
MESSAGES = []  # [ {...}, {...} ]

# 🔗 CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================
# 🧩 Helper funksiyalar
# ==============================
def get_tashkent_time():
    return datetime.now(TASHKENT_TZ)


def generate_uuid():
    return str(uuid.uuid4())


def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str):
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict):
    expire = get_tashkent_time() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"user_id": payload.get("user_id"), "username": payload.get("username")}
    except Exception:
        return None


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    user_data = verify_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Yaroqsiz token")
    user = USERS.get(user_data["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    return user


# ==============================
# 📡 Connection manager
# ==============================
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def broadcast(self, message: dict, exclude_user: Optional[str] = None):
        tasks = []
        for uid, ws in self.active_connections.items():
            if exclude_user and uid == exclude_user:
                continue
            try:
                tasks.append(ws.send_json(message))
            except Exception:
                pass
        await asyncio.gather(*tasks, return_exceptions=True)


manager = ConnectionManager()


# ==============================
# 📍 API
# ==============================
@app.get("/")
async def root():
    return {
        "message": "In-memory Chat API v3.1",
        "docs": "/docs",
        "users_count": len(USERS),
        "messages_count": len(MESSAGES)
    }


class UserRegister(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None


@app.post("/auth/register")
async def register(user: UserRegister):
    if any(u["username"] == user.username for u in USERS.values()):
        raise HTTPException(status_code=400, detail="Bu username band")

    user_id = generate_uuid()
    USERS[user_id] = {
        "id": user_id,
        "username": user.username,
        "full_name": user.full_name,
        "hashed_password": get_password_hash(user.password),
        "is_online": False,
        "last_seen": get_tashkent_time()
    }

    token = create_access_token({"user_id": user_id, "username": user.username})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user_id,
        "username": user.username
    }


class UserLogin(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
async def login(user: UserLogin):
    for u in USERS.values():
        if u["username"] == user.username and verify_password(user.password, u["hashed_password"]):
            token = create_access_token({"user_id": u["id"], "username": u["username"]})
            return {
                "access_token": token,
                "token_type": "bearer",
                "user_id": u["id"],
                "username": u["username"]
            }
    raise HTTPException(status_code=401, detail="Noto‘g‘ri login yoki parol")


@app.get("/users")
async def get_users():
    return {"users": list(USERS.values()), "count": len(USERS)}


@app.get("/messages")
async def get_messages(limit: int = 50):
    return {"messages": MESSAGES[-limit:], "count": len(MESSAGES)}


# ===============================
# ========== WebSocket ==========
# ===============================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    user_data = verify_token(token)
    if not user_data:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_id = user_data["user_id"]
    username = user_data["username"]

    if user_id not in USERS:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    USERS[user_id]["is_online"] = True
    USERS[user_id]["last_seen"] = get_tashkent_time()

    await manager.connect(user_id, websocket)
    await manager.broadcast({
        "type": "user_joined",
        "user_id": user_id,
        "username": username
    })

    await websocket.send_json({"type": "connected", "user_id": user_id, "username": username})

    try:
        while True:
            try:
                data = await websocket.receive_json()
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Xabar JSON formatida bo‘lishi kerak."
                })
                continue

            msg_type = data.get("type")

            if msg_type == "message":
                msg_id = generate_uuid()
                message = {
                    "id": msg_id,
                    "user_id": user_id,
                    "username": username,
                    "message": data["message"],
                    "created_at": get_tashkent_time().isoformat()
                }
                MESSAGES.append(message)
                await manager.broadcast({"type": "new_message", "data": message})

            elif msg_type == "typing":
                await manager.broadcast({
                    "type": "user_typing",
                    "user_id": user_id,
                    "username": username
                }, exclude_user=user_id)

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong", "timestamp": get_tashkent_time().isoformat()})

            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Noma’lum xabar turi: {msg_type}"
                })

    except WebSocketDisconnect:
        USERS[user_id]["is_online"] = False
        USERS[user_id]["last_seen"] = get_tashkent_time()
        manager.disconnect(user_id)
        await manager.broadcast({
            "type": "user_left",
            "user_id": user_id,
            "username": username
        })


@app.get("/stats")
async def stats():
    return {
        "users": len(USERS),
        "messages": len(MESSAGES),
        "online_users": sum(1 for u in USERS.values() if u["is_online"]),
        "active_connections": len(manager.active_connections),
        "current_time": get_tashkent_time().isoformat()
    }

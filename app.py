import re
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import jwt
from aiohttp import web
from pydantic import BaseModel, EmailStr, ValidationError, constr
import aiosqlite

SECRET_KEY = "54bd13db7d65ef38998956fa13fa701dc52b5f38bd72163d320ab0d7362d780d"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def create_access_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise web.HTTPUnauthorized(reason="Срок действия токена истек")
    except jwt.InvalidTokenError:
        raise web.HTTPUnauthorized(reason="Недействительный токен")

class UserRegister(BaseModel):
    email: EmailStr
    password: constr(min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class AdCreate(BaseModel):
    title: constr(min_length=1, strip_whitespace=True)
    description: str

class AdUpdate(BaseModel):
    title: Optional[constr(min_length=1, strip_whitespace=True)] = None
    description: Optional[str] = None

@web.middleware
async def jwt_middleware(request: web.Request, handler):
    path = request.path
    method = request.method

    open_routes = [
        (method == "POST" and path == "/register"),
        (method == "POST" and path == "/login"),
        (method == "GET" and (path == "/ads" or re.match(r"^/ads/\d+$", path)))
    ]

    if any(open_routes):
        return await handler(request)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return web.json_response({"error": "Отсутствует или неверный заголовок авторизации"}, status=401)

    token = auth_header.split(" ")[1]
    try:
        payload = decode_access_token(token)
        request["user_id"] = int(payload["sub"])
    except web.HTTPUnauthorized as e:
        return web.json_response({"error": e.reason}, status=401)

    return await handler(request)

async def init_db(app: web.Application):
    db = await aiosqlite.connect("ads.db")
    db.row_factory = aiosqlite.Row
    await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    await db.execute("""
        CREATE TABLE IF NOT EXISTS ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    await db.commit()
    app["db"] = db

async def cleanup_db(app: web.Application):
    await app["db"].close()

async def register(request: web.Request):
    try:
        data = await request.json()
        validated = UserRegister(**data)
    except ValidationError as e:
        return web.json_response({"error": e.errors()}, status=422)
    except Exception:
        return web.json_response({"error": "Некорректный JSON"}, status=400)

    email = validated.email
    password = validated.password
    db = request.app["db"]

    cursor = await db.execute("SELECT id FROM users WHERE email = ?", (email,))
    if await cursor.fetchone():
        return web.json_response({"error": "Email уже зарегистрирован"}, status=409)

    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    cursor = await db.execute(
        "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
        (email, hash_password(password), created_at)
    )
    await db.commit()
    user_id = cursor.lastrowid
    return web.json_response(
        {"id": user_id, "email": email, "created_at": created_at},
        status=201,
    )

async def login(request: web.Request):
    try:
        data = await request.json()
        validated = UserLogin(**data)
    except ValidationError as e:
        return web.json_response({"error": e.errors()}, status=422)
    except Exception:
        return web.json_response({"error": "Некорректный JSON"}, status=400)

    email = validated.email
    password = validated.password
    db = request.app["db"]

    cursor = await db.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
    row = await cursor.fetchone()
    if not row or not check_password(password, row["password_hash"]):
        return web.json_response({"error": "Неверный email или пароль"}, status=401)

    token = create_access_token(row["id"])
    return web.json_response({"access_token": token, "token_type": "bearer"})

async def create_ad(request: web.Request):
    try:
        data = await request.json()
        validated = AdCreate(**data)
    except ValidationError as e:
        return web.json_response({"error": e.errors()}, status=422)
    except Exception:
        return web.json_response({"error": "Некорректный JSON"}, status=400)

    user_id = request["user_id"]
    db = request.app["db"]
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    cursor = await db.execute(
        "INSERT INTO ads (title, description, created_at, user_id) VALUES (?, ?, ?, ?)",
        (validated.title, validated.description, created_at, user_id)
    )
    await db.commit()
    ad_id = cursor.lastrowid
    return web.json_response({
        "id": ad_id,
        "title": validated.title,
        "description": validated.description,
        "created_at": created_at,
        "user_id": user_id,
    }, status=201)

async def get_ad(request: web.Request):
    try:
        ad_id = int(request.match_info["id"])
    except ValueError:
        return web.json_response({"error": "Некорректный id"}, status=400)

    db = request.app["db"]
    cursor = await db.execute("SELECT id, title, description, created_at, user_id FROM ads WHERE id = ?", (ad_id,))
    ad = await cursor.fetchone()
    if ad is None:
        return web.json_response({"error": "Объявление не найдено"}, status=404)
    return web.json_response(dict(ad))

async def update_ad(request: web.Request):
    try:
        ad_id = int(request.match_info["id"])
    except ValueError:
        return web.json_response({"error": "Некорректный id"}, status=400)

    user_id = request.get("user_id")
    if not user_id:
        return web.json_response({"error": "Не авторизован"}, status=401)

    db = request.app["db"]
    cursor = await db.execute("SELECT user_id FROM ads WHERE id = ?", (ad_id,))
    ad = await cursor.fetchone()
    if ad is None:
        return web.json_response({"error": "Объявление не найдено"}, status=404)
    if ad["user_id"] != user_id:
        return web.json_response({"error": "Доступ запрещен"}, status=403)

    try:
        data = await request.json()
        validated = AdUpdate(**data)
    except ValidationError as e:
        return web.json_response({"error": e.errors()}, status=422)
    except Exception:
        return web.json_response({"error": "Некорректный JSON"}, status=400)

    if validated.title is not None:
        await db.execute("UPDATE ads SET title = ? WHERE id = ?", (validated.title, ad_id))
    if validated.description is not None:
        await db.execute("UPDATE ads SET description = ? WHERE id = ?", (validated.description, ad_id))
    await db.commit()

    cursor = await db.execute("SELECT id, title, description, created_at, user_id FROM ads WHERE id = ?", (ad_id,))
    updated_ad = await cursor.fetchone()
    return web.json_response(dict(updated_ad))

async def delete_ad(request: web.Request):
    try:
        ad_id = int(request.match_info["id"])
    except ValueError:
        return web.json_response({"error": "Некорректный id"}, status=400)

    user_id = request.get("user_id")
    if not user_id:
        return web.json_response({"error": "Не авторизован"}, status=401)

    db = request.app["db"]
    cursor = await db.execute("SELECT user_id FROM ads WHERE id = ?", (ad_id,))
    ad = await cursor.fetchone()
    if ad is None:
        return web.json_response({"error": "Объявление не найдено"}, status=404)
    if ad["user_id"] != user_id:
        return web.json_response({"error": "Доступ запрещен"}, status=403)

    await db.execute("DELETE FROM ads WHERE id = ?", (ad_id,))
    await db.commit()
    return web.Response(status=204)

async def list_ads(request: web.Request):
    db = request.app["db"]
    cursor = await db.execute("SELECT id, title, description, created_at, user_id FROM ads")
    ads = [dict(row) for row in await cursor.fetchall()]
    return web.json_response(ads)

app = web.Application(middlewares=[jwt_middleware])

app.router.add_post("/register", register)
app.router.add_post("/login", login)
app.router.add_post("/ads", create_ad)
app.router.add_get("/ads", list_ads)
app.router.add_get(r"/ads/{id:\d+}", get_ad)
app.router.add_put(r"/ads/{id:\d+}", update_ad)
app.router.add_delete(r"/ads/{id:\d+}", delete_ad)

app.on_startup.append(init_db)
app.on_cleanup.append(cleanup_db)

if __name__ == "__main__":
    web.run_app(app, port=8080)

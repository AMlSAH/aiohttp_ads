import re
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import jwt
from aiohttp import web
from pydantic import BaseModel, EmailStr, ValidationError, constr

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


users = {}
next_user_id = 1
ads = {}
next_ad_id = 1


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

    if any(u["email"] == email for u in users.values()):
        return web.json_response({"error": "Email уже зарегистрирован"}, status=409)

    global next_user_id
    user = {
        "id": next_user_id,
        "email": email,
        "password_hash": hash_password(password),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    users[next_user_id] = user
    next_user_id += 1

    return web.json_response(
        {"id": user["id"], "email": user["email"], "created_at": user["created_at"]},
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

    user = next((u for u in users.values() if u["email"] == email), None)
    if not user or not check_password(password, user["password_hash"]):
        return web.json_response({"error": "Неверный email или пароль"}, status=401)

    token = create_access_token(user["id"])
    return web.json_response({"access_token": token, "token_type": "bearer"})


async def create_ad(request: web.Request):
    try:
        data = await request.json()
        validated = AdCreate(**data)
    except ValidationError as e:
        return web.json_response({"error": e.errors()}, status=422)
    except Exception:
        return web.json_response({"error": "Некорректный JSON"}, status=400)

    global next_ad_id
    user_id = request["user_id"]
    ad = {
        "id": next_ad_id,
        "title": validated.title,
        "description": validated.description,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "user_id": user_id,
    }
    ads[next_ad_id] = ad
    next_ad_id += 1
    return web.json_response(ad, status=201)


async def get_ad(request: web.Request):
    ad_id = int(request.match_info["id"])
    ad = ads.get(ad_id)
    if ad is None:
        return web.json_response({"error": "Объявление не найдено"}, status=404)
    return web.json_response(ad)


async def update_ad(request: web.Request):
    ad_id = int(request.match_info["id"])
    ad = ads.get(ad_id)
    if ad is None:
        return web.json_response({"error": "Объявление не найдено"}, status=404)
    user_id = request.get("user_id")
    if not user_id:
        return web.json_response({"error": "Не авторизован"}, status=401)
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
        ad["title"] = validated.title
    if validated.description is not None:
        ad["description"] = validated.description

    return web.json_response(ad)


async def delete_ad(request: web.Request):
    ad_id = int(request.match_info["id"])
    ad = ads.get(ad_id)
    if ad is None:
        return web.json_response({"error": "Объявление не найдено"}, status=404)
    user_id = request.get("user_id")
    if not user_id:
        return web.json_response({"error": "Не авторизован"}, status=401)
    if ad["user_id"] != user_id:
        return web.json_response({"error": "Доступ запрещен"}, status=403)

    del ads[ad_id]
    return web.Response(status=204)


async def list_ads(request: web.Request):
    return web.json_response(list(ads.values()))


app = web.Application(middlewares=[jwt_middleware])

app.router.add_post("/register", register)
app.router.add_post("/login", login)
app.router.add_post("/ads", create_ad)
app.router.add_get("/ads", list_ads)
app.router.add_get(r"/ads/{id:\d+}", get_ad)
app.router.add_put(r"/ads/{id:\d+}", update_ad)
app.router.add_delete(r"/ads/{id:\d+}", delete_ad)

if __name__ == "__main__":
    web.run_app(app, port=8080)

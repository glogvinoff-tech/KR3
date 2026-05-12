import os
import secrets
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import sqlite3

from database import get_db_connection, init_db

load_dotenv()

# ========== КОНФИГУРАЦИЯ ==========
MODE = os.getenv("MODE", "DEV")
SECRET_KEY = os.getenv("SECRET_KEY", "my-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "secret123")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # Отключаем стандартную документацию
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_basic = HTTPBasic()
security_bearer = HTTPBearer()

init_db()  # Создаём таблицы

# ========== PYDANTIC МОДЕЛИ ==========
class UserBase(BaseModel):
    username: str

class User(UserBase):
    password: str

class UserInDB(UserBase):
    hashed_password: str

class UserRegister(BaseModel):
    username: str
    password: str

class TodoCreate(BaseModel):
    title: str
    description: str

class TodoUpdate(BaseModel):
    title: str
    description: str
    completed: bool

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
def get_user_from_db(username: str):
    """Поиск пользователя в SQLite"""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(user) if user else None

def create_access_token(username: str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None

def get_current_user(token: str = Depends(security_bearer)):
    username = verify_access_token(token.credentials)
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = get_user_from_db(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

def authenticate_basic(credentials: HTTPBasicCredentials = Depends(security_basic)):
    """Базовая аутентификация для /login-basic"""
    user = get_user_from_db(credentials.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    if not pwd_context.verify(credentials.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user

# ========== ЗАДАНИЕ 8.1 (регистрация без хеширования) ==========
@app.post("/register-sqlite")
async def register_sqlite(user: UserRegister):
    """Регистрация в SQLite (пароль в открытом виде)"""
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, user.password))
        conn.commit()
        return {"message": "User registered successfully!"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

# ========== ЗАДАНИЕ 6.2 и 6.5 (регистрация с хешированием) ==========
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    """Регистрация с хешированием пароля"""
    if get_user_from_db(user.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")
    
    conn = get_db_connection()
    hashed = pwd_context.hash(user.password)
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed))
    conn.commit()
    conn.close()
    return {"message": "New user created"}

# ========== ЗАДАНИЕ 6.2 (Basic Auth логин) ==========
@app.get("/login-basic")
async def login_basic(user: dict = Depends(authenticate_basic)):
    """Basic Auth логин"""
    return {"message": f"Welcome, {user['username']}!"}

# ========== ЗАДАНИЕ 6.4 и 6.5 (JWT логин) ==========
@app.post("/login")
async def login(user: UserRegister):
    """JWT логин"""
    db_user = get_user_from_db(user.username)
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not pwd_context.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization failed")
    
    access_token = create_access_token(user.username)
    return {"access_token": access_token, "token_type": "bearer"}

# ========== ЗАДАНИЕ 6.4 (Защищённый ресурс) ==========
@app.get("/protected_resource")
async def protected_resource(current_user: dict = Depends(get_current_user)):
    """Защищённый ресурс (требует JWT)"""
    return {"message": "Access granted"}

# ========== ЗАДАНИЕ 7.1 (RBAC) ==========
def get_current_user_with_role(token: str = Depends(security_bearer)):
    username = verify_access_token(token.credentials)
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = get_user_from_db(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    # Роли: admin (для пользователя "admin"), остальные - user
    role = "admin" if username == "admin" else "user"
    return {**user, "role": role}

def require_role(required_role: str):
    def role_checker(current_user: dict = Depends(get_current_user_with_role)):
        if current_user["role"] != required_role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return role_checker

@app.get("/admin-resource")
async def admin_resource(user: dict = Depends(require_role("admin"))):
    return {"message": f"Admin access granted to {user['username']}"}

@app.get("/user-resource")
async def user_resource(user: dict = Depends(require_role("user"))):
    return {"message": f"User access granted to {user['username']}"}

# ========== ЗАДАНИЕ 8.2 (CRUD Todo) ==========
@app.post("/todos", status_code=status.HTTP_201_CREATED)
async def create_todo(todo: TodoCreate):
    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO todos (title, description, completed) VALUES (?, ?, 0)",
        (todo.title, todo.description)
    )
    conn.commit()
    new_todo = conn.execute("SELECT * FROM todos WHERE id = ?", (cursor.lastrowid,)).fetchone()
    conn.close()
    return dict(new_todo)

@app.get("/todos/{todo_id}")
async def get_todo(todo_id: int):
    conn = get_db_connection()
    todo = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    conn.close()
    if not todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    return dict(todo)

@app.put("/todos/{todo_id}")
async def update_todo(todo_id: int, todo: TodoUpdate):
    conn = get_db_connection()
    conn.execute(
        "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
        (todo.title, todo.description, todo.completed, todo_id)
    )
    conn.commit()
    updated = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    conn.close()
    if not updated:
        raise HTTPException(status_code=404, detail="Todo not found")
    return dict(updated)

@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: int):
    conn = get_db_connection()
    todo = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if not todo:
        conn.close()
        raise HTTPException(status_code=404, detail="Todo not found")
    conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    conn.commit()
    conn.close()
    return {"message": "Todo deleted successfully"}

# ========== ЗАДАНИЕ 6.3 (Документация с защитой) ==========
def setup_documentation():
    if MODE == "PROD":
        # PROD: документация полностью отключена (просто не добавляем эндпоинты)
        pass
    elif MODE == "DEV":
        @app.get("/docs", include_in_schema=False)
        async def custom_swagger_ui_html(credentials: HTTPBasicCredentials = Depends(security_basic)):
            if not secrets.compare_digest(credentials.username, DOCS_USER) or \
               not secrets.compare_digest(credentials.password, DOCS_PASSWORD):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                    headers={"WWW-Authenticate": "Basic"},
                )
            return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")
        
        @app.get("/openapi.json", include_in_schema=False)
        async def get_open_api(credentials: HTTPBasicCredentials = Depends(security_basic)):
            if not secrets.compare_digest(credentials.username, DOCS_USER) or \
               not secrets.compare_digest(credentials.password, DOCS_PASSWORD):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    headers={"WWW-Authenticate": "Basic"},
                )
            return get_openapi(title="My API", version="1.0.0", routes=app.routes)
        
        # /redoc скрыт
    else:
        raise ValueError(f"Invalid MODE: {MODE}. Use DEV or PROD")

setup_documentation()

# ========== ТЕСТОВЫЙ ЭНДПОИНТ ==========
@app.get("/test")
async def test():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
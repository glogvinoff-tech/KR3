# README.md

## Установка и запуск

1. Создайте виртуальное окружение: `python -m venv venv`
2. Активируйте окружение: Windows: `venv\Scripts\activate`, Mac/Linux: `source venv/bin/activate`
3. Установите зависимости: `pip install fastapi uvicorn passlib[bcrypt] python-dotenv pyjwt`
4. Создайте файл `.env` с содержимым: MODE=DEV, DOCS_USER=admin, DOCS_PASSWORD=secret123, SECRET_KEY=my-super-secret-key
5. Запустите приложение: `uvicorn main:app --reload --host 127.0.0.1 --port 8000` или `python main.py`

## Тестирование curl

Регистрация: `curl -X POST http://127.0.0.1:8000/register -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"123456\"}"`

JWT логин: `curl -X POST http://127.0.0.1:8000/login -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"123456\"}"`

Basic Auth логин: `curl -u alice:123456 http://127.0.0.1:8000/login-basic`

Защищённый ресурс: `curl -H "Authorization: Bearer ТОКЕН" http://127.0.0.1:8000/protected_resource`

Создать Todo: `curl -X POST http://127.0.0.1:8000/todos -H "Content-Type: application/json" -d "{\"title\":\"Buy milk\",\"description\":\"Go to store\"}"`

Получить Todo: `curl http://127.0.0.1:8000/todos/1`

Обновить Todo: `curl -X PUT http://127.0.0.1:8000/todos/1 -H "Content-Type: application/json" -d "{\"title\":\"Buy bread\",\"description\":\"Fresh\",\"completed\":true}"`

Удалить Todo: `curl -X DELETE http://127.0.0.1:8000/todos/1`

Документация: открыть в браузере `http://127.0.0.1:8000/docs`, логин: admin, пароль: secret123
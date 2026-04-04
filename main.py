from fastapi import FastAPI
from routes import router

# XiCipher - потоковый шифр на основе ГПСЧ
#
# Запуск:
# pip install fastapi uvicorn
# python main.py
#
# Дока: http://localhost:8000/docs

app = FastAPI(
    title="XiCipher API",
    description="Потоковый шифр на основе ГПСЧ - XiCipher",
    version="1.0.0",
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    print()
    print("XiCipher API запускается...")
    print("  http://localhost:8000 - Главная")
    print("  http://localhost:8000/docs - Swagger")
    print("  http://localhost:8000/info - Описание алгоритма")
    print()
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

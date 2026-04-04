import secrets
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from cipher import encrypt, decrypt, derive_key
from models import (
    EncryptRequest, EncryptResponse,
    DecryptRequest, DecryptResponse,
    KeygenResponse, AlgoInfo,
)

# Эндпоинты FastAPI

router = APIRouter()
@router.get("/", response_class=HTMLResponse, include_in_schema=False)

# Главная страница с описанием API
def index():
    return """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <title>XiCipher API</title>
      <style>
        body { font-family: monospace; background: #0d1117; color: #c9d1d9;
               max-width: 760px; margin: 60px auto; padding: 0 24px; }
        h1   { color: #58a6ff; }
        h2   { color: #79c0ff; margin-top: 32px; }
        code { background: #161b22; padding: 2px 6px; border-radius: 4px;
               color: #ff7b72; }
        pre  { background: #161b22; padding: 16px; border-radius: 8px;
               overflow-x: auto; border: 1px solid #30363d; }
        .method { color: #3fb950; font-weight: bold; }
        a    { color: #58a6ff; }
      </style>
    </head>
    <body>
      <h1>XiCipher API v1.0</h1>
      <p>Потоковый шифр на основе ГПСЧ с ARX-ядром и RC4-KSA S-блоком.</p>

      <h2>Endpoints</h2>
      <pre><span class="method">GET</span>  /info             - описание алгоритма
<span class="method">POST</span> /keygen           - сгенерировать ключ
<span class="method">POST</span> /encrypt          - зашифровать текст
<span class="method">POST</span> /decrypt          - расшифровать текст
<span class="method">GET</span>  /docs             - Swagger UI</pre>

      <h2>Пример шифрования</h2>
      <pre>curl -X POST http://localhost:8000/encrypt \\
     -H "Content-Type: application/json" \\
     -d '{"text": "Привет!", "password": "мой_ключ"}'</pre>

      <h2>Пример расшифрования</h2>
      <pre>curl -X POST http://localhost:8000/decrypt \\
     -H "Content-Type: application/json" \\
     -d '{"ciphertext": "...", "nonce": "...", "password": "мой_ключ"}'</pre>

      <p><a href="/docs">Swagger UI</a> | <a href="/info">Описание алгоритма</a></p>
    </body>
    </html>
    """


@router.get("/info", response_model=AlgoInfo, summary="Описание алгоритма")
def get_info():
    return AlgoInfo(
        name="XiCipher",
        version="v1",
        type="Потоковый симметричный шифр",
        block_size="1 байт (потоковый)",
        key_size=256,
        prng="ARX-PRNG (8 раундов Add-Rotate-XOR) + RC4-KSA S-блок",
        description=(
            "Ключ преобразуется через SHA-256 в 32 байта. "
            "Генерируется случайный nonce (8 байт), из него и ключа "
            "через SHA-256 получается seed для ГПСЧ. ГПСЧ выдает поток "
            "псевдослучайных байт. S-блок строится из ключа через RC4-KSA. "
            "Шифрование: cipher[i] = sbox[plain[i] XOR keystream[i]]. "
            "Nonce обеспечивает уникальность каждого шифрования."
        ),
    )

# Генерирует случайный пароль и 256-битный ключ
@router.post("/keygen", response_model=KeygenResponse, summary="Сгенерировать ключ")
def keygen():

    password = secrets.token_urlsafe(24)
    key_bytes = derive_key(password)
    return KeygenResponse(
        password=password,
        key_hex=key_bytes.hex(),
        bits=256,
    )


@router.post("/encrypt", response_model=EncryptResponse, summary="Зашифровать текст")
def encrypt_text(req: EncryptRequest):
    if not req.text:
        raise HTTPException(400, "Текст не может быть пустым")
    if not req.password:
        raise HTTPException(400, "Пароль не может быть пустым")

    result = encrypt(req.text, req.password)
    return EncryptResponse(**result)


@router.post("/decrypt", response_model=DecryptResponse, summary="Расшифровать текст")
def decrypt_text(req: DecryptRequest):
    try:
        plaintext = decrypt(req.ciphertext, req.nonce, req.password)
        return DecryptResponse(plaintext=plaintext)
    except Exception as e:
        raise HTTPException(400, f"Ошибка расшифрования: {e}")

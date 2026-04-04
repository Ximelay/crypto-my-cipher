from pydantic import BaseModel

# Pydantic-модели для запросов и ответов API

class EncryptRequest(BaseModel):
    text: str
    password: str


class EncryptResponse(BaseModel):
    ciphertext: str # base64
    nonce: str # hex
    algo: str
    length: int


class DecryptRequest(BaseModel):
    ciphertext: str
    nonce: str
    password: str


class DecryptResponse(BaseModel):
    plaintext: str


class KeygenResponse(BaseModel):
    password: str # сгенерированный пароль
    key_hex: str # ключ в hex
    bits: int


class AlgoInfo(BaseModel):
    name: str
    version: str
    type: str
    block_size: str
    key_size: int
    prng: str
    description: str

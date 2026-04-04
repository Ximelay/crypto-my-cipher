import hashlib
import secrets
import struct
from base64 import b64encode, b64decode

# Реализация потокового шифра XiCipher

"""
Генератор псевдослучайного потока байт. Берем seed (32 байта), разбиваем на 8 uint32 слов, а
потом прогоняем через ARX-раунды (сложение, сдвиг, XOR) и собираем выходные блоки по 32 байта.
"""
def xi_prng(seed: bytes, length: int) -> bytes:
    # seed 32 байта -> 8 чисел по 4 байта
    state = list(struct.unpack('<8I', seed[:32]))

    out = bytearray()
    ctr = 0

    while len(out) < length:
        s = state[:]
        s[7] ^= ctr # счетчик блока чтобы каждый блок был разный

        # 8 раундов ARX-смешивания
        for _ in range(8):
            # пары слов смешиваются: a = a + b, b = rotate(b) ^ a
            s[0] = (s[0] + s[1]) & 0xFFFFFFFF
            s[1] = ((s[1] << 7) | (s[1] >> 25)) & 0xFFFFFFFF
            s[1] ^= s[0]

            s[2] = (s[2] + s[3]) & 0xFFFFFFFF
            s[3] = ((s[3] << 9) | (s[3] >> 23)) & 0xFFFFFFFF
            s[3] ^= s[2]

            s[4] = (s[4] + s[5]) & 0xFFFFFFFF
            s[5] = ((s[5] << 13) | (s[5] >> 19)) & 0xFFFFFFFF
            s[5] ^= s[4]

            s[6] = (s[6] + s[7]) & 0xFFFFFFFF
            s[7] = ((s[7] << 18) | (s[7] >> 14)) & 0xFFFFFFFF
            s[7] ^= s[6]

            # диагональное смешивание для лучшей диффузии
            s[0] ^= s[4]
            s[2] ^= s[6]
            s[1] ^= s[5]
            s[3] ^= s[7]

        # складываем с начальным состоянием
        block = [(s[i] + state[i]) & 0xFFFFFFFF for i in range(8)]
        out.extend(struct.pack('<8I', *block))
        ctr += 1

    return bytes(out[:length])

# Получаем 32-байтный ключ из пароля через SHA-256
def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()


"""
Строим S-блок (таблицу подстановки 256 байт) из ключа.
Используется алгоритм RC4-KSA, перемешиваем массив [0..255] в зависимости от байтов ключа.
Возвращаем прямой sbox и обратный sbox_inv для расшифровки.
"""
def make_sbox(key_bytes: bytes):
    s = list(range(256))
    j = 0
    klen = len(key_bytes)
    for i in range(256):
        j = (j + s[i] + key_bytes[i % klen]) % 256
        s[i], s[j] = s[j], s[i]

    sbox = bytes(s)

    # обратный S-блок: если sbox[i] = v, то sbox_inv[v] = i
    sbox_inv = bytearray(256)
    for i, v in enumerate(sbox):
        sbox_inv[v] = i

    return sbox, bytes(sbox_inv)

"""
Шифрование строки.
1. из пароля получаем ключ (SHA-256)
2. генерируем случайный nonce 8 байт
3. из ключа + nonce делаем seed для ГПСЧ
4. ГПСЧ генерирует keystream нужной длины
5. из ключа строим S-блок
6. каждый байт: сначала XOR с keystream, потом подстановка через S-блок
"""
def encrypt(plaintext: str, password: str) -> dict:
    plain_bytes = plaintext.encode('utf-8')
    key_bytes = derive_key(password)
    nonce = secrets.token_bytes(8)

    seed = hashlib.sha256(key_bytes + nonce).digest()
    keystream = xi_prng(seed, len(plain_bytes))

    sbox, _ = make_sbox(key_bytes)

    # XOR + подстановка
    cipher_bytes = bytes(sbox[p ^ k] for p, k in zip(plain_bytes, keystream))

    return {
        "ciphertext": b64encode(cipher_bytes).decode(),
        "nonce": nonce.hex(),
        "algo": "XiCipher",
        "length": len(plain_bytes),
    }

"""
Расшифровка:
1. обратная подстановка через sbox_inv
2. XOR с тем же keystream
"""
def decrypt(ciphertext_b64: str, nonce_hex: str, password: str) -> str:
    cipher_bytes = b64decode(ciphertext_b64)
    key_bytes = derive_key(password)
    nonce = bytes.fromhex(nonce_hex)

    seed = hashlib.sha256(key_bytes + nonce).digest()
    keystream = xi_prng(seed, len(cipher_bytes))

    _, sbox_inv = make_sbox(key_bytes)

    plain_bytes = bytes(sbox_inv[c] ^ k for c, k in zip(cipher_bytes, keystream))
    return plain_bytes.decode('utf-8')

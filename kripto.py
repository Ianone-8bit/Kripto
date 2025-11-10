import os
import hashlib
import binascii
from Crypto.Cipher import AES, CAST
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import numpy as np
import cv2

# ------------------------
# Konfigurasi kunci master (ubah via env jika perlu)
# ------------------------
AES192_MASTER_KEY = os.environ.get("AES192_KEY", "verysecretkeybook192").encode("utf-8")
CAST5_DB_KEY = os.environ.get("CAST5_KEY", "crypto_cast5_key_16").encode("utf-8")[:16]

# ------------------------
# 1) PBKDF2-HMAC-SHA512 (password hashing) - one-way
#    hash_password -> (hash_hex, salt_hex)
# ------------------------
def hash_password(password: str, iterations: int = 100000):
    """
    Hash password using PBKDF2-HMAC-SHA512 and random 16-byte salt.
    Returns (hash_hex, salt_hex)
    """
    salt = get_random_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, iterations, dklen=64)
    return dk.hex(), salt.hex()

def verify_password(password: str, stored_hash_hex: str, salt_hex: str, iterations: int = 100000) -> bool:
    """
    Verify password given stored hash hex and salt hex.
    """
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, iterations, dklen=64)
    return dk.hex() == stored_hash_hex

# ------------------------
# 2) CAST5-CFB for email encryption in DB
#    store as hex string: iv(8) + ciphertext (hex)
# ------------------------
def encrypt_email_cast5(email: str, key: bytes = None) -> str:
    """
    Encrypt email using CAST5-CFB. Returns hex string (iv + ct).
    """
    if key is None:
        key = CAST5_DB_KEY
    iv = get_random_bytes(8)
    cipher = CAST.new(key[:16], CAST.MODE_CFB, iv=iv)
    ct = cipher.encrypt(email.encode("utf-8"))
    return (iv + ct).hex()

def decrypt_email_cast5(hex_blob: str, key: bytes = None) -> str:
    """
    Decrypt the hex string produced by encrypt_email_cast5.
    """
    if key is None:
        key = CAST5_DB_KEY
    data = bytes.fromhex(hex_blob)
    iv, ct = data[:8], data[8:]
    cipher = CAST.new(key[:16], CAST.MODE_CFB, iv=iv)
    pt = cipher.decrypt(ct)
    return pt.decode("utf-8", errors="ignore")

# ------------------------
# 3) Playfair + AES-192-CBC (text-super for title)
#    AES-192-CBC with PKCS7 padding, store as hex: iv + ct
# ------------------------
def _generate_playfair_matrix(key: str):
    keyf = "".join([c for c in key.upper() if c.isalpha()]).replace("J","I")
    seen = []
    for ch in keyf:
        if ch not in seen:
            seen.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    return seen  # list length 25

def playfair_prepare(text: str) -> str:
    t = "".join([c for c in text.upper() if c.isalpha()]).replace("J","I")
    out = ""
    i = 0
    while i < len(t):
        a = t[i]
        b = t[i+1] if i+1 < len(t) else "X"
        if a == b:
            out += a + "X"
            i += 1
        else:
            out += a + b
            i += 2
    if len(out) % 2 == 1:
        out += "X"
    return out

def playfair_encrypt(plain: str, key: str = "KRIPTOGRAFI") -> str:
    matrix = _generate_playfair_matrix(key)
    text = playfair_prepare(plain)
    cipher = ""
    for i in range(0, len(text), 2):
        a,b = text[i], text[i+1]
        ia, ib = matrix.index(a), matrix.index(b)
        ra, ca = divmod(ia, 5)
        rb, cb = divmod(ib, 5)
        if ra == rb:
            cipher += matrix[ra*5 + (ca+1)%5] + matrix[rb*5 + (cb+1)%5]
        elif ca == cb:
            cipher += matrix[((ra+1)%5)*5 + ca] + matrix[((rb+1)%5)*5 + cb]
        else:
            cipher += matrix[ra*5 + cb] + matrix[rb*5 + ca]
    return cipher

def playfair_decrypt(ciphertext: str, key: str = "KRIPTOGRAFI") -> str:
    matrix = _generate_playfair_matrix(key)
    plain = ""
    for i in range(0, len(ciphertext), 2):
        a,b = ciphertext[i], ciphertext[i+1]
        ia, ib = matrix.index(a), matrix.index(b)
        ra, ca = divmod(ia, 5)
        rb, cb = divmod(ib, 5)
        if ra == rb:
            plain += matrix[ra*5 + (ca-1)%5] + matrix[rb*5 + (cb-1)%5]
        elif ca == cb:
            plain += matrix[((ra-1)%5)*5 + ca] + matrix[((rb-1)%5)*5 + cb]
        else:
            plain += matrix[ra*5 + cb] + matrix[rb*5 + ca]
    return plain.rstrip("X")

def aes192_encrypt_hex(plain: str, key_bytes: bytes = None) -> str:
    if key_bytes is None:
        key_bytes = AES192_MASTER_KEY
    key24 = key_bytes[:24].ljust(24, b"\0")
    iv = get_random_bytes(16)
    cipher = AES.new(key24, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plain.encode("utf-8"), AES.block_size))
    return (iv + ct).hex()

def aes192_decrypt_hex(hex_blob: str, key_bytes: bytes = None) -> str:
    if key_bytes is None:
        key_bytes = AES192_MASTER_KEY
    key24 = key_bytes[:24].ljust(24, b"\0")
    data = bytes.fromhex(hex_blob)
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key24, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8", errors="ignore")

def encrypt_title_super(title: str, pf_key: str = "KRIPTOGRAFI") -> str:
    pf = playfair_encrypt(title, pf_key)
    return aes192_encrypt_hex(pf)

def decrypt_title_super(enc_hex: str, pf_key: str = "KRIPTOGRAFI") -> str:
    pf = aes192_decrypt_hex(enc_hex)
    return playfair_decrypt(pf, pf_key)

# ------------------------
# 4) AES-256-CTR for file encryption (use key derived from message)
#    store as bytes: nonce(8) + ct
# ------------------------
def derive_key_from_message(message: str) -> bytes:
    return hashlib.sha256(message.encode("utf-8")).digest()

def encrypt_file_bytes_ctr(file_bytes: bytes, key_bytes: bytes) -> bytes:
    nonce = get_random_bytes(8)
    cipher = AES.new(key_bytes[:32], AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(file_bytes)
    return nonce + ct

def decrypt_file_bytes_ctr(blob: bytes, key_bytes: bytes) -> bytes:
    if not blob or len(blob) < 8:
        raise ValueError("Blob file tidak valid")
    nonce = blob[:8]
    ct = blob[8:]
    cipher = AES.new(key_bytes[:32], AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct)

# ------------------------
# 5) Edge-LSB steganography (bytes in/out) - FIXED VERSION
#    encode_edge_lsb_bytes(bytes, message) -> bytes (PNG)
#    decode_edge_lsb_bytes(bytes) -> message string
# ------------------------
def encode_edge_lsb_bytes(image_bytes: bytes, message: str) -> bytes:
    """
    Read image from bytes, detect edges with Canny, embed message bits into LSB of BGR channels
    only for pixels that are edges. Returns PNG bytes of stego image.
    Terminator used: '####' (converted to bits) appended to message.
    """
    # decode image
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Format gambar tidak valid / gagal decode")

    # PENTING: Copy image untuk menghindari read-only array issues
    img = img.copy()
    
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 100, 200)

    # prepare bits
    term = "####"
    bits = "".join(format(ord(c), "08b") for c in (message + term))
    total_edge_pixels = np.count_nonzero(edges)
    max_capacity = total_edge_pixels * 3  # 3 channels per pixel
    if len(bits) > max_capacity:
        raise ValueError(f"Pesan terlalu panjang untuk cover ini (kapasitas ~{max_capacity} bit)")

    bit_idx = 0
    h, w = img.shape[:2]

    # iterate over edge coordinates (row, col)
    ys, xs = np.where(edges == 255)
    for (y, x) in zip(ys, xs):
        if bit_idx >= len(bits):
            break
        # operate on channels B,G,R
        for ch in range(3):
            if bit_idx >= len(bits):
                break
            
            # SOLUSI: Extract ke Python int, lakukan operasi, then assign
            original = int(img[y, x, ch])
            bit = int(bits[bit_idx])
            
            # Clear LSB bit dan set dengan bit baru - AMAN
            if bit == 1:
                new_val = original | 1  # Set LSB = 1
            else:
                new_val = original & 254  # Clear LSB = 0 (254 = 11111110)
            
            # Pastikan dalam range valid dan assign sebagai Python int
            img[y, x, ch] = min(255, max(0, new_val))
            bit_idx += 1

    # encode to PNG bytes
    ok, buf = cv2.imencode(".png", img, [cv2.IMWRITE_PNG_COMPRESSION, 0])
    if not ok:
        raise RuntimeError("Gagal meng-encode gambar hasil stego")
    return buf.tobytes()

def decode_edge_lsb_bytes(image_bytes: bytes) -> str:
    """
    Extract message from image bytes using edge detection and reading LSBs
    Returns extracted message (stops at '####' terminator). If not found returns empty string.
    """
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return ""

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 100, 200)

    ys, xs = np.where(edges == 255)
    bits = []
    for (y, x) in zip(ys, xs):
        for ch in range(3):
            bits.append(str(int(img[y, x, ch]) & 1))

    bitstr = "".join(bits)
    terminator = "".join(format(ord(c), "08b") for c in "####")
    idx = bitstr.find(terminator)
    if idx == -1:
        # terminator not found -> return empty
        return ""
    payload = bitstr[:idx]
    chars = [payload[i:i+8] for i in range(0, len(payload), 8)]
    message = "".join(chr(int(b, 2)) for b in chars if len(b) == 8)
    return message

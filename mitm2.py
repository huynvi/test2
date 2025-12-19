# mitm2.py
from mitmproxy import http, ctx
from Crypto.Cipher import AES
import base64

SECRET_KEY = b"1234567890123456"
IV = b"abcdefghijklmnop"

def pkcs5_pad(data: bytes) -> bytes:
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len]) * pad_len

def pkcs5_unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def aes_encrypt_raw(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pkcs5_pad(data))

def aes_decrypt_raw(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    return pkcs5_unpad(cipher.decrypt(data))

class Mitm2:
    def request(self, flow: http.HTTPFlow):
            try:
                raw = flow.request.raw_content or b""
                ctx.log.info(f"[MITM2] plaintext req bytes: {raw}")

                encrypted = aes_encrypt_raw(raw)
                encrypted_b64 = base64.b64encode(encrypted)

                flow.request.text = encrypted_b64.decode()
                flow.request.headers["Content-Type"] = "text/plain"

                flow.request.headers["Content-Length"] = str(len(encrypted_b64))
                flow.request.headers["Content-Type"] = "application/octet-stream"

                ctx.log.info("[MITM2] REQUEST ENCRYPTED → SERVER")
            except Exception as e:
                ctx.log.error(f"[MITM2] Encrypt error: {e}")

    def response(self, flow: http.HTTPFlow):
        try:
            raw = base64.b64decode(flow.response.raw_content)
            decrypted = aes_decrypt_raw(raw)

            flow.response.raw_content = decrypted
            flow.response.headers["Content-Length"] = str(len(decrypted))

            ctx.log.info("[MITM2] RESPONSE DECRYPTED ← SERVER")
        except Exception:
            pass  # If the response is not encrypted, ignore it

addons = [Mitm2()]
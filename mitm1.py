# mitm1.py
from mitmproxy import http, ctx
from Crypto.Cipher import AES
import base64

SECRET_KEY = b"1234567890123456"
IV = b"abcdefghijklmnop"

def aes_decrypt(ciphertext_b64: str) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode('utf-8', errors='replace')

def aes_encrypt(plaintext: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + chr(pad_len) * pad_len
    encrypted = cipher.encrypt(padded.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

class Mitm1:
    def request(self, flow: http.HTTPFlow):
        # Decrypt the body sent from the client
        if flow.request.raw_content:
            try:
                decrypted_body = aes_decrypt(flow.request.get_text())
                ctx.log.info(f"[MITM1 DECRYPTED REQUEST]: {decrypted_body}")
                flow.request.text = decrypted_body  # send plaintext to Burp
            except Exception as e:
                ctx.log.info(f"[MITM1 Decrypt Failed]: {e}")

    def response(self, flow: http.HTTPFlow):
        # Re-encrypt the body before sending it back to the client
        if flow.response.raw_content:
            try:
                plaintext = flow.response.get_text()
                encrypted_body = aes_encrypt(plaintext)
                flow.response.text = encrypted_body
                ctx.log.info(f"[MITM1 ENCRYPTED RESPONSE]: {encrypted_body}")
            except Exception as e:
                ctx.log.info(f"[MITM1 Encrypt Failed]: {e}")

addons = [
    Mitm1()
]
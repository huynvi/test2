from flask import Flask, request, jsonify
from Crypto.Cipher import AES

import base64

"""
Flask server using AES-CBC encryption:
- Decrypts incoming Base64-AES request body.
- If decrypted data is "data=test", responds with AES-encrypted "nice!!!".
- Otherwise responds with plaintext "fail".

AES key and IV:
SECRET_KEY = 1234567890123456
IV = abcdefghijklmnop
"""

app = Flask(__name__)

SECRET_KEY = b'1234567890123456' 
IV = b'abcdefghijklmnop'          

def decrypt_aes(ciphertext_b64: str) -> str:
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
        decrypted = cipher.decrypt(ciphertext)
        pad_len = decrypted[-1]
        return decrypted[:-pad_len].decode('utf-8')
    except Exception as e:
        return None

def encrypt_aes(plaintext: str) -> str:
    data = plaintext.encode('utf-8')
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(data)
    return base64.b64encode(encrypted).decode('utf-8')

@app.route('/', methods=['POST'])
def encryption_route():
    body = request.get_data(as_text=True)
    decrypted = decrypt_aes(body)
    
    if decrypted == "data=test":
        return encrypt_aes("nice!!!")
    else:
        return "fail", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7589, debug=True)


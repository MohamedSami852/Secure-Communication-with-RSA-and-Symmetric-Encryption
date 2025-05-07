import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Load environment variables
load_dotenv()
ServerPRIVATE_KEY = os.getenv("ServerPRIVATE_KEY").encode()
ServerPUBLIC_KEY  = os.getenv("ServerPUBLIC_KEY")

if not ServerPRIVATE_KEY or not ServerPUBLIC_KEY:
    raise ValueError("ServerPRIVATE_KEY and ServerPUBLIC_KEY must be set in .env file.")

ClientPublicKey = None
alice_random    = None
bob_random      = None
SESSION_KEY     = None

app = FastAPI()

class PublicKeyRequest(BaseModel):
    clientPublicKey: str

class EncryptedSessionKeyRequest(BaseModel):
    clientEncryptedSessionKey: str

class MessagePayload(BaseModel):
    message: str

class EncryptedPayload(BaseModel):
    ciphertext_hex: str
    nonce_hex: str
    tag_hex: str
    signature_hex: str

def derive_session_key(a: bytes, b: bytes) -> bytes:
    return SHA256.new(a + b).digest()[:16]

def sign_message(message: bytes) -> bytes:
    key = RSA.import_key(ServerPRIVATE_KEY)
    h = SHA256.new(message)
    return pkcs1_15.new(key).sign(h)

def verify_signature(message: bytes, signature: bytes, public_pem: str) -> bool:
    key = RSA.import_key(public_pem.encode())
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

@app.get("/Publickey")
def get_public_key():
    return {"ServerPUBLIC_KEY": ServerPUBLIC_KEY}

@app.post("/Publickey")
def post_public_key(req: PublicKeyRequest):
    global ClientPublicKey
    if not req.clientPublicKey:
        raise HTTPException(status_code=400, detail="Missing client public key.")
    ClientPublicKey = req.clientPublicKey
    return {"message": "Client public key received."}

@app.get("/Sessionkey")
def get_session_key():
    global alice_random
    if ClientPublicKey is None:
        raise HTTPException(status_code=400, detail="Client public key not received.")
    alice_random = get_random_bytes(16)
    rsa_key = RSA.import_key(ClientPublicKey.encode())
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted = cipher.encrypt(alice_random)
    return {"session_key_hex": encrypted.hex()}

@app.post("/Sessionkey")
def post_session_key(req: EncryptedSessionKeyRequest):
    global bob_random, SESSION_KEY
    if alice_random is None:
        raise HTTPException(status_code=400, detail="Alice's random not generated.")
    encrypted = bytes.fromhex(req.clientEncryptedSessionKey)
    rsa_key = RSA.import_key(ServerPRIVATE_KEY)
    cipher = PKCS1_OAEP.new(rsa_key)
    bob_random = cipher.decrypt(encrypted)
    SESSION_KEY = derive_session_key(alice_random, bob_random)
    print(f"[Server] SESSION_KEY: {SESSION_KEY.hex()}")
    return {"message": "Session established."}

@app.post("/send")
def send_message(req: MessagePayload):
    if SESSION_KEY is None:
        raise HTTPException(status_code=400, detail="Session not established.")
    plaintext = req.message.encode()
    cipher = AES.new(SESSION_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    signature = sign_message(plaintext)
    return {
        "ciphertext_hex": ciphertext.hex(),
        "nonce_hex": cipher.nonce.hex(),
        "tag_hex": tag.hex(),
        "signature_hex": signature.hex()
    }

@app.post("/receive")
def receive_message(req: EncryptedPayload):
    if SESSION_KEY is None or ClientPublicKey is None:
        raise HTTPException(status_code=400, detail="Missing session or public key.")
    try:
        ciphertext = bytes.fromhex(req.ciphertext_hex)
        nonce = bytes.fromhex(req.nonce_hex)
        tag = bytes.fromhex(req.tag_hex)
        signature = bytes.fromhex(req.signature_hex)
        cipher = AES.new(SESSION_KEY, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        valid = verify_signature(plaintext, signature, ClientPublicKey)
        return {"plaintext": plaintext.decode(), "signature_valid": valid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

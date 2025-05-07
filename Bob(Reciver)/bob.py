import os
from dotenv import load_dotenv
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Load env keys
load_dotenv()
ClientPRIVATE_KEY = os.getenv("ClientPRIVATE_KEY").encode()
ClientPUBLIC_KEY  = os.getenv("ClientPUBLIC_KEY")

if not ClientPRIVATE_KEY or not ClientPUBLIC_KEY:
    raise ValueError("ClientPRIVATE_KEY and ClientPUBLIC_KEY must be set in .env file.")

server_public_key = None
alice_random = None
bob_random = None
SESSION_KEY = None

def derive_session_key(a: bytes, b: bytes) -> bytes:
    return SHA256.new(a + b).digest()[:16]

def sign_message(message: bytes) -> bytes:
    key = RSA.import_key(ClientPRIVATE_KEY)
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

def handshake():
    global server_public_key, alice_random, bob_random, SESSION_KEY
    print("[Client] Fetching server public key...")
    r1 = requests.get("http://localhost:8000/Publickey").json()
    server_public_key = r1["ServerPUBLIC_KEY"]

    print("[Client] Sending client public key...")
    requests.post("http://localhost:8000/Publickey", json={"clientPublicKey": ClientPUBLIC_KEY})

    print("[Client] Receiving encrypted Alice random...")
    r2 = requests.get("http://localhost:8000/Sessionkey").json()
    encrypted = bytes.fromhex(r2["session_key_hex"])
    alice_random = PKCS1_OAEP.new(RSA.import_key(ClientPRIVATE_KEY)).decrypt(encrypted)

    bob_random = get_random_bytes(16)
    cipher = PKCS1_OAEP.new(RSA.import_key(server_public_key.encode()))
    encrypted_bob = cipher.encrypt(bob_random)
    requests.post("http://localhost:8000/Sessionkey", json={"clientEncryptedSessionKey": encrypted_bob.hex()})

    SESSION_KEY = derive_session_key(alice_random, bob_random)
    print(f"[Client] SESSION_KEY: {SESSION_KEY.hex()}")

def send_secure_message(msg: str):
    cipher = AES.new(SESSION_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    signature = sign_message(msg.encode())
    payload = {
        "ciphertext_hex": ciphertext.hex(),
        "nonce_hex": cipher.nonce.hex(),
        "tag_hex": tag.hex(),
        "signature_hex": signature.hex()
    }
    r = requests.post("http://localhost:8000/receive", json=payload).json()
    print("Server decrypted:", r["plaintext"])
    print("Signature valid?", r["signature_valid"])

def request_secure_message(msg: str):
    r = requests.post("http://localhost:8000/send", json={"message": msg}).json()
    ciphertext = bytes.fromhex(r["ciphertext_hex"])
    nonce = bytes.fromhex(r["nonce_hex"])
    tag = bytes.fromhex(r["tag_hex"])
    signature = bytes.fromhex(r["signature_hex"])
    plaintext = AES.new(SESSION_KEY, AES.MODE_EAX, nonce=nonce).decrypt_and_verify(ciphertext, tag)
    valid = verify_signature(plaintext, signature, server_public_key)
    print("Received from server:", plaintext.decode())
    print("Signature valid?", valid)

if __name__ == "__main__":
    handshake()
    send_secure_message("BobStudentID456")
    request_secure_message("AliceStudentID123")

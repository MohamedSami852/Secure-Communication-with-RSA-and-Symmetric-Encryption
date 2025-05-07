import os
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

load_dotenv()
ServerPUBLIC_KEY = os.getenv('ServerPUBLIC_KEY')
ServerPRIVATE_KEY = os.getenv('ServerPRIVATE_KEY')

ClientPublicKey = None
Server_Session_key = None
Client_Session_key = None

app = FastAPI()
class PublicKeyRequest(BaseModel):
    clientPublicKey: str
class EncryptedSessionKeyRequest(BaseModel):
    clientEncryptedSessionKey: str

@app.get("/Publickey")
def get_server_public_key():
    return {"ServerPUBLIC_KEY": ServerPUBLIC_KEY}



@app.post("/Publickey")
def get_client_public_key(payload: PublicKeyRequest):
    global ClientPublicKey
    ClientPublicKey = payload.clientPublicKey
    print(f"Client Public Key: {ClientPublicKey}")
    return {"message": "Client public key received successfully."}

@app.get("/Sessionkey")
def get_session_key():
    Server_generated_key = get_random_bytes(16)
    global Server_Session_key
    Server_Session_key = Server_generated_key
    print (f"Server generated session key: {Server_generated_key.hex()}")
    rsa_key = RSA.import_key(ClientPublicKey.encode())
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_session_key = cipher.encrypt(Server_generated_key)
    print (f"Encrypted session key: {encrypted_session_key}")

    return {"session_key": encrypted_session_key.hex()}

@app.post("/Sessionkey")
def receive_session_key(payload: EncryptedSessionKeyRequest):
    global Client_Session_key
    encrypted_key_bytes = bytes.fromhex(payload.clientEncryptedSessionKey)
    rsa_key = RSA.import_key(ServerPRIVATE_KEY.encode())
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_session_key = cipher.decrypt(encrypted_key_bytes)
    Client_Session_key = decrypted_session_key
    print(f"Decrypted session key: {decrypted_session_key.hex()}")
    return {"message": "Session key received successfully."}


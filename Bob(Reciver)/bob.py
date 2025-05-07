import os
from dotenv import load_dotenv
import requests
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
load_dotenv()

clientPublicKey = os.getenv('ClientPUBLIC_KEY')
ClientPrivateKey = os.getenv('ClientPRIVATE_KEY')


server_public_key = None
server_Session_Key= None
Client_Session_key = None

def handshake():
    global server_public_key

    # Step 1: Get the server's public key
    response = requests.get("http://localhost:8000/Publickey")
    print(f"Received server public key: {server_public_key}")
    global server_Session_Key
    server_public_key = response.json().get("ServerPUBLIC_KEY")
    print(f"Server's public key: {server_public_key}")

    # Step 2: Send the client's public key
    send_public_key_response = requests.post("http://localhost:8000/Publickey",json={"clientPublicKey": clientPublicKey}
    )
    print(send_public_key_response.json())
def getting_AES_Session_key():
    
    Get_Server_session_key = requests.get("http://localhost:8000/Sessionkey")
    encrypted_session_key_hex = Get_Server_session_key.json().get("session_key")
    encrypted_session_key = bytes.fromhex(encrypted_session_key_hex)
    global Client_Session_key
    global server_Session_Key 
    rsa_key = RSA.import_key(ClientPrivateKey.encode())
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    server_Session_Key = cipher_rsa.decrypt(encrypted_session_key)
    print (server_Session_Key.hex())

def genrating_AES_Session_key():
    global Client_Session_key
    global server_Session_Key
    Client_Session_key = os.urandom(16)
    print(f"Client session key: {Client_Session_key.hex()}")
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(server_public_key.encode()))
    encrypted_session_key = cipher_rsa.encrypt(Client_Session_key)
    response = requests.post("http://localhost:8000/Sessionkey",json={"clientEncryptedSessionKey": encrypted_session_key.hex()})
    print(response.json())


 
handshake()
getting_AES_Session_key()
genrating_AES_Session_key()


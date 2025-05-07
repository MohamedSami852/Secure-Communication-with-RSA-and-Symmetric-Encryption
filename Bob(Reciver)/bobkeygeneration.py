from Crypto.PublicKey import RSA

# Generate RSA key pair
key = RSA.generate(2048)
private_pem = key.export_key().decode()
public_pem = key.publickey().export_key().decode()



# Save to .env file
with open('.env', 'w') as f:
    f.write(f'ClientPRIVATE_KEY="{private_pem}"\n')
    f.write(f'ClientPUBLIC_KEY="{public_pem}"\n')

print("Stripped keys saved to .env")

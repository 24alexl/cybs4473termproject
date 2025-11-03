# generate_keys.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

print("Generating RSA 2048-bit key pair...")

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# --- Save Private Key ---
pem_private = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.NoEncryption()
)
with open('private_key.pem', 'wb') as f:
    f.write(pem_private)

# --- Save Public Key ---
public_key = private_key.public_key()
pem_public = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public_key.pem', 'wb') as f:
    f.write(pem_public)

print("Successfully created 'private_key.pem' and 'public_key.pem'.")
print("KEEP YOUR PRIVATE KEY SECRET!")
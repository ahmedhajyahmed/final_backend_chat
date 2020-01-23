import hashlib

from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto import Random



def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def write_private_key(private_key, path):
    with open(path + "/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

def write_public_key(public_key, path):
    with open(path + "/public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ))
#GENERATING KEYS
privateKey1 = generate_private_key()
write_private_key(privateKey1, "client1_keys")
publicKey1 = privateKey1.public_key()
write_public_key(publicKey1 , "client1_keys")

privateKey2 = generate_private_key()
write_private_key(privateKey2,"client2_keys")
publicKey2 = privateKey2.public_key()
write_public_key(publicKey2, "client2_keys")

#RSA ENCRYPTING
cle = 'abcdefghijklmnop'
key_AES = hashlib.sha256(cle.encode("utf-8")).digest()
ciphertext = publicKey1.encrypt(
key_AES,
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None
)
)


message = "Bonjour client 1"
print("client2 envoie ce message : " + message )
#AES ENCRYPTING
iv_AES = Random.new().read(AES.block_size)
aese = AES.new(key_AES, AES.MODE_CFB, iv_AES)
encmessage = aese.encrypt(bytes(message,'utf-8'))
print("message crypté envoyé:")
print(encmessage)
print("clé cryptée envoyée: ")
print(ciphertext)

#RSA DECRYPTING
plaintext = privateKey1.decrypt(
ciphertext,
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None
)
)

#AES DECRYPTING
aesd = AES.new(plaintext, AES.MODE_CFB, iv_AES)
plaintext1 = aesd.decrypt(encmessage)
print("message décrypté reçu")
print(plaintext1)
print("clé reçue et décryptée :")
print(plaintext)

from Crypto.Cipher import AES
from getpass4 import getpass

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return cipher.nonce + tag + ciphertext

def decrypt(key, data):
    nonce = data[:AES.block_size]
    tag = data[AES.block_size:AES.block_size * 2]
    ciphertext = data[AES.block_size * 2:]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    
    return cipher.decrypt_and_verify(ciphertext, tag)



key = b"llave                     32bits"

f = open("./password", "rb")
encryptedPassword = f.read()
f.close()

inputPassword = encrypt(key, bytes(getpass('Ingrese su contraseña: '), "utf-8"))

while (decrypt(key, inputPassword) != decrypt(key, encryptedPassword)):
  print("Error")
  inputPassword = encrypt(key, bytes(getpass('Ingrese su contraseña: '), "utf-8"))
print("Bienvenido")
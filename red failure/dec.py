import hashlib, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt(data: bytes, password: str) -> bytes:
    key = hashlib.sha256(password.encode("utf-8")).digest()
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16)

with open("9tVI0", "rb") as f:
    data = f.read()

#print(len(data), data[:32])  # بصّ على الشكل الأول

plain = decrypt(data, "z64&Rx27Z$B%73up")
print(plain)

with open("sc.bin", "wb") as f:
    f.write(plain)
print(len(plain))

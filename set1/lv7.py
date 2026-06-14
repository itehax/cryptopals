from Crypto.Cipher import AES
import base64

if __name__ == "__main__":
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key,AES.MODE_ECB)
    print(cipher.decrypt(base64.b64decode(open("7.txt","rb").read())).decode())

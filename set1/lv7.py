import base64
from Crypto.Cipher import AES

s = base64.b64decode(open("set/set1/7.txt").read())
key = b"YELLOW SUBMARINE"

cipher = AES.new(key, AES.MODE_ECB)

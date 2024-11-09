from Crypto.Cipher import AES
f = open("8.txt").read().split("\n")

for s in f:
    print(bytes.fromhex(s))
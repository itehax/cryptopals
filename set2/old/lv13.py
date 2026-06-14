# %% test
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from lv9 import pkcs_7
uid = 0
key = get_random_bytes(16)

#return "json" object
def parser(src):
    cipher = AES.new(key,AES.MODE_ECB)
    src = cipher.decrypt(src).decode()
    fields = src.split("&")
    res = {}
    for field in fields:
        k,v = field.split("=")
        res[k] = v
    return res

def profile_for(email):
    global uid
    uid+=1
    email = email.replace("&","").replace("=","")
    plain =  pkcs_7(f"email={email}&uid={uid-1}&role=user".encode(),16)
    cipher = AES.new(key,AES.MODE_ECB)
    return cipher.encrypt(plain)


def cut_and_paste():
    crafted_admin = profile_for("a@"+"M"*8+pkcs_7(b"admin",16).decode())[16:32]
    first_crafted = profile_for("a@"+"M"*12)[0:32]
    print(parser(first_crafted+crafted_admin))

if __name__ == "__main__":
    cut_and_paste()

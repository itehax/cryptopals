# %% t
from lv9 import pkcs_7
def un_pkcs_7(plain,block_size):
    pad = plain[-1]
    if 0 < pad <= block_size and plain[-pad:] == bytes([pad])*pad:
        return plain[:-pad]
    raise ValueError("Bad padding")

if __name__ == "__main__":
   for i in range(200):
       print(un_pkcs_7(pkcs_7(b"M"*i,16),16))

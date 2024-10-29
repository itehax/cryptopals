from lv1 import hex_to_str
from pwn import *
#todo,trivial. just need to understand how char <=0xF are rapresented eg F or 0F
#def str_to_hexstr(s):
    #new_str=""
    #for c in s:
        #new_str+=
    
def fixed_xor(str1,str2):
    assert(len(str1) == len(str2))
    res = ""
    for i in range(len(str1)):
        res+= chr(ord(str1[i]) ^ ord(str2[i]))
    return res 

xored = fixed_xor(hex_to_str("1c0111001f010100061a024b53535009181c"),hex_to_str("686974207468652062756c6c277320657965"))
print(enhex(xored.encode()))


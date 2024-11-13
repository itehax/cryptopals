def pkcs_7(s: str, size):
    if len(s) < size:
        pad = size - len(s)
        return s + pad.to_bytes(1, "little") * pad
    else:
        return s[:size] + pkcs_7(s[size:], 16)

def un_pkcs_7(s:str,size):
    return
    
if __name__ == "__main__":
    print(pkcs_7(b"YELLOW SUBMARINE", 20))

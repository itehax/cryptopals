def pkcs_7(plain,pad):
    missing = pad - len(plain) % pad
    return plain + bytes([missing])*missing

if __name__ == "__main__":
    for i in range(17):
        print(pkcs_7(b"A"*i,16))

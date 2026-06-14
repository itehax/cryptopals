from Crypto.Cipher import AES
import os

KEY = os.urandom(16)


def xor_bytes(first: bytes, second: bytes):
    return b"".join(bytes([x ^ y]) for x, y in zip(first, second))


def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    if len(plaintext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, iv=KEY)
    encrypted = cipher.encrypt(plaintext)

    return {"ciphertext": encrypted.hex()}


def receive(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    if len(ciphertext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    decrypted = cipher.decrypt(ciphertext)

    try:
        decrypted.decode()  # ensure plaintext is valid ascii
    except UnicodeDecodeError:
        return {"error": "Invalid plaintext: " + decrypted.hex()}

    return {"success": "Your message has been received"}


if __name__ == "__main__":
    choosen_first_pt = b"A" * 16
    ct = encrypt(choosen_first_pt.hex())["ciphertext"]

    crafted_ct = ct + ct
    got = bytes.fromhex(receive(crafted_ct)["error"].split(":")[1])[16:32]

    recovered_key = xor_bytes(xor_bytes(got, choosen_first_pt), bytes.fromhex(ct))
    assert KEY == recovered_key

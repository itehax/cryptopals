import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha1
from Crypto.Util.number import long_to_bytes
import string


# Dummy Protocol implementation
class DH:
    def __init__(self, is_creator: bool):
        self.is_creator = is_creator
        if is_creator:
            self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
            self.g = 2

            self.private = random.randint(1, self.p - 1)
            self.public = pow(self.g, self.private, self.p)

    def recv_params(self, g, p, A):
        if not self.is_creator:
            self.g = g
            self.p = p
            self.private = random.randint(1, self.p - 1)
            self.public = pow(self.g, self.private, self.p)

        self.shared_secret = pow(A, self.private, p)

    def get_public_params(self):
        return self.g, self.p

    def get_public_val(self):
        assert self.public
        return self.public

    def send_msg(self, msg):
        key = sha1(long_to_bytes(self.shared_secret)).digest()[0:16]
        iv = random.randbytes(16)
        msg = pad(msg, 16)
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(msg)
        return (iv + ct).hex()

    def recv_msg(self, enc_msg):
        enc_msg = bytes.fromhex(enc_msg)
        assert len(enc_msg) % 16 == 0 and len(enc_msg) >= 32

        key = sha1(long_to_bytes(self.shared_secret)).digest()[0:16]
        iv = enc_msg[0:16]
        enc_msg = enc_msg[16:]
        msg = AES.new(key, AES.MODE_CBC, iv).decrypt(enc_msg)
        return unpad(msg, 16)


def mitm_dec(enc_msg):
    enc_msg = bytes.fromhex(enc_msg)
    assert len(enc_msg) % 16 == 0 and len(enc_msg) >= 32

    key = sha1(long_to_bytes(0)).digest()[0:16]
    iv = enc_msg[0:16]
    enc_msg = enc_msg[16:]
    msg = AES.new(key, AES.MODE_CBC, iv).decrypt(enc_msg)
    return unpad(msg, 16)


def test():
    Alice = DH(is_creator=True)
    Bob = DH(is_creator=False)

    Bob.recv_params(*Alice.get_public_params(), Alice.get_public_val())
    Alice.recv_params(*Bob.get_public_params(), Bob.get_public_val())
    alice_msg = Alice.send_msg(b"Test message!")
    bob_got_msg = Bob.recv_msg(alice_msg)
    assert bob_got_msg == b"Test message!"
    bob_msg = Bob.send_msg(b"Bob msg!")
    alice_got_msg = Alice.recv_msg(bob_msg)
    assert alice_got_msg == b"Bob msg!"


def randomword(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length)).encode()


def mitm():
    """Simulate a message between alice and bob while M is wiretapping and reading all the messages exchanged"""
    # Key exchange
    Alice = DH(is_creator=True)
    Bob = DH(is_creator=False)
    g, p, A = *Alice.get_public_params(), Alice.get_public_val()  # Read by mitm
    Bob.recv_params(g, p, p)
    B = Bob.get_public_val()  # read by mitm
    Alice.recv_params(g, p, p)
    # After key are exchanged, messaging can start. Here the key collapse to 0, so mitm know it and can decrypt messages

    for _ in range(100):
        alice_msg = randomword(random.randint(1, 2000))
        alice_msg_enc = Alice.send_msg(alice_msg)
        # Mitm decrypt, and send the same encrypted msg back
        assert mitm_dec(alice_msg_enc) == alice_msg
        Bob.recv_msg(alice_msg_enc)

        bob_msg = randomword(random.randint(1, 2000))
        bob_msg_enc = Bob.send_msg(bob_msg)
        assert mitm_dec(bob_msg_enc) == bob_msg
        Alice.recv_msg(bob_msg_enc)


if __name__ == "__main__":
    test()
    mitm()

import random
from lv2 import aes_ecb_encrypt, aes_ecb_decrypt
from lv1 import pkcs_7, un_pkcs_7

aes_key = random.randbytes(16)


class Profile:
    uid = -1

    def __init__(self, email: str):
        self.email = email
        self.role = "user"
        Profile.uid += 1

    def __bytes__(self):
        return aes_ecb_encrypt(
            pkcs_7(f"email={self.email}&uid={self.uid}&role={self.role}".encode(), 16),
            aes_key,
        )


def parse_key_value(input: bytes):
    input = un_pkcs_7(aes_ecb_decrypt(input, aes_key)).decode()
    sep = "="
    union = "&"
    res = {}
    splitted = input.split(union)
    for split in splitted:
        k, v = split.split(sep)
        res[k] = v

    return res


# might be not perfect, implemented fast
def profile_for(mail: str):
    mail = mail.replace("=", "")
    index = mail.find("@")
    new_mail = mail[: index + 1]
    # now i got all chars including first "@"

    # check if other @ are found => Invalid encoding
    last_part = mail[index + 1 :]
    if last_part.find("@") != -1:
        last_part = mail.replace("@", "")

    return Profile((new_mail + last_part).replace("&", f""))


def ecb_cut_and_paste():
    # i know that profile is encoded in this way email={self.email}&uid={self.uid}&role={self.role}
    # what i want to do now is get 2 block containing all the str except for the self.role, so email=...&role=
    # craft input that matches this requirement,len(email=)=6 ,len(&uid=)=5, i'm going to assume that lenght of uid is 1, but anyway i can find it by bruteforcing..
    # also i know that len(&role=)=6,now 32(2blocks) - 18 = 14,so i want mail to be 15chars,after that i can copy the content of it
    crafted_email = "mymail@foo.bar"
    encrypted_mail = bytes(profile_for(crafted_email))[0:32]

    # now i want one block to be admin+pad,i'm going to craft input such that second block is going to be what i want
    crafted = (b"A" * 10 + pkcs_7(b"admin", 16)).decode()
    encrypted_admin = bytes(profile_for(crafted))[16:32]

    crafted_admin = encrypted_mail + encrypted_admin
    print(parse_key_value(crafted_admin))


if __name__ == "__main__":
    # print(parse_key_value("foo=bar&baz=qux&zap=zazzle"))
    # profile = profile_for("foo@bar.com")
    # print(f"Encrypted user profile: {bytes(profile)}")
    # print(parse_key_value(bytes(profile)))
    ecb_cut_and_paste()

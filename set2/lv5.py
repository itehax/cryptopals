import random 
aes_key = random.randbytes(16)


class Profile:
    uid = -1

    def __init__(self, email: str):
        self.email = email
        self.role = "user"
        Profile.uid += 1

    def __str__(self):
        return f"email={self.email}&uid={self.uid}&role={self.role}"


def parse_key_value(input: str):
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


if __name__ == "__main__":
    # print(parse_key_value("foo=bar&baz=qux&zap=zazzle"))
    profile = profile_for("foo@bar.com")
    print(profile)
    print(parse_key_value(str(profile)))
    profile_bug = profile_for("foo@bar.com&role=admin")
    print(profile_bug)
    print(parse_key_value(str(profile_bug)))

import base64


def hex_to_str(s):
    assert len(s) % 2 == 0
    new_str = ""
    for i in range(0, len(s), 2):
        new_str += chr(int(s[i : i + 2], 16))
    return new_str


# print(base64.b64encode(hex_to_str("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").encode()))

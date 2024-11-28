def parse_key_value(input: str):
    sep = "="
    union = "&"
    res = {}
    splitted = input.split(union)
    for split in splitted:
        k, v = split.split(sep)
        res[k] = v

    return res


if __name__ == "__main__":
    print(parse_key_value("foo=bar&baz=qux&zap=zazzle"))

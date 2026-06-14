from lv3 import find_best_text

if __name__ == "__main__":
    f = open("4.txt").readlines()
    best_scores = {}
    for l in f:
        l = bytes.fromhex(l.strip())
        if (res := find_best_text(l)) != {}:
            cur = list(res.items())[0]
            best_scores[cur[0]] = cur[1]

    res = dict(sorted(best_scores.items(), key=lambda item: item[1]))
    print(res)

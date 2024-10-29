ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
def xor_str(str1,str2): 
    return bytes([x ^ y for x,y in zip(str1,str2)])

def xor_byte(str1,key):
    return bytes([ord(c) ^ key for c in str1])

english_probability = {
    "E":12.60,
    "T":9.37,
    "A":8.34,
    "O":7.70,
    "N":6.80,
    "I":6.71,
    "H":6.11,
    "S":6.11,
    "R":5.68,
    "L":4.24,
    "D":4.14,
    "U":2.85,
    "C":2.73,
    "M":2.53,
    "W":2.34,
    "Y":2.04,
    "F":2.03,
    "G":1.92,
    "P":1.66,
    "B":1.54,
    "V":1.06,
    "K":0.87,
    "J":0.23,
    "X":0.20,
    "Q":0.09,
    "Z":0.06
}

#return a dictionary where key = char, value = P(char) in str1
def get_word_probabilities(str1):
    str_len = len(str1)
    res = {c: 0 for c in ascii_uppercase}
    for c in str1:
        if c in ascii_uppercase:
            res[c]+=1
        else:
            str_len-=1
    
    res = {c:p/str_len for c,p in res.items()}
    return res
   
matches = {}             
string = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").decode()

for i in range(0xFF + 1):
    try:
        xored = xor_byte(string,i).decode()
        word_prob = get_word_probabilities(xored.upper())
        matches[xored] = sum(abs(e_freq - word_prob[c] * 100) for (c,e_freq) in english_probability.items()) / len(ascii_uppercase)

    except Exception as error:
        pass

sorted_by_values = dict(sorted(matches.items(), key=lambda item: item[1]))

for (k,v) in sorted_by_values.items():
    print("{} - {}".format(k,v))


#!/usr/bin/env python3
'''
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
'''

from challenge1 import hex_to_bytearray
from challenge2 import xor

# english character frequency
# from http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
FREQUENCY_TABLE = {
    "E": 12.02,
    "T": 9.10,
    "A": 8.12,
    "O": 7.68,
    "I": 7.31,
    "N": 6.95,
    "S": 6.28,
    "R": 6.02,
    "H": 5.92,
    "D": 4.32,
    "L": 3.98,
    "U": 2.88,
    "C": 2.71,
    "M": 2.61,
    "F": 2.30,
    "Y": 2.11,
    "W": 2.09,
    "G": 2.03,
    "P": 1.82,
    "B": 1.49,
    "V": 1.11,
    "K": 0.69,
    "X": 0.17,
    "Q": 0.11,
    "J": 0.10,
    "Z": 0.07
}

# calculate L1 distance from english character frequency
# x: string
def l1_english_dist(x):
    x = x.upper()
    # remove all white spaces
    x = x.replace(' ', '')
    freq_table = {}
    dist = 0
    for c in x:
        if c in freq_table:
            freq_table[c] += 100.0/(len(x))
        else:
            freq_table[c] = 100.0/len(x)
    
    for k in freq_table.keys():
        if k in FREQUENCY_TABLE:
            dist += abs(freq_table[k] - FREQUENCY_TABLE[k])
        else:
            dist += freq_table[k] 
    
    for k in FREQUENCY_TABLE.keys():
        if k not in freq_table:
            dist += FREQUENCY_TABLE[k]

    return dist


# bruteforce a single byte xor key on the hex string x
def bruteforce_single_byte(x):
    x = hex_to_bytearray(x)
    len_x = len(x)

    results = []

    for i in range(256):
        test = bytearray([i for _ in range(len_x)])
        xored_str = xor(x, test)
        test_score = l1_english_dist(xored_str)
        results.append(test_score)

    min_result = min(results)
    min_char_idx = results.index(min_result)
    min_char = chr(min_char_idx)
    return min_char, xor(x, bytearray([min_char_idx for _ in range(len_x)]))


if __name__=="__main__":
    test = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key, pt = bruteforce_single_byte(test)

    print(f"Key: {key}")
    print(f"Plaintext: {pt}")
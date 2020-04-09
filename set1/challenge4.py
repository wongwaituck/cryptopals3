#!/usr/bin/env python3

'''
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
'''

from challenge3 import bruteforce_single_byte

# checks whether a string is printable ascii
def is_printable_ascii(x):
    import string
    for c in x:
        if c not in string.printable:
            return False
    return True


# finds the single byte xor in the list of hex strings
def find_single_xor(xs):
    for x in xs:
        c, s = bruteforce_single_byte(x)
        if is_printable_ascii(s):
            return c, x, s
    return None, None


if __name__=="__main__":
    # read the file
    f = open('4.txt', 'rt')
    data = f.read()
    hex_strings = data.split()
    f.close()

    key, x, s = find_single_xor(hex_strings)
    if s:
        print(f"[+] String found! Ciphertext: {x} Key: {key} Plaintext: {s}")
    else:
        print("[-] Failed to find ciphertext. SAD!")
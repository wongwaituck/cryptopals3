#!/usr/bin/env python3

'''
Implement repeating-key XOR
Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
'''

from challenge2 import xor
from challenge1 import bytes_to_hex
import math

# converts a string to its byte array form by mapping them to their ordinal represenation
def ba(x):
    return bytearray(map(lambda c : c  if type(c) == int else ord(c), x))

# encrypts plaintext x with key k, repeating if |k| < x.
def repeating_xor(x, k):
    len_x = len(x)
    len_k = len(k)
    key = ba(k * math.ceil(float(len_x) / len_k))
    x = ba(x)

    return bytes_to_hex(ba(xor(x, key)))


if __name__=="__main__":
    test = "Burning 'em, if you ain't quick and nimble\n" + "I go crazy when I hear a cymbal"
    key = "ICE"
    answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    ciphertext = repeating_xor(test, key)
    assert answer == ciphertext

    print("[+] Test passed!")

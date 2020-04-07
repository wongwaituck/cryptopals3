#!/usr/bin/env python3

'''
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
'''

import challenge1

def xor(x, y):
    res = ""
    for c, d in zip(x, y):
        res += chr(c ^ d)
    return res

def fixed_xor(x, y):
    x_1 = challenge1.hex_to_bytearray(x)
    y_1 = challenge1.hex_to_bytearray(y)
    z_1 = bytearray(xor(x_1, y_1), 'utf-8')
    z = challenge1.bytes_to_hex(z_1)

    return z

if __name__=="__main__":
    test = "1c0111001f010100061a024b53535009181c"
    key = "686974207468652062756c6c277320657965"
    test_ans = "746865206b696420646f6e277420706c6179"

    res = fixed_xor(test, key)
    assert test_ans == res

    print("[+] Test passed.")
#!/usr/bin/env python3
"""
Challenge 1:
Convert hex to base64
The string:
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

https://cryptopals.com/sets/1/challenges/1
"""


# Uses library bytearray.fromhex to convert a hex string to its bytearray representation
def hex_to_bytearray(x):
    return bytearray.fromhex(x)

def bytes_to_hex(x):
    return x.hex()

# Custom implementation of hex to bytes
def hex_to_bytes_custom(x):
    b = ""
    if len(x) % 2 != 0:
        # take care of padding issues
        x = "0" + x
    while len(x) != 0:
        hex_c = int(x[:2], 16)
        b += chr(hex_c)
        x = x[2:]
    return b

# Uses library function to covert bytearray to base64
def bytes_to_b64(x):
    x = bytes(x)
    import base64
    return base64.standard_b64encode(x)

def b64_to_bytes(x):
    import base64
    return base64.standard_b64decode(x)

TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

# Pads string z until size sz using character ch. Padding appears at the start by default, else appears at the end.
def pad(z, sz, ch, start=True):
    if len(z) % sz != 0:
        if start:
            z = ch *(sz - (len(z) % sz)) + z
        else:
            z += ch *(sz - (len(z) % sz))
    return z

# Custom function to convert to base64
# based on https://en.wikipedia.org/wiki/Base64
def bytes_to_b64_custom(x, table=TABLE):
    def octet_pad(z):
        return pad(z, 8, "0")
    # turn into a bit string
    bs = ""
    for c in x:
        bs += octet_pad(bin(ord(c))[2:])

    # look up sextets
    b64s = ""
    while len(bs) != 0:
        cbs = bs[:6]
        cb = int(cbs, 2)
        if len(cbs) != 6:
            cb = cb << (6-len(cbs))
        ch = table[cb]
        b64s += ch
        bs = bs[6:]

    # add padding
    # This means that when the length of the unencoded input is not a multiple of three, the encoded output must have padding added so that its length is a multiple of four. 
    # 3 octets ==> 4 sextets
    b64s = pad(b64s, 4, TABLE[-1], False)

    return b64s

# sextet to octet
def b64_to_bytes_custom(x, table=TABLE):
    def sextet_pad(z):
        return pad(z, 6, "0")

    # turn into a bit string
    bs = ""
    x = x.strip('=')

    for c in x:
        bs += sextet_pad(bin(table.index(c))[2:])

    # right strip zeroes
    bs = bs.rstrip('0')

    s = ""
    while len(bs) != 0:
        cbs = int(bs[:8], 2)
        c = chr(cbs)
        s += c
        bs = bs[8:]

    return s


if __name__=="__main__":
    test = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    test_ans = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    result = bytes_to_b64(hex_to_bytearray(test)).decode('utf-8')
    assert result == test_ans
    
    result = hex_to_bytes_custom(test)
    result = bytes_to_b64_custom(result)
    assert result == test_ans

    print("[+] Test passed.")
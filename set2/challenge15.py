#!/usr/bin/env python3

'''
PKCS#7 padding validation
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"
... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"
... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"
If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
'''

def valid_pad(x):
    if x == str:
        x = bytearray(x, 'utf-8')
    pad_sz = ord(x[-1]) if type(x[-1]) == str else int(x[-1])

    for i in range(pad_sz):
        assert(x[-(i+1)] == x[-1])        


if __name__=="__main__":
    try:
        test1 = "ICE ICE BABY\x04\x04\x04\x04"
        valid_pad(test1)
    except:
        assert False

    try:
        test2 = "ICE ICE BABY\x05\x05\x05\x05"
        valid_pad(test2)
    except:
        r = False
    assert r == False

    try:
        test3 = "ICE ICE BABY\x01\x02\x03\x04"
        valid_pad(test3)
    except:
        r = False
    assert r == False
    
    print("[+] Test passed.")
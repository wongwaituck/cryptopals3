#!/usr/bin/env python3

'''
Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
'''

# pads a block to sz bytes, or adds a sz byte block if there is no such pad.
def pkcs7_pad(x, sz):
    if type(x) == str:
        x = bytearray(map(lambda z: ord(z), x))
    pad = chr(sz) * sz if len(x) % sz == 0 else chr(sz -(len(x) % sz)) * (sz -(len(x) % sz))
    return x + bytearray(map(lambda x: ord(x), pad))

# unpads a pkcs7_padded plaintext block
def pkcs7_unpad(x):
    if type(x)== str:
        return x[:-(ord(x[-1]))]
    else:
        return x[:-x[-1]]


if __name__=="__main__":
    test = b"YELLOW SUBMARINE"
    test_ans = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    padded = pkcs7_pad(test, 20)

    assert padded == test_ans
    assert pkcs7_unpad(padded) == test
    print("[+] Test passed!")
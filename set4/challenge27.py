#!/usr/bin/env python3

'''
Recover the key from CBC with IV=Key
Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1
Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the key:

P'_1 XOR P'_3

This is as during encryption, we have the following things during CBC

C_1 := AES(P_1 ^ K)
C_2 := AES(P_2 ^ C_1)
C_3 := AES(P_3 ^ C_2)

when we decrypt...

P_1 := AESD(C_1) ^ K
P_2 := AESD(C_2)  ^ C_1
P_3 := AESD(C_3) ^ C_2

Note that we have P_1. This means we have to find AESD(C_1). This is possible by feeding a C_2' := 0, and C_3' := C_1. We then have

P_2' := AESD(0) ^ C_1
P_3' := AESD(C_1) ^ 0 == AESD(C_1)

Therefore, P_3' & P_1 == AESD(C_1) ^ (AESD(C_1) ^ K) == K

'''

from cryptopals import *

PT = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed dui metus, rhoncus at lectus eget, pretium iaculis eros. Morbi nec.'

MIN_BLKS = 3

KEY = randbytes(AES_KEY_SZ)

assert(len(PT) >= MIN_BLKS * AES_BLK_SZ)

def bad_decrypt(ct):
    import string
    pt = aes_cbc_decrypt(ct, KEY, KEY)
    for pc in pt:
        if chr(pc) not in string.printable:
            return pt, False
    return pt, True

def bad_encrypt(pt):
    ct, _ = aes_cbc_encrypt(pt, KEY, KEY)
    return ct


def attack_key():
    ct = bad_encrypt(PT)
    c_1 = chunk(ct, AES_BLK_SZ)[0]
    evil_ct = c_1 + bytearray([0 for _ in range(AES_BLK_SZ)]) + c_1
    keyed_pt, _ = bad_decrypt(evil_ct)
    keyed_pt_chunks = chunk(keyed_pt, AES_BLK_SZ)
    key = xor(keyed_pt_chunks[0], keyed_pt_chunks[2])
    return key

if __name__=="__main__":
    key = attack_key()
    assert(key == KEY)
    print("[+] Test passed.")
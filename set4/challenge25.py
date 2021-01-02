#!/usr/bin/env python3

'''
Break "random access read/write" AES CTR
Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.

Food for thought.
A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.
'''

from cryptopals import *
from pwn import u64

KEY = randbytes(AES_KEY_SZ)
NONCE = u64(randbytes(CTR_DEFAULT_NONCE_SZ))

def edit(ciphertext, key, nonce, offset, newtext):
    # this is the lazy way but is probably correct in spirit
    data = aes_ctr_dec(ciphertext, key, nonce)
    new_data = data[:offset] + newtext + data[offset + len(newtext):]
    return aes_ctr_enc(new_data, KEY, nonce)

def blackbox_edit(ciphertext, nonce, offset, newtext):
    return edit(ciphertext, KEY, nonce, offset, newtext)

def hack(ct, nonce):
    # get keystream by xoring with 0
    allzeros = bytearray([0 for _ in range(len(ct))])
    keystream = blackbox_edit(ct, nonce, 0, allzeros)
    pt = xor(ct, keystream)
    return pt


if __name__=="__main__":
    with open('25.txt', 'rt') as f:
        data = f.read()
        decoded_data = fromb64(data)
        decrypted_data = aes_ecb_dec(decoded_data, "YELLOW SUBMARINE")
        ct = aes_ctr_enc(decrypted_data, KEY, NONCE)

        assert aes_ctr_dec(ct, KEY, NONCE) == decrypted_data

        pt = hack(ct, NONCE)
        print(f"Plaintext: {pt}")
        assert pt == decrypted_data
    
    print("[+] Test passed.")
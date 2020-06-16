#!/usr/bin/env python3

# all commonly used functions are defined here

### CONVERSION FUNCTONS ###

from Crypto.Cipher import AES
import base64
import itertools 
import functools 

AES_BLK_SZ = 16
AES_KEY_SZ = 16

# coverts hex string to bytearray
def fromhex(x):
    assert type(x) == str
    return bytearray.fromhex(x)

# converts bytearray to hex string
def tohex(x):
    assert type(x) == bytearray
    return x.hex()

#converts bytearray to b64 string
def tob64(x):
    assert type(x) == bytearray
    return base64.standard_b64encode(x)


# converts base64 string to bytearray
def fromb64(x):
    assert type(x) == str
    return base64.standard_b64decode(x)

# xors two strings/bytearray
def xor(*args):
    from pwn import xor as zor
    return zor(*args)


### SYMMETRIC KEY HELPER FUNCTIONS ###

# Pads string z until size sz using character ch. Padding appears at the start by default, 
# else appears at the end.
def pad(z, sz, ch, start=True):
    if len(z) % sz != 0:
        if start:
            z = ch *(sz - (len(z) % sz)) + z
        else:
            z += ch *(sz - (len(z) % sz))
    return z

# chunk bytearray x to a list of bytearrays of size sz, padding the last entry if it is not of sz s
def chunk(x, sz):
    if type(x) == bytearray:
        x = bytes(x)
    l = [x[i:i+sz] for i in range(0, len(x), sz)]
    if len(l[-1]) != sz:
        l[-1] = pad(l[-1], sz, bytearray([0]), False)

    return l


### AES RELATED FUNCTIONS ###

# generates n random bytes to be used as a key
def randbytes(n):
    import secrets
    return secrets.token_bytes(n)

# AES encrypts string/bytes pt with key k
def aes_ecb_enc(pt, k):
    cipher = AES.new(k, AES.MODE_ECB)
    ct = cipher.encrypt(bytes(pt))
    return ct

# AES decrypts bytearray ct with key k
def aes_ecb_dec(ct, k):
    cipher = AES.new(k, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    return pt

# checks if a given ciphertext is AES ecb encoded
def is_ecb(ct):
    ECB_SIZE = 16
    chunks = chunk(ct, ECB_SIZE)
    all_combo = itertools.combinations(chunks, 2)
    for c1, c2 in all_combo:
        if c1 == c2:
            return True
    return False

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


# AES CBC decrypts the given ciphertext ct with key k and returns the plaintext pt
def aes_cbc_decrypt(ct, key, iv, unpad=False):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    if unpad:
        pt = pkcs7_unpad(pt)
    return pt
    
    
# AES CBC encrypts the given plaintext data pt with key k and returns a tuple (ct, iv)
def aes_cbc_encrypt(pt, key, iv=None, should_pad=False):
    if not iv:
        iv = randbytes(AES_BLK_SZ)
    if should_pad:
        pt = pkcs7_pad(pt, AES_BLK_SZ)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pt)
    return ct, iv

def aes_ctr_enc(pt, key, nonce):
    # produce key stream
    pt_chunks = chunk(pt, AES_BLK_SZ)
    from pwn import p64

    ct = bytearray([])

    for i, pt_chunk in enumerate(pt_chunks):
        keystream_input = p64(nonce) + p64(i)
        keystream = aes_ecb_enc(keystream_input, key)
        ct = ct + xor(keystream, pt_chunk)

    return ct[:len(pt)]

def aes_ctr_dec(ct, key, nonce):
    ct_chunks = chunk(ct, AES_BLK_SZ)
    pt = bytearray([])
    from pwn import p64

    for i, ct_chunk in enumerate(ct_chunks):
        keystream_input = p64(nonce) + p64(i)
        keystream = aes_ecb_enc(keystream_input, key)
        pt = pt + xor(keystream, ct_chunk)

    return pt[:len(ct)]


# returns a valid padding if the PKCS7 padding is correct for data provided in x
def valid_pad(x, null_is_valid=True):
    if x == str:
        x = bytearray(x, 'utf-8')
    try:
        pad_sz = ord(x[-1]) if type(x[-1]) == str else int(x[-1])
        if not null_is_valid and pad_sz == 0:
            return False

        valid = True
        for i in range(pad_sz):
            valid = valid and (x[-(i+1)] == x[-1])   

        return valid
    except:
        return False
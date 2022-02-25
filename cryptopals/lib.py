#!/usr/bin/env python3

# all commonly used functions are defined here

### CONVERSION FUNCTONS ###

from Crypto.Cipher import AES
import base64
import itertools 
import functools 

AES_BLK_SZ = 16
AES_KEY_SZ = 16
CTR_DEFAULT_NONCE_SZ = 8

# coverts hex string to bytearray
def fromhex(x):
    assert type(x) == str
    return bytearray.fromhex(x)

# converts bytearray to hex string
def tohex(x):
    if type(x) == bytes:
        x = bytearray(x)
    assert type(x) == bytearray
    return x.hex()

#converts bytearray to b64 string
def tob64(x):
    if type(x) == bytes:
        x = bytearray(x)
    assert type(x) == bytearray
    return base64.standard_b64encode(x)


# converts base64 string to bytearray
def fromb64(x):
    assert type(x) == str
    return base64.standard_b64decode(x)

# xors two strings/bytearray
def xor(*args):
    args_t = []
    for arg in args:
        if type(arg) == bytearray:
            args_t.append(bytes(arg))
        else:
            args_t.append(arg)
    from pwn import xor as zor
    return zor(*args_t)


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
def chunk(x, sz, should_pad=True):
    if type(x) == bytearray:
        x = bytes(x)
    l = [x[i:i+sz] for i in range(0, len(x), sz)]
    if len(l[-1]) != sz and should_pad:
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
    from pwn import p64, u64

    # produce key stream
    pt_chunks = chunk(pt, AES_BLK_SZ)

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


FREQUENCY_TABLE = {
    "E": 11.162,
    "T": 9.356,
    "A": 8.497,
    "O": 7.507,
    "I": 7.546,
    "N": 6.749,
    "S": 6.327,
    "R": 7.587,
    "H": 6.094,
    "D": 4.253,
    "L": 4.025,
    "U": 2.758,
    "C": 2.202,
    "M": 2.406,
    "F": 2.228,
    "Y": 1.994,
    "W": 2.560,
    "G": 2.015,
    "P": 1.929,
    "B": 1.492,
    "V": 0.978,
    "K": 1.292,
    "X": 0.150,
    "Q": 0.095,
    "J": 0.153,
    "Z": 0.077
}

# calculate L1 distance from english character frequency
# x: string
def l1_english_dist(x):
    import string
    for c in x:
        if not c in string.printable:
            return 99999999999

    x = x.upper()
    dist = 0.0
    freq_table = {}
    
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

# bruteforce a single byte xor key on bytearray x
def bruteforce_single_byte(x, truncate_null=False):
    if type(x) == str:
        x = bytearray(x, 'utf-8')
    len_x = len(x)

    results = []

    for i in range(256):
        if truncate_null:
            xp = bytes(x).replace(b'\x00', b'')
        else:
            xp = bytes(x)
        test = bytearray([i for _ in range(len(xp))])
        
        xored_str = xor(xp, bytes(test))
        try:
            xored_str = xored_str.decode('utf-8')
        except:
            results.append(100 * len(xp))
            continue
        test_score = l1_english_dist(xored_str)
        results.append(test_score)
    min_result = min(results)
    min_char_idx = results.index(min_result)
    min_char = chr(min_char_idx)
    return min_char, xor(x, bytearray([min_char_idx for _ in range(len_x)]))

# takes a binary string and pads it to byte length (8 bits)
def byte_pad(x):
    return pad(x, 8, "0")


def binary_str(x):
    return bin(x)[2:]


def padded_binary_str(x):
    return byte_pad(binary_str(x))

# takes 2 bytearrays and find the edit distance between the 2 byte arrays
def edit_dist(x, y):
    cum_edit_dist = 0

    for x_c, y_c in zip(x, y):
        sx_c = padded_binary_str(x_c)
        sy_c = padded_binary_str(y_c)
        for sx_ci, sy_ci in zip(sx_c, sy_c):
            if sx_ci != sy_ci:
                cum_edit_dist += 1

    return cum_edit_dist

# transpose the blocks - i.e. takes the first byte of every block and put them into the first block
# 2nd byte into the 2nd block... etc.
def transpose_blks(blks):
    transposed_blks = [bytearray([]) for _ in range(len(blks[0]))]
    for i in range(len(blks[0])):
        for j in range(len(blks)):
            transposed_blks[i] += bytearray([blks[j][i]])
    return transposed_blks


def TGFSR(w,n,m,r,a,u,d,s,b,t,c,l,f,seed=5489):
    # initialize seed
    MT = [0 for _ in range(n)]
    index = n + 1
    MT[0] = seed
    lower_mask = (1 << r) - 1
    upper_mask = ((1 << w) - 1) ^ lower_mask

    for i in range(1, n):
        MT[i] = ((1 << w) - 1) & (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i)

    def twist():
        nonlocal index
        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
            xA = x >> 1
            if (x % 2 != 0):
                xA = xA ^ a
            MT[i] = MT[(i + m) % n] ^ xA
        index = 0

    def extract_number():
        nonlocal index
        if index >= n :
            twist()
        y = MT[index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)
        index = index + 1
        return ((1 << w) - 1) & y
    return extract_number

def mt19937(seed):
    w, n, m, r = (32, 624, 397, 31)
    a = 0x9908b0DF
    u, d = (11, 0xFFFFFFFF)
    s, b = (7, 0x9D2C5680)
    t, c = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    return TGFSR(w,n,m,r,a,u,d,s,b,t,c,l,f,seed)

def mt19937_64(seed):
    w, n, m, r = (64, 312, 156, 31)
    a = 0xB5026F5AA96619E9
    u, d = (29, 0x5555555555555555)
    s, b = (17, 0x71D67FFFEDA60000)
    t, c = (37, 0xFFF7EEE000000000)
    l = 43
    f = 6364136223846793005

    return TGFSR(w,n,m,r,a,u,d,s,b,t,c,l,f,seed)

def get_unix_timestamp():
    from datetime import datetime
    return int(datetime.strftime(datetime.utcnow(), "%s"))
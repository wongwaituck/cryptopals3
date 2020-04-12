#!/usr/bin/env python3
'''
AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
'''

from Crypto.Cipher import AES
from challenge1 import b64_to_bytes

# encrypts AES-ECB using library functions
def encrypt_aes_ecb(x, k):
    cipher = AES.new(k, AES.MODE_ECB)
    ct = cipher.encrypt(x)
    return ct


# decrypts AES-ECB using library functions
def decrypt_aes_ecb(x, k):
    cipher = AES.new(k, AES.MODE_ECB)
    pt = cipher.decrypt(x)
    return pt

if __name__=="__main__":
    key = "YELLOW SUBMARINE"
    key_ba = bytearray(key, "utf-8")

    with open('7.txt', 'rt') as test_file:
        data = test_file.read()
        ct = b64_to_bytes(data)
        pt = decrypt_aes_ecb(ct, key)
        
        print(f"[+] File decrypted!\n{pt.decode('utf-8')}")
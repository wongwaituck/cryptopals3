#!/usr/bin/env python3

'''
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
'''

import sys
sys.path.append("../set1") # Adds higher directory to python modules path.

from challenge7 import encrypt_aes_ecb, decrypt_aes_ecb
from challenge9 import pkcs7_pad, pkcs7_unpad
from challenge11 import gen_aes_key

KEY = gen_aes_key()
BLK_SZ = 16

def parse_qs_custom(x):
    queries = x.split('&')
    kv_pairs = map(lambda x: x.split("="), queries)
    parsed = {}

    for k, v in kv_pairs:
        parsed[k] = v

    return parsed

def profile_for(x):
    x = x.replace("&", "")
    x = x.replace("=", "")
    d = {
        'email': x,
        'uid': 10,
        'role': 'user'
    }

    return encrypt_aes_ecb(pkcs7_pad(obj_to_qs(d), BLK_SZ), KEY)

def profile_dec(x):
    return pkcs7_unpad(decrypt_aes_ecb(x, KEY))

def obj_to_qs(x):
    qs = ""
    for k, v in x.items():
        qs += f"{k}={v}&"
    qs = qs.rstrip("&")
    return qs


# make a role=admin profile
def attacker():
    # generate input such that last block contains only user
    email = "A"*13
    victim = profile_for(email)
    assert len(profile_for(email[5:])) < len(victim)

    target_block = pkcs7_pad("admin", BLK_SZ)

    # spray email=\x00...|admin__pad__|....
    email_spray = bytearray([0 for _ in range(10)]) + target_block
    evil = profile_for(email_spray.decode('utf-8'))
    evil_blk = evil[BLK_SZ:2*BLK_SZ]

    # copy and paste
    victim = victim[:-BLK_SZ]
    victim += evil_blk

    return victim


if __name__=="__main__":
    enc_qs = attacker()

    qs = profile_dec(enc_qs)

    is_admin = parse_qs_custom(qs.decode('utf-8'))['role'] == 'admin'
    # parse query string
    assert is_admin
    print("[+] Test passed.")
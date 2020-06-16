#!/usr/bin/env python3
'''
Break fixed-nonce CTR mode using substitutions
Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.

In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts:

SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.

Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that:

CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
And since the keystream is the same for every ciphertext:

CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
say!")
Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on.

Don't overthink it.
Points for automating this, but part of the reason I'm having you do this is that I think this approach is suboptimal.
'''

# this is a slightly different solution that attempts to solve via frequency analysis on XOR of two plaintexts

import string
import itertools
from cryptopals import *

plaintexts = '''SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='''.split('\n')

# abuse some assumptions 
POSSIBLE_CHARS = string.ascii_letters + " ,-;:.?'"

KEY = randbytes(AES_KEY_SZ)

LOOKUP_TABLE = {}

def gen_lookup_table():
    p = itertools.product(POSSIBLE_CHARS, repeat=2)
    for i in p:
        val = ord(i[0]) ^ ord(i[1])
        if val not in LOOKUP_TABLE.keys():
            LOOKUP_TABLE[val] = [i[0], i[1]]
        else:
            LOOKUP_TABLE[val].append(i[0])
            LOOKUP_TABLE[val].append(i[1])


FREQUENCY_TABLE = {
    "E": 12.02,
    "T": 9.10,
    "A": 8.12,
    "O": 7.68,
    "I": 7.31,
    "N": 6.95,
    "S": 6.28,
    "R": 6.02,
    "H": 5.92,
    "D": 4.32,
    "L": 3.98,
    "U": 2.88,
    "C": 2.71,
    "M": 2.61,
    "F": 2.30,
    "Y": 2.11,
    "W": 2.09,
    "G": 2.03,
    "P": 1.82,
    "B": 1.49,
    "V": 1.11,
    "K": 0.69,
    "X": 0.17,
    "Q": 0.11,
    "J": 0.10,
    "Z": 0.07
}

# calculate L1 distance from english character frequency
# x: string
def l1_english_dist(x):
    x = x.upper()
    for c in string.punctuation + string.whitespace:
        x = x.replace(c, '')

    freq_table = {}
    dist = 0
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

# solve a XOR b
def solve_char(char_l, idx, cts):
    possible_keys = []
    for i, c in enumerate(char_l):
        # for each character we hold a list of candidate letters
        candidates = []
        for d in char_l:
            val = c ^ d
            if (val != 0) and val in LOOKUP_TABLE.keys():
                candidates += LOOKUP_TABLE[val]
        candidates = "".join(candidates).lower()
        max_char = ' '
        max_count = -1
        for pos in POSSIBLE_CHARS:
            count = candidates.count(pos)
            if count >= max_count:
                if len(cts[i]) > idx:
                    key = cts[i][idx] ^ ord(pos)
                    all_pos = True
                    for c_p in char_l:
                        if c_p == 0:
                            continue
                        all_pos = all_pos and (chr(c_p ^ key) in POSSIBLE_CHARS) 
                    if all_pos:
                        max_char = pos
                        max_count = count
                
        if len(cts[i]) > idx and max_count != -1:
            possible_keys.append(cts[i][idx] ^ ord(max_char))
        

    min_dist = 999999
    max_key = -1
    for k in possible_keys:
        candidate_ans = "".join([chr(c ^ k) for c in char_l if c != 0])
        dist = l1_english_dist(candidate_ans)
        if dist < min_dist:
            max_key = k
            min_dist = dist
    ans = []
    for c in char_l:
        if c == 0:
            ans.append(0)
        else:
            ans.append(c ^ max_key)
    return ans


if __name__=="__main__":
    cts = [aes_ctr_enc(fromb64(pt), KEY, 0) for pt in plaintexts]
    max_len = max([len(x) for x in cts])
    

    gen_lookup_table()
    cs = [bytearray([]) for _ in range(max_len)]
    
    for ct in cts:
        for i in range(max_len):
            if i >= len(ct):
                cs[i] += bytearray([0])
            else:
                cs[i] += bytearray([ct[i]])
    pt = ["" for _ in cts]
    for idx, c in enumerate(cs):
        soln_c = solve_char(c, idx, cts)
        for i, s in enumerate(soln_c):
            pt[i] += chr(s)
    print("\n".join([str(p).replace('\x00', '') for p in pt]))
    
    # Actual:
    # print("\n".join([str(fromb64(p)).replace('\x00', '') for p in plaintexts])) 
    
    # prints 
    '''
    i have met them at close of day
    coming with vivid faces
    from counter or desk among grey
    eighteenth-century houses.
    i have passed with a nod of the oizz
    or polite meaningless words,
    or have lingered awhile and said
    polite meaningless words,
    and thought before I had done
    of a mocking tale or a gibe
    to please a companion
    around the fire at the club,
    being certain that they and I
    but lived where motley is worn:
    all changed, changed utterly:
    a terrible beauty is born.
    that woman's days were spent
    in ignorant good will,
    her nights in argument
    until her voice grew shrill.
    what voice more sweet than hers
    when young and beautiful,
    she rode to harriers?
    this man had kept a school
    and rode our winged horse.
    this other his helper and friend
    was coming into his force;
    he might have won fame in the enc
    so sensitive his nature seemed,
    so daring and sweet his thought.
    this other man I had dreamed
    a drunken, vain-glorious lout.
    he had done most bitter wrong
    to some who are near my heart,
    yet I number him in the song;
    he, too, has resigned his part
    in the casual comedy;
    he, too, has been changed in his'xnl''
    transformed utterly:
    a terrible beauty is born.
    '''

    # with some manual fixing, we get
    '''
    i have met them at close of day
    coming with vivid faces
    from counter or desk among grey
    eighteenth-century houses.
    i have passed with a nod of the head
    or polite meaningless words,
    or have lingered awhile and said
    polite meaningless words,
    and thought before I had done
    of a mocking tale or a gibe
    to please a companion
    around the fire at the club,
    being certain that they and I
    but lived where motley is worn:
    all changed, changed utterly:
    a terrible beauty is born.
    that woman's days were spent
    in ignorant good will,
    her nights in argument
    until her voice grew shrill.
    what voice more sweet than hers
    when young and beautiful,
    she rode to harriers?
    this man had kept a school
    and rode our winged horse.
    this other his helper and friend
    was coming into his force;
    he might have won fame in the end,
    so sensitive his nature seemed,
    so daring and sweet his thought.
    this other man I had dreamed
    a drunken, vain-glorious lout.
    he had done most bitter wrong
    to some who are near my heart,
    yet I number him in the song;
    he, too, has resigned his part
    in the casual comedy;
    he, too, has been changed in his turn,
    transformed utterly:
    a terrible beauty is born.
    '''
    # sadly, the last few characters are too hard to recover automatically.
#!/usr/bin/env python3
'''
Break repeating-key XOR
It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

this is a test

and

wokka wokka!!!

is 37. Make sure your code agrees before you proceed.

For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.

Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.

Solve each block as if it was single-character XOR. You already have code to do this.

For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.

'''


'''
Additional Notes:

I previously wrote a better implementation based on a slightly better technique but I thought
it might be interesting to try the method above. My old implementation was based on the notes here:

Finding key length via index of coincidence
https://pages.mtu.edu/~shene/NSF-4/Tutorial/VIG/Vig-IOC-Len.html

Key Recovery using chi-square method
https://pages.mtu.edu/~shene/NSF-4/Tutorial/VIG/Vig-Recover.html
'''

from challenge1 import pad, b64_to_bytes, bytes_to_hex, hex_to_bytearray
from challenge3 import bruteforce_single_byte
from challenge5 import repeating_xor

KEY_SZS = range(2, 40)

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


# chunk bytearray x to a list of bytearrays of size sz, padding the last entry if it is not of sz s
def chunk(x, sz):
    l = [x[i:i+sz] for i in range(0, len(x), sz)]
    if len(l[-1]) != sz:
        l[-1] = pad(l[-1], sz, bytearray([0]), False)

    return l


# transpose the blocks - i.e. takes the first byte of every block and put them into the first block
# 2nd byte into the 2nd block... etc.
def transpose_blks(blks):
    transposed_blks = [bytearray([]) for _ in range(len(blks[0]))]
    for i in range(len(blks[0])):
        for j in range(len(blks)):
            transposed_blks[i] += bytearray([blks[j][i]])
    return transposed_blks


# attempts to recover the key given a bytearray encrypted using the vigenere cipher
def break_vigenere(x):
    # find the key size by taking the minimum edit distance
    edit_dsts = []
    for key_sz in KEY_SZS:
        ct_chunks = chunk(x, key_sz)
        paired_ct_chunks = [(ct_chunks[i], ct_chunks[i+1]) for i in range(0, len(ct_chunks), 2)  if i + 1 < len(ct_chunks) ]
        edit_dst = 0.0
        for x_1, x_2 in paired_ct_chunks:
            edit_dst += float(edit_dist(x_1, x_2)) / key_sz
        edit_dst = edit_dst / len(paired_ct_chunks)
        edit_dsts.append(edit_dst)

    min_edit_dst = min(edit_dsts)
    guessed_key_sz = KEY_SZS[edit_dsts.index(min_edit_dst)]
    print(f"[*] Guessed key size: {guessed_key_sz}")

    ct_chunks = chunk(x, guessed_key_sz)
    
    # transpose the blocks
    ct_chunks_t = transpose_blks(ct_chunks)

    # solve each block as a single-character XOR
    key = bytearray([])
    for ct_chunk_t in ct_chunks_t:
        c, _ = bruteforce_single_byte(bytes_to_hex(ct_chunk_t))
        key += bytearray([ord(c)])

    # get the key
    print(f"[*] Key found: {key}")

    # get the plaintext (hopefully!)
    pt_hex = repeating_xor(x, key)
    pt = hex_to_bytearray(pt_hex)

    return key, pt

if __name__=="__main__":
    # edit distance test
    edit_1 = "this is a test"
    edit_2 = "wokka wokka!!!"

    edit_dist_test = edit_dist(bytearray(edit_1, "utf-8"), bytearray(edit_2, "utf-8"))    
    assert edit_dist_test == 37

    print("[+] Edit distance test passed.")

    with open('6.txt', 'rt') as test_file:
        data = test_file.read()
        ciphertext = b64_to_bytes(data)

        key, pt = break_vigenere(ciphertext)

        if pt:
            print(f"[+] Found key: {key.decode('utf-8')}\nPlaintext: {pt.decode('utf-8')}")
        else:
            print("[-] Failed to break the vigenere cipher :(")
import string
import os

ALPHABET = string.ascii_letters + "{}_!$&-%?()"

def load_ciphertexts():
    return [x.strip() for x in open('./ciphertexts','r').readlines()]


def keygen(length):
    key = ""
    rnd_bytes = os.urandom(length)
    for i in range(length):
        pos = rnd_bytes[i] % len(ALPHABET)
        key += ALPHABET[pos]
    return key

ciphertexts = load_ciphertexts()

# start with a
N = len(ciphertexts)

flag = ''
for flagindex in range(17):

    groups = []

    for probable_char in ['b','c','d','a']:

        proable_pos = ALPHABET.index(probable_char)

        counts = {x:0 for x in range(len(ALPHABET))}

        for ciphertext in ciphertexts:
    
            cipher_pos = ALPHABET.index(ciphertext[flagindex])

            guess = (cipher_pos - proable_pos) % len(ALPHABET)

            counts[guess] += 1

        most_common_subgroups = [x[0] for x in sorted(counts.items(), key=lambda x: x[1],reverse=True)[:4]]

        groups.append(most_common_subgroups)

    
    for index in groups[0]:
        found = True
        for group in groups[1:]:
            if not index in group:
                found = False
                break
        if found:
            flag += ALPHABET[index]
            break
    print(flag,end='\r')
print()
from Crypto.Cipher import DES
import random
import time

# Count the hamming weight (number of bits set in x)
# (from https://www.expobrain.net/2013/07/29/hamming-weights-python-implementation/)
def popcount(x):
    x -= (x >> 1) & 0x5555555555555555
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
    return ((x * 0x0101010101010101) & 0xffffffffffffffff) >> 56


# Set/unset lsb of a DES key byte to make odd parity
def set_odd_parity(b):
    if popcount(b) % 2 == 0:
        return b ^ 0x01
    return b


# Saves the first seven bits to Byte 1, next 7 bits to Byte 2, and next 6 bits to Byte 3
# (from fellow student Gudni)
def get_key(n):

    b3 = set_odd_parity((n % 64) << 2)
    b2 = set_odd_parity(((n >> 6) % 128) << 1)
    b1 = set_odd_parity(((n >> 13) % 128) << 1)

    key = bytearray([b1, b2, b3, 0, 0, 0, 0, 0])

    return bytes(key)


def DES_enc(k, p):
    cipher = DES.new(k, DES.MODE_ECB)
    enc = cipher.encrypt(p)

    return enc


def DES_dec(k, c):
    cipher = DES.new(k, DES.MODE_ECB)
    dec = cipher.decrypt(c)

    return dec


# Assuming a chosen plaintext attack for the MITM:
#   1. Computing forwards from plaintext (Enc(k1, p) and backwards from cipher (Dec(k2, c)))
#       then save sub-cipher1 together with k1 from the former computation
#   2. if there is a match between sub-cipher2 computed with k2 and the saved sub-cipher1 with k1,
#      then save key pairs as candidates
#
# Keyspace: 2^20
# thus traversing a 56 bit DES key, with zero padding such that that
# the effective key for the attack is 20-bit

def MITM(p, c):

    # Allocate dictionaries for sub-cipher set of encryptions (setA) and for keypairs (T)
    setA = {}
    T = {}

    # Dictionary saving sub-cipher as key, which maps to the encryption key:
    # key=sub-cipher1, value=k1
    for key1 in valid_keys:
        sub1 = DES_enc(key1, p)
        setA[sub1] = key1

    # Dictionary saving key pairs:
    # key=k2, value=k1
    for key2 in valid_keys:
        sub2 = DES_dec(key2, c)
        if sub2 in setA:
            T[key2] = setA.get(sub2)

    return T

# --------------------------------------------------
#   PREP and ATTACK
# --------------------------------------------------

# Precompute valid keys in keyspace
valid_keys = []
for k in range(2**20-1):
    temp = get_key(k & 0x00000000000fffff)
    valid_keys.append(temp)

# Choose two random keys from valid_keys array
idx1 = random.randrange(0, len(valid_keys), 1)
idx2 = random.randrange(0, len(valid_keys), 1)
rand1 = valid_keys[idx1]
rand2 = valid_keys[idx2]

print("Keys to find")
print("k1=", rand1)
print("k2=", rand2)

# Prepare five plaintext/ciphertext pairs from a 2DES encryption scheme
# to be used for the attack
i = 0
plaintexts = [b'Lorem ipsum dolor sit am', b'et, consectetur adipiscing elit,', b'sed do eiusmod tempor   ', b'incididunt ut labore et dolore  ', b'Ut enim ad minim veniam,']
ciphertexts = []
while i < 5:
    # Do 2DES for the plaintext/ciphertext pairs
    subc = DES_enc(rand1, plaintexts[i])
    c = DES_enc(rand2, subc)
    ciphertexts.append(c)
    i += 1

found = 0
j = 0

# Execute inital attack and save found keypairs to array
keypairs = MITM(plaintexts[j], ciphertexts[j])
j += 1

while not found:
    # Validate found keypairs on a new set of (p,c)
    for key in keypairs:
        k2 = key
        k1 = keypairs[key]
        subc1 = DES_enc(k1, plaintexts[j])
        subc2 = DES_dec(k2, ciphertexts[j])

        # If found keypairs successfully encrypt and decrypt the plain- and ciphertext respectively
        # they keyparis are correct
        if subc1 == subc2:
            print("keypair found: ", k1, "and", k2)
            found = 1
            break
    j += 1

    # If found keypairs fails to enc/dec a new (p,c) pair,
    # we execute a new attack on a new set of (p,c)
    if found == 0:
        print("Did not find keypair - trying new attack with new (p,c) pairs")
        keypairs = MITM(plaintexts[j], ciphertexts[j])


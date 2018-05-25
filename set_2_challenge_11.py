import Crypto.Random
import Crypto.Random.random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor


def encrypt_aes_ecb(data, key):
    """Returns data encrypted with AES in ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)

    # Only pad the data if it isn't the size of the block
    if not len(data) % block_size == 0:
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
    else:
        ciphertext = cipher.encrypt(data)
    return ciphertext


def encrypt_aes_cbc(data, key, iv):
    """Returns AES encrypted ciphertext in CBC mode."""
    # Sets the initial IV. During the encryption (in the for
    # loop), prev will be reset to previous ciphertext block.
    prev = iv
    ciphertext = b''

    # Divides the plaintext into block size-sized chunks
    plaintext_blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

    # Iterate over each block
    for plaintext_block in plaintext_blocks:

        # XORs block with the previous ciphertext block, or
        # with the IV if first block. 
        xor_data = strxor(plaintext_block, prev)

        # Encrypts the block and adds it to the ciphertext 
        # byte string
        ciphertext_block = encrypt_aes_ecb(xor_data, key)
        ciphertext += ciphertext_block
        prev = ciphertext_block 
    return ciphertext


def count_repetitions(ciphertext, block_size):
    """Breaks the ciphertext into block_size-sized chunks and 
    counts the number of repetitions. Returns the ciphertext
    and repetitions as a dictionary.
    """
    chunks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_repetitions = len(chunks) - len(set(chunks))
    result = {
        'ciphertext': ciphertext,
        'repetitions': number_of_repetitions,
    }
    return result


def detect_encryption_mode(ciphertext, block_size):
    if count_repetitions(ciphertext, block_size)['repetitions'] > 0:
        # Assumes ECB mode
        return 'ECB'
    else:
        # Assumes CBC mode
        return 'CBC'


def generate_random_key(key_length):
    """Returns a specified number of random bytes"""
    return Crypto.Random.get_random_bytes(key_length)


def encryption_oracle(data):
    """Generates a random key and encrypts under it. Appends a 
    prefix and suffix of random bytes, then pads and encrypts the
    data using AES in either ECB or CBC mode. Returns the ciphertext
    and the encryption mode.
    """
    
    # Generate a random key
    key = generate_random_key(16)

    # Append a prefix and suffix to the data
    prefix = Crypto.Random.get_random_bytes(Crypto.Random.random.randrange(5,11))
    suffix = Crypto.Random.get_random_bytes(Crypto.Random.random.randrange(5,11))
    data_to_encrypt = prefix + data + suffix

    # Randomly determine the mode
    mode = 'ECB' if Crypto.Random.random.randrange(2) == 1 else 'CBC'
    if mode == 'ECB':
        ciphertext = encrypt_aes_ecb(pad(data_to_encrypt, block_size), key)
    if mode == 'CBC':
        iv = Crypto.Random.get_random_bytes(block_size)
        ciphertext = encrypt_aes_cbc(pad(data_to_encrypt, block_size), key, iv)
    return mode, ciphertext


def main():
    data = b'Arbitrary data to encrypt ' * 50
    for i in range(1000):
        mode, ciphertext = encryption_oracle(data)
        detected_mode = detect_encryption_mode(ciphertext, block_size)
        if not mode == detected_mode:
            print("Incorrect Mode Detected!")


if __name__ == '__main__':
    block_size = AES.block_size
    main()
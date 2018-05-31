import base64
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
        ciphertext = cipher.encrypt(pad(data, block_size))
    else:
        ciphertext = cipher.encrypt(data)
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
    """Returns ECB if count_repetitions returns greater than 0 else 
    returns CBC"""
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
    """Appends a secret suffix, then pads and encrypts the
    data using AES in either ECB or CBC mode. Returns the ciphertext
    and the encryption mode.
    """
    unknown_string = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''
    suffix = base64.b64decode(unknown_string.encode())
    data_to_encrypt = data + suffix
    ciphertext = encrypt_aes_ecb(pad(data_to_encrypt, block_size), key)
    return ciphertext


def determine_block_size():
    """Determines the block size of encryption by continuously
    appending and encrypting data and measuring the size of the 
    output.  
    """
    data = b''
    initial_length = len(encryption_oracle(data))
    while True:
        data += b'A'
        result_length = len(encryption_oracle(data))
        if result_length != initial_length:
            break
    return result_length - initial_length


def decrypt_byte(block_size, decrypted_message):
    """Decrypts a ciphertext one byte at a time by continuosly 
    encrypting a message and comparing the ciphertext.
    """

    # The length that our filler message needs to be.
    probe_length = block_size - ((1 + len(decrypted_message)) % block_size)
    probe = b'A' * probe_length

    # The length where our probe will occur each iteration. It will
    # be a multiple of the blocksize each iteration.
    testing_length = probe_length + (len(decrypted_message) + 1)
    
    # A dictionary of every possible last byte from encrypting 
    # different probe + decrypted_message + byte combinations
    # probes for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC"
    byte_dict = {}
    for byte in range(256):
        test_data = probe + decrypted_message + bytes([byte])
        test_ciphertext = encryption_oracle(test_data)
        byte_dict[test_ciphertext[:testing_length]] = byte
    comparison_ciphertext = encryption_oracle(probe)[:testing_length]
    plaintext = bytes([byte_dict.get(comparison_ciphertext, 0)])
    return plaintext


def main():
    # Determine the block size. Initial block size value
    # is assumed to be 16.
    global block_size
    determined_block_size = determine_block_size()
    block_size = determined_block_size

    # Determine whether the data is encrypted using ECB
    data = b'Random arbitrary data ' * 50
    ciphertext = encryption_oracle(data)
    determined_encryption_mode = detect_encryption_mode(ciphertext, block_size)
    if not determined_encryption_mode == 'ECB':
        print('ECB mode not detected. Exiting.')
        exit()

    length_of_encrypted_unknown_string = len(encryption_oracle(b''))
    discovered_string = b''
    for i in range(length_of_encrypted_unknown_string):
        discovered_string += decrypt_byte(block_size, discovered_string)
    print(discovered_string.decode())


if __name__ == '__main__':
    block_size = AES.block_size
    key = generate_random_key(16)
    main()
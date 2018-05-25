import base64
from Crypto.Cipher import AES


def pkcs7_pad_bytes(input_bytes, block_size):
    """Returns the input bytes padded to the block size using pkcs7 
    padding.
    """
    if len(input_bytes) == block_size:
        return input_bytes
    padding_length = block_size - len(input_bytes) % block_size
    padding = bytes([padding_length] * padding_length)
    return input_bytes + padding


def pkcs7_unpad_bytes(input_bytes):
    """Returns the input_bytes with pkcs7 padding removed.
    """
    # Strips off what is expected to be the bytes by 
    padding = input_bytes[-input_bytes[-1]:]
    if not all(padding[byte] == len(padding) for byte in range(0, len(padding))):
        return input_bytes
    return input_bytes[:-input_bytes[-1]]


def xor_byte_strings(input_bytes_1, input_bytes_2):
    """XOR two byte strings together.
    """
    return bytes([b1 ^ b2 for b1, b2 in zip(input_bytes_1, input_bytes_2)])


def decrypt_ecb_cipher(ciphertext, key):
    """Decrypts supplied ciphertext with supplied key using AES
    in ECB mode. Returns the decrypted data after unpadding.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return pkcs7_unpad_bytes(plaintext)


def encrypt_ecb_cipher(data, key):
    """Pads and encrypts supplied data with supplied key using AES
    in ECB mode. Returns the encrypted data.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pkcs7_pad_bytes(data, AES.block_size))
    return ciphertext


def encrypt_cbc_cipher(data, key, iv):
    """Implements AES CBC encryption.
    """
    ciphertext = b''
    previous_block_input = iv

    # Cycles through the data, one block at a time
    for i in range(0, len(data), AES.block_size):

        # Pads the current block
        plaintext_block = pkcs7_pad_bytes(data[i:i + AES.block_size], AES.block_size)
        
        # XORs the current block with the previous block. If it is
        # the first block it XORs with the iv value.
        xor_input = xor_byte_strings(plaintext_block, previous_block_input)
        
        # Encrypts the block using AES ECB and builds the ciphertext
        ecb_encrypted_block = encrypt_ecb_cipher(xor_input, key)
        ciphertext += ecb_encrypted_block

        # Sets the block to be XOR'd with for the next block
        previous_block_input = ecb_encrypted_block
    return ciphertext


def decrypt_cbc_cipher(data, key, iv):
    """Implements AES CBC decryption.
    """
    plaintext = b''
    previous_block_input = iv

    # Cycles through the data, one block at a time
    for i in range(0, len(data), AES.block_size):

        # The current encrypted block
        encrypted_block = data[i:i + AES.block_size]

        # Decrypts the block using AES ECB, and builds the plaintext
        decrypted_block = decrypt_ecb_cipher(encrypted_block, key)
        plaintext += xor_byte_strings(previous_block_input, decrypted_block)
        
        # Sets the block to be XOR'd with for the next block
        previous_block_input = encrypted_block
    return pkcs7_unpad_bytes(plaintext)


def main():
    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * AES.block_size
    with open("10.txt") as fh:
        ciphertext = base64.b64decode(fh.read())
    print(decrypt_cbc_cipher(ciphertext, key, iv))
    message = b'Two can keep a secret, if one of them is dead...'
    encrypted = encrypt_cbc_cipher(message, key, iv)
    decrypted = decrypt_cbc_cipher(encrypted, key, iv)
    assert decrypted == message

if __name__ == '__main__':
    main()
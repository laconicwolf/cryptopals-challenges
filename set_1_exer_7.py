import base64

# Requires Pycryptodome: https://pycryptodome.readthedocs.io/en/latest/
# pip install pycryptodome
from Crypto.Cipher import AES


def decrypt_ecb_cipher(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def main():
    key = b'YELLOW SUBMARINE'
    with open('7.txt') as fh:
        ciphertext = base64.b64decode(fh.read())
    message = decrypt_ecb_cipher(ciphertext, key)
    print(message)


if __name__ == '__main__':
    main()
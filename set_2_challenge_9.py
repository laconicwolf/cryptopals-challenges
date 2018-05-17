from Crypto.Util.Padding import pad


def pkcs7_pad_bytes(input_bytes, block_size):
    """Returns the input bytes padded to the block size using pkcs7 
    padding.
    """
    return pad(input_bytes, block_size)


def main():
    example = b'YELLOW SUBMARINE'
    block_size = 20
    print(pkcs7_pad_bytes(example, block_size))


if __name__ == '__main__':
    main()
def xor_byte_strings(input_bytes_1, input_bytes_2):
    """XOR two byte strings together
    """
    return bytes([b1 ^ b2 for b1, b2 in zip(input_bytes_1, input_bytes_2)])


def main():
    byte_string_1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    byte_string_2 = bytes.fromhex('686974207468652062756c6c277320657965')
    print(xor_byte_strings(byte_string_1, byte_string_2).hex())


if __name__ == '__main__':
    main()
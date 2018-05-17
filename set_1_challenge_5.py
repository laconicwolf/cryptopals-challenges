def repeating_key_xor(message_bytes, key):
    """Returns message XOR'd with a key. If the message, is longer
    than the key, the key will repeat.
    """
    output_bytes = b''
    index = 0
    for byte in message_bytes:
        output_bytes += bytes([byte ^ key[index]])
        if (index + 1) == len(key):
            index = 0
        else:
            index += 1
    return output_bytes


def main():
    message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    ciphertext = repeating_key_xor(message, key)
    print(ciphertext.hex())


if __name__ == '__main__':
    main()
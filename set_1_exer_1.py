import base64


def hexstring_to_b64(string):
    """Returns a base64 encoded string from a hex-encoded string
    """

    # Decode the hex-encoded string
    decoded_hexstring = bytes.fromhex(string)
    # Decodes to b"I'm killing your brain like a poisonous mushroom"

    # Base64-encode the string of bytes
    b64_encoded_string = base64.b64encode(decoded_hexstring)
    # Encodes to b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    # Return a string object (decode() converts the bytes object to a string)
    return b64_encoded_string.decode()
    # Returns 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


def main():
    hexstring = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    if hexstring_to_b64(hexstring) == expected:
        print(expected)


if __name__ == '__main__':
    main()
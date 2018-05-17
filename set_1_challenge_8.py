def count_repetitions(ciphertext, block_size):
    """Breaks the ciphertext into block_size-sized chunks and counts the 
    number of repetitions. Returns the ciphertext and repetitions as a dictionary.
    """
    chunks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_repetitions = len(chunks) - len(set(chunks))
    result = {
        'ciphertext': ciphertext,
        'repetitions': number_of_repetitions
    }
    return result


def main():
    ciphertexts = [bytes.fromhex(line.strip()) for line in open('8.txt')]
    block_size = 16
    repetitions = [count_repetitions(cipher, block_size) for cipher in ciphertexts]

    # Sorts the list of dictionaries by the repetitions key and returns the dict 
    # with the largest value
    most_repetitions = sorted(repetitions, key=lambda x: x['repetitions'], reverse=True)[0]
    print("Ciphertext: {}".format(most_repetitions['ciphertext']))
    print("Repeating Blocks: {}".format(most_repetitions['repetitions']))


if __name__ == '__main__':
    main()
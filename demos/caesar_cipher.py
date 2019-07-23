import plac

from ciphers.caesar import CaesarCipher
from crypto.interfaces import Key


@plac.annotations(
    key=plac.Annotation("The key to use for the caesar cipher. This is typically an integer in the range [0, 25].", type=int),
)
def main(key=1):
    """A demonstration of the Caesar cipher."""
    cc = CaesarCipher()
    key = Key(key)
    message = input('Enter a message to encrypt: ')

    while not CaesarCipher.is_valid(message):
        print('Invalid message format.\n'
              'Messages must be a string of all uppercase letters and spaces.')
        message = input('Enter a message to encrypt: ')

    print('\nMessage: %s' % message)
    print('Key: %s' % key)
    print('Ciphertext: %s' % cc.encrypt(message, key))


if __name__ == '__main__':
    plac.call(main)

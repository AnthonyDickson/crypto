[![Build Status](https://travis-ci.com/eight0153/crypto.svg?token=mBA1uqs7VwsypGYiKPgD&branch=master)](https://travis-ci.com/eight0153/crypto)
[![codecov](https://codecov.io/gh/eight0153/crypto/branch/master/graph/badge.svg?token=bNppdfp3Ql)](https://codecov.io/gh/eight0153/crypto)
# Crypto

This repository contains implementations of some well-known ciphers.
See the [roadmap section](#roadmap) for what has been implemented so far.

## Getting Started
1.  Set up the python environment using conda:
    ```bash
    $ conda env create -f environment.yml
    ```
    or if you are not using conda, then make sure you have a python environment
    set up with all of the packages listed in the file `environment.yml`.
    
2.  Activate the conda environment:
    ```bash
    $ conda activate crypto
    ```
    
3.  The dictionary-based attack methods use [Enchant](https://abiword.github.io/enchant/), 
    so make sure this is installed on your computer if you want to run code that uses these 
    attacks.
    
4.  Run a demo:
    ```bash
    $ python samples/caesar_cipher.py
    ```
    
    1.  Instead of typing out a message, you can pipe a text file into a demo 
        to use its contents as the message for the cipher to encrypt:
        ```bash
        $ python samples/caesar_cipher.py < data/hello_world.txt
        Enter a message to encrypt: 
        Message: HELLO WORLD
        ...
        ```
    
    2.  You can get the help text for each demo by adding the help option, e.g.:
        ```bash
        $ python samples/caesar_cipher.py --help
        ```
    
    3.  If you get an error such as:
        ```
        Traceback (most recent call last):
          File "samples/caesar_cipher.py", line 7, in <module>
            from crypto.ciphers.caesar import CaesarCipher
        ModuleNotFoundError: No module named 'crypto'
        ```
        then add the current directory (should be the root directory of this repo) 
        to the python path as such:
        ```bash
        $ export PYTHONPATH=${PYTHONPATH}:${PWD}
        ```

## Roadmap
- [ ] Caesar Cipher
    - [x] Encryption
    - [x] Decryption
    - [ ] Attacks
        - [ ] Ciphertext only
        - [ ] Chosen Plaintext
        - [ ] Known Plaintext
        - [x] Bruteforce
- [ ] Substitution Cipher
    - [x] Encryption
    - [x] Decryption
    - [ ] Attacks
        - [ ] Ciphertext only
        - [ ] Chosen Plaintext
        - [ ] Known Plaintext
        - [ ] Bruteforce
- [ ] Vigenère Cipher
    - [ ] Encryption
    - [ ] Decryption
    - [ ] Attacks
        - [ ] Ciphertext Only
        - [ ] Chosen Plaintext
        - [ ] Known Plaintext
        - [ ] Bruteforce
- [ ] One Time Pad Cipher
    - [ ] Encryption
    - [ ] Decryption
    - [ ] Attacks
        - [ ] Ciphertext Only
        - [ ] Chosen Plaintext
        - [ ] Known Plaintext
        - [ ] Bruteforce
- [ ] Stream Cipher   
    - [ ] Encryption
    - [ ] Decryption
    - [ ] Attacks
        - [ ] Ciphertext Only
        - [ ] Chosen Plaintext
        - [ ] Known Plaintext
        - [ ] Bruteforce

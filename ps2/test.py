import base64

import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# use this at the end
# if len(sys.argv) != 5:
#     print "Usage : python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file"
#     exit()

if sys.argv[1] == "-e":
    print "encrypting.."

def encrypt():

    # destination_public_key_filename_opener = open(sys.argv[2])
    # destination_public_key_filename = destination_public_key_filename.read()
    # destination_public_key_filename_opener.close()

    # sender_private_key_filename_opener = open(sys.argv[3])
    # sender_private_key_filename = sender_private_key_filename.read()
    # sender_private_key_filename_opener.close()

    # input_plaintext_file_opener = open(sys.argv[4])
    # input_plaintext_file = input_plaintext_file.read()
    # input_plaintext_file_opener.close()

    # open ciphertext_file, write and close later here later
    # ciphertext_file = open(sys.argv[5])

    # generating a random 128 bit key for symmetric encryption
    key = os.urandom(16) # in bytes, 128 bits
    iv = os.urandom(16)

    # opening and reading in same variable, has to be another cleaner way
    input_plaintext_file = open('plain_text.txt')
    input_plaintext_file = input_plaintext_file.read()
    print input_plaintext_file


    cipher_text_file = open('ciphertext_file.txt', 'wb')

#  trying CTR mode since it does not require padding, less complications

# CTR Mode, we don't need padding in CTR mode. In transforms a block cipher into a stream cipher
# we only need to introduce the nonce
cipher = Cipher(algorithms.AES(key), modes.CTR(os.urandom(16)), backend=default_backend())
encryptor = cipher.encryptor()
# len("Network Security CS 6740") = 25, but no padding is needed
# cipher_text = encryptor.update("Network Security CS(6740)") + encryptor.finalize()
cipher_text = encryptor.update(content) + encryptor.finalize()


print cipher_text
print base64.b64encode(cipher_text)


# decrypt_cipher_text = open('ciphertext_file.txt')
# cipher_text2 = decrypt_cipher_text.read()
# print "cipher : ", cipher_text2
# decryptor = cipher.decryptor()
# plain_text =  decryptor.update(cipher_text2) + decryptor.finalize()
# print plain_text
#


# print cipher_text
#
# print base64.b64encode(cipher_text)

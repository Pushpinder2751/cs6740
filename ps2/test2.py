import base64

import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# for Asymmetric Encryption

# from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# to import private key form file
# from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def encrypt():

    destination_public_key_filename_opener = open(sys.argv[2])
    destination_public_key_filename = destination_public_key_filename_opener.read()
    destination_public_key_filename_opener.close()

    sender_private_key_filename_opener = open(sys.argv[3])
    sender_private_key_filename = sender_private_key_filename_opener.read()
    sender_private_key_filename_opener.close()

    input_plaintext_file_opener = open(sys.argv[4])
    input_plaintext = input_plaintext_file_opener.read()
    print input_plaintext
    input_plaintext_file_opener.close()

    # open ciphertext_file, write and close later here later
    ciphertext_file = open(sys.argv[5], 'wb')

    # generating a random 128 bit key for symmetric encryption(AES)
    key = os.urandom(16) # in bytes, 128 bits
    iv = os.urandom(16)
    print "key : ", base64.b64encode(key)
    print "iv : ", base64.b64encode(iv)

    # RSA/Asymmetric encryption of AES key here:

    # I am just writing this step for knowledge, we are going to use openssl
    # for generation of keys

    # Generate a 2048 bit private key

    # private_key = rsa.generate_private_key(
    # public_exponent=65537,
    # key_size=2048,
    # backend=default_backend())
    # # to get the public key
    # public_key = private_key.public_key()


    # getting public_key form  destination_public_key_filename
    public_key = serialization.load_der_public_key(destination_public_key_filename,
        backend=default_backend())
    # some problem here, changed hashes.SHA1 to hashes.SHA256
    # ask professor
    # encoding key and iv both to send over via RSA
    message = key + iv
    print "len of message : ", len(message)
    print base64.b64encode(message)
    ciphertext_key = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None))

    print len(ciphertext_key)
    print base64.b64encode(ciphertext_key)
    ciphertext_file.write(ciphertext_key)


    # signing using sender_private_key_filename
    # # get private key
    with open(sys.argv[3], "rb") as key_file:
     private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())
    public_key = private_key.public_key()

    signer = private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
            )

    signer.update(ciphertext_key)
    signature = signer.finalize()
    print "signature : "
    print len(signature)
    print base64.b64encode(signature)

    ciphertext_file.write(signature)



    # AES encryption of data here :

    #  trying CTR mode since it does not require padding, less complications

    # CTR Mode, we don't need padding in CTR mode. In transforms a block cipher into a stream cipher
    # we only need to introduce the nonce
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # len("Network Security CS 6740") = 25, but no padding is needed
    # cipher_text = encryptor.update("Network Security CS(6740)") + encryptor.finalize()
    cipher_text = encryptor.update(input_plaintext) + encryptor.finalize()
    ciphertext_file.write(cipher_text)
    ciphertext_file.close()


    print cipher_text
    print len(cipher_text)
    print base64.b64encode(cipher_text)
    print "finished AES encryption"






def decrypt():

    destination_private_key_opener = open(sys.argv[2])
    destination_private_key_filename = destination_private_key_opener.read()
    destination_private_key_opener.close()

    sender_public_key_opener = open(sys.argv[3])
    sender_public_key_filename = sender_public_key_opener.read()
    sender_public_key_opener.close()

    ciphertext_file_opener = open(sys.argv[4])
    ciphertext_file = ciphertext_file_opener.read()
    ciphertext_file_opener.close()

    output_file_opener = open(sys.argv[5], 'w')

    # print "content : "
    # print len(ciphertext_file)
    # print base64.b64encode(ciphertext_file)
    # # verify signature here :
    message = ciphertext_file[:256]
    print "key: "
    print base64.b64encode(message)
    print "signature : "
    signature = ciphertext_file[256:512]
    print base64.b64encode(signature)


    # getting public_key form  sender_public_key_filename
    # used to verify signatures
    public_key = serialization.load_der_public_key(sender_public_key_filename,
        backend=default_backend())


    verifier = public_key.verifier(
     signature,
     padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
     hashes.SHA256()
    )
    verifier.update(message)
    # raises an exception if signature is invalid, none otherwise,
    # have to confirm the none part
    verifier.verify()

    # decrypt the AES key using private key of the destination

    # get private key
    with open(sys.argv[2], "rb") as key_file:
     private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())
    public_key = private_key.public_key()

    # decrypt AES key here :
    ciphertext = message
    key_iv = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None))
    print len(key_iv)
    print base64.b64encode(key_iv)
    aes_key = key_iv[:16]
    iv = key_iv[16:]


    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
    cipher_text2 = ciphertext_file[512:]
    decryptor = cipher.decryptor()
    plain_text =  decryptor.update(cipher_text2) + decryptor.finalize()
    print plain_text
    output_file_opener.write(plain_text)
    output_file_opener.close()



# # program starts here!
# if len(sys.argv) != 5:
#     print "Usage : python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file"
#     exit()
print "len of argv", len(sys.argv)

if sys.argv[1] == "-e":
    print "encrypting.."
    encrypt()
    # decrypt()
elif sys.argv[1] == "-d":
    print "decrypting.."
    decrypt()
else:
    print "Usage : python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file"
    exit()

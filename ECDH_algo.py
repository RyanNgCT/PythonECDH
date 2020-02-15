# Important Note: Install tinyec and Fernet
from tinyec import registry
import secrets
from cryptography.fernet import Fernet
from Crypto.Hash import SHA256
import base64

def compress(pubKey):
    #Arithmetic to compress public key: X coord of pubk and Y coord of pubk mod 2, 
    #then stripped off the first 2 elements
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

def encryptECDH(a):
    #secret key is 257 bits long, requires encoding to
    #convert to byte string
    secret_key = str(a.x).encode()
    message = input("Enter message to be encrypted: ")
    encoded_message = message.encode()
    print('The encoded secret key is: ' + str(secret_key) + '\n')
    
    #hash to give a fixed 256-bit value which can be
    #passed into Fernet later on.
    hash_object = SHA256.new(secret_key)
    hash_object = hash_object.digest()
    print('The hash object is: ' + str(hash_object) + '\n')

    #Fernet requires a 32 byte/256-bit base64 encoded
    #byte string, thus the need to encode
    encoded_object  = base64.b64encode(hash_object)
    print('The encoded object is: ' + str(encoded_object) + ' after Base64 encoding\n')

    #Call Fernet Library on object
    cipher_suite = Fernet(encoded_object)
    ciphertext = cipher_suite.encrypt(encoded_message)
    print('The encoded ciphertext is: ' + str(ciphertext) + '\n')

    #Decode byte string to string to make ciphertext "MORE" human readable
    ciphertext = ciphertext.decode('utf-8')
    return ciphertext

def decryptECDH(a, ciphertext):
    secret_key = str(a.x).encode()

    #Encode Ciphertext which has been decoded in encrypt operation
    a = ciphertext.encode('utf-8')

    hash_object = SHA256.new(secret_key)
    hash_object = hash_object.digest()
    encoded_object  = base64.b64encode(hash_object)

    cipher_suite = Fernet(encoded_object)

    #Perform ciphersuite decryption (opposite to encryption)
    plaintext = cipher_suite.decrypt(a)

    return plaintext


curve = registry.get_curve('brainpoolP256r1')

# Random number generator in range of elliptic curve
alicePrivKey = secrets.randbelow(curve.field.n)

# Arithmetic of base G and prv key
alicePubKey = alicePrivKey * curve.g

#Compression of Public Key with function defined above
print("Alice public key:", compress(alicePubKey))

# Random number generator in range of elliptic curve
bobPrivKey = secrets.randbelow(curve.field.n)

# Arithmetic of base G and prv key
bobPubKey = bobPrivKey * curve.g

#Compression of Public Key with function defined above
print("Bob public key:", compress(bobPubKey))

print("Now exchange the public keys (e.g. through Internet)")

#Generation of shared keys using DH concepts
aliceSharedKey = alicePrivKey * bobPubKey
print("Alice shared key:", compress(aliceSharedKey))

bobSharedKey = bobPrivKey * alicePubKey
print("Bob shared key:", compress(bobSharedKey))

# Public Key is 257-bit, Private Key is 256-bits, Compressed Shared Key is 257 bits
print("Equal shared keys:", aliceSharedKey == bobSharedKey, \
    " We are now ready to start encrypting communications.")


#Calling of Function and storage of results in variables
#to be displayed to console window
ciphertext = encryptECDH(aliceSharedKey)
print('The ciphertext is: ' + ciphertext + '\n')
plaintext = decryptECDH(aliceSharedKey, ciphertext)
print(plaintext)

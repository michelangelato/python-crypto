# mac os module fix
import crypto
import secrets
import sys
sys.modules['Crypto'] = crypto
from Crypto import Random
from Crypto.Cipher import AES
import binascii

def generate_nonce():
    return secrets.token_hex(16)

def encrypt(plaintext, iv, key):
    print('\n-- ENCRYPT')

    # initialize AES
    aes = AES.new(key, AES.MODE_CBC, iv)

    # convert to byte array
    plaintext = plaintext.encode('utf-8')
    iv = iv.encode('utf-8')
    key = key.encode('utf-8')
    print('-- msg (b):\t' + str(plaintext))
    print('-- msg (h):\t' + str(plaintext.hex()))
    print('-- iv (b):\t' + str(iv))
    print('-- iv (h):\t' + str(iv.hex()))
    print('-- key (b):\t' + str(key))
    print('-- key (h):\t' + str(key.hex()))

    # add PKCS#7 padding
    pad = 16 - len(plaintext) % 16
    plaintext += bytes([pad] * pad)
    print('-- padded (b):\t' + str(plaintext))
    print('-- padded (h):\t' + str(plaintext.hex()))
    
    # encrypt
    #ciphertext = iv + aes.encrypt(plaintext)
    ciphertext = aes.encrypt(plaintext)
    
    #return key, ciphertext
    return ciphertext

def decrypt(cipher, iv, key):
    print('\n-- DECRYPT')

    # initialize AES
    #iv = ciphertext[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)

    iv = iv.encode('utf-8')
    key = key.encode('utf-8')
    print('-- cipher (b):\t' + str(cipher))
    print('-- cipher (h):\t' + str(cipher.hex()))
    print('-- iv (b):\t' + str(iv))
    print('-- iv (h):\t' + str(iv.hex()))
    print('-- key (b):\t' + str(key))
    print('-- key (h):\t' + str(key.hex()))

    # decrypt
    plaintext = aes.decrypt(cipher)
    print('-- msg (b):\t' + str(plaintext))
    print('-- msg (h):\t' + str(plaintext.hex()))
    
    # check PKCS#7 padding
    pad = plaintext[-1]
    if pad not in range(1, 17):
        raise Exception()
    if plaintext[-pad:] != bytes([pad] * pad):
        raise Exception()
    print('-- pad:\t\t' + str(pad))

    # remove padding
    plaintext = plaintext[:-pad]
    print('-- msg (b):\t' + str(plaintext))
    print('-- msg (h):\t' + str(plaintext.hex()))

    return plaintext

print('\nAES CBC 128 padding PKCS7')

print('\nnonce1:\t' + str(generate_nonce()))
print('nonce2:\t' + str(generate_nonce()))
print('nonce3:\t' + str(generate_nonce()))

message = input('\ninput message: ')

iv = '7d0168a2a49bdd51'     # initial vector static
key = 'UwXYLkqxKHArvxxy'    # kcs
print('iv:\t\t' + iv)
print('key:\t\t' + key)

cipher = encrypt(message, iv, key)
print('cipher (b):\t' + str(cipher))
print('cipher (h):\t' + str(cipher.hex()))

decipher = decrypt(cipher, iv, key)
print('decipher (b):\t' + str(decipher))
print('decipher (h):\t' + str(decipher.hex()))

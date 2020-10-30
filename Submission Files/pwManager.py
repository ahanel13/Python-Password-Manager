'''
	Danie Bates - DanielBates2@my.unt.edu
	Anthony Hanel - AnthonyHanel@my.unt.edu

	python packages: pycryptodome (pycryptodomex)
	Tested on CSCE Linux Machines on Python 3

	References:
	1.) CSCE3550 Reference Code
	2.) https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
	3.) https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html?highlight=encrypt_and_digest#encrypt_and_digest
	4.) https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

	To run: (Python 2 will give errors if ran through Python 2)
		python3 pwManager.py www.google.com

	To reset:
		rm passwords

	Example Output: 
		Enter Master Password: 123
		Loading database...
		The message is authentic: b'{"": ""}'
		No entry for www.test.com, creating new...
		New entry - enter password for www.test.com: 123
		stored

		Enter Master Password: 123
		Loading database...
		The message is authentic: b'{"": "", "www.test.com": "123"}'
		entry   : www.test.com
		password: 123
'''

import csv
import os
import sys
import json
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2

# Name of passwords file
passwordFile = "passwords"
# Random string for salt value
salt = "ens2910s"
head = " ____               __  __\n" + "|  _ \ __ _ ___ ___|  \/  | __ _ _ __  \n" + "| |_) / _` / __/ __| |\/| |/ _` | '_ \ \n" + "|  __/ (_| \__ \__ \ |  | | (_| | | | |\n" + "|_|   \__,_|___/___/_|  |_|\__,_|_| |_|\n"


# Reference 1 - From original provided code (Uses json to dump a dictionary as utf-8 byte information)
def dictToBytes(dict):
    return json.dumps(dict).encode('utf-8')

def bytesToDict(dict):
    return json.loads(dict.decode('utf-8'))

# Encreypts dictionary data on a master key
def encrypt(dict, k):
    # Reference 4 - Get a cipher based on AES EAX
    cipher = AES.new(k, AES.MODE_EAX)
    # Reference 3 - Get the ciphertext, and the verification tag from the encrpyt_and_digest(data) metho 
    ciphertext, tag = cipher.encrypt_and_digest(dict)
    # Output the nonce, tag and ciphertext to the file
    with open(passwordFile, 'wb') as outfile:
        [outfile.write(x) for x in (cipher.nonce, tag, ciphertext)]

# Inverse of the encrypt function.
def decrypt(k):
    with open(passwordFile, 'rb') as infile:
        nonce, tag, ciphertext = [infile.read(x) for x in (16, 16, -1)]
        # Reference 4 - Get a cipher based on AES EAX
        cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
        # Decrypts the ciphertext and saves as data
        data = cipher.decrypt(ciphertext)
        try:
        	# Verify the authenticity of the tag
            cipher.verify(tag)
            # Output the user's dictionary
            print("The message is authentic")
        except ValueError:
            print("Key incorrect or message corrupted.")
        return data

# Driver
def Main():
    print("\n")
    mpw = input("Enter Master Password: ")
    # Converts the salt to utf-8 (Only for Linux machines for some reason)
    newSalt = bytes(salt, 'utf-8')
    # Reference 1, Create a key using PBKDF2 and the newSalt byte value
    k = PBKDF2(mpw, newSalt, dkLen=32)

    # check for password database file
    if not os.path.isfile(passwordFile):

        # create new passwords file
        print("No password database, creating....")
        newDict = dictToBytes({"": ""})
        encrypt(newDict, k)

    # check usage
    if len(sys.argv) != 2:
        print("usage: python pwMan.py <website>")
        return
    else:

        # decrypt passwords file to dictionary
        try:
            print("Loading database...")
            pws = decrypt(k)
            pws = bytesToDict(pws)

        except Exception as e:
        	# Prints the Exception value to the user for debugging
            print("Wrong password\n" + str(e))
            return

        # print value for  website or add new value
        entry = sys.argv[1]
        if entry in pws:
            print("entry   : " + str(entry))
            print("password: " + str(pws[entry]))
        else:
            print("No entry for " + str(entry) + ", creating new...")
            newPass = input("New entry - enter password for " + entry + ": ")
            pws[entry] = newPass
            encrypt(dictToBytes(pws), k)
            print("stored")

# Redirects to main after printing the header.
if __name__ == '__main__':
    print(str(head))
    Main()

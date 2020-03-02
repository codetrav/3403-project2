"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""
import os
from Crypto.Cipher import AES
import base64
import hashlib
user = input("Enter a username: ")
password = input("Enter a password: ")

# hashlib reccomends salt be al least size 16
salt = str(os.urandom(16));
print(salt)
# use sha1 algorithm in hashlib to hash password
hashed= hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 120000)
hashed_password = hashed

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt, hashed_password))
    print("User successfully added!")


#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading
import Crypto.Cipher.AES as AES
import Crypto.PublicKey.RSA as RSA
from Crypto import Random
import random
import string

def generate_rsa(size=2048):
    rsa = RSA.generate(size)
    return rsa

def generate_AES_key(size=16):
    aes_key = ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(size))
    return aes_key

def create_AES(aes_key, iv=None, block_size=AES.block_size, mode=AES.MODE_CFB):
    if iv is None:
        iv = Random.new().read(block_size)
    elif len(iv) is not block_size:
        raise
    aes = AES.new(aes_key, mode, iv)
    return aes

def encrypt_AES(aes, msg):
    result = aes.encrypt(aes.IV+msg)
    return result

def decrypt_AES(aes, data):
    result = aes.decrypt(data)[len(aes.IV):]
    return result

def encrypt_RSA(rsa_key_u, msg):
    result = None
    if len(msg)<=256:
        result = rsa_key_u.encrypt(msg, random.randint(2,50))
    else:
        chunks = len(msg)//256
        bytes_left = len(msg)%256
        offset = 0
        for i in range(chunks):
            n = 256*(i+1)
            result += rsa_key_u.encrypt(msg[offset:n], random.randint(2,50))
            offset = n
        if bytes_left is not 0:
            result += encrypt(msg[offset:bytes_left], random.randint(2,50))
    return result[0]


def decrypt_RSA(rsa_key_r, data):
    msg = None
    result = None
    if len(data)==256:
        msg = rsa_key_r.decrypt(data)
        result = msg
    else:
        chunks = len(data)//256
        bytes_left = len(data)%256
        offset = 0
        for i in range(chunks):
            n = 256*(i+1)
            result += rsa_key_r.decrypt(data[offset:n])
            offset = n
        if bytes_left is not 0:
            result += rsa_key_r.decrypt(data[offset:bytes_left])
    print result
    return result


rsa_server_key_u = None
rsa_key_r = None
aes = None
AES_key = None
sock = None

def auth_phase():
    data = sock.recv(256) #5
    msg = decrypt_AES(aes, decrypt_RSA(rsa_key_r, data))
    print msg
    t_id = msg[0]
    prc = msg[1]
    if prc == chr(128):
        passphrase = raw_input('type password: ')
        data = msg[0:2] + passphrase
        sock.send(encrypt_RSA(rsa_server_key_u, encrypt_AES(aes, data)))


def enc_phase_rsa():
    global sock, rsa_key_r, rsa_server_key_u
    rsa_key_r = generate_rsa()
    rsa_key_u = rsa_key_r.publickey()
    msg = sock.recv(1024) #1
    rsa_server_key_u = RSA.importKey(msg)
    sock.send(rsa_key_u.exportKey()) #2

def enc_phase_aes():
    global sock, aes, AES_key
    iv = Random.new().read(16)
    data = sock.recv(256) #3
    msg = decrypt_RSA(rsa_key_r, data)
    AES_key = msg
    sock.send(encrypt_RSA(rsa_server_key_u, AES_key)) #4
    aes = AES.new(AES_key, AES.MODE_CFB, iv)

def connect_to_app(ip, port = 5001):
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))


def main():
    connect_to_app('localhost')
    enc_phase_rsa()
    enc_phase_aes()
    auth_phase()
    print 'Done\n'

if __name__ == '__main__':
    main()
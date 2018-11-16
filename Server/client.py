
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
    return result


def decrypt_RSA(rsa_key_u, data):
    msg = None
    if len(data)==256:
        msg = rsa_key_u.decrypt(data)
    else:
        chunks = len(data)//256
        bytes_left = len(data)%256
        for i in range(chunks):
            n = 256*(i+1)
            result += rsa_key_u.decrypt(data[offset:n])
            offset = n
        if bytes_left is not 0:
            result += decrypt(data[offset:bytes_left])
    return result


rsa_server_key_u = None
rsa_key_r = None
aes = None
AES_key = None
sock = None

def enc_phase_rsa():
	rsa_key_r = generate_rsa()
	rsa_key_u = rsa_key_r.publickey()
	msg = sock.recv(1024)
	rsa_server_key_u = RSA.importKey(msg)
	sock.send(rsa_key_u.exportKey())

def enc_phase_aes():
	iv = Random.new().read(16)
	data = sock.recv(256)
	msg = decrypt_RSA(rsa_key_r, data)
	AES_key = msg
	aes = AES.new(AES_key, AES.MODE_CFB, iv)


def connect_to_app(ip, port = 5001):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((ip, port))


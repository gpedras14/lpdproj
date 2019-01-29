

#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from Crypto import Random
import random
import string
from response_handler import Data_handler as D_handler

"""Handles the data received from the client to the server
and reedirects it to the data handler class"""
passphrase = 'banana'

def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


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
    result = ''
    if len(msg)<=256:
        result = rsa_key_u.encrypt(msg, random.randint(2,50))[0]
    else:
        chunks = len(msg)//256
        bytes_left = len(msg)%256
        offset = 0
        for i in range(chunks):
            n = 256*(i+1)
            result += rsa_key_u.encrypt(msg[offset:n], random.randint(2,50))[0]
            offset = n
        if bytes_left is not 0:
            result += rsa_key_u.encrypt(msg[offset:bytes_left], random.randint(2,50))[0]
    return result


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
    return result

def check_t_id(expected_id, m_t_id):
    if expected_id != m_t_id:
        return False
    else:
        return True

def check_c(expected_c, c):
    if expected_c != c:
        return False
    else:
        return True

def get_message_from_data(data):
    if len(data) == 4:
        return None
    else:
        return data[4:]


def receive(sock):
    data = sock.recv(4)
    data_len = int(data[2:4].encode('hex'), 16)
    print str(data_len)
    if data_len > 0:
        data += sock.recv(data_len)
    return data


def send(sock, t_id, c, data=None):
    msg = t_id + c
    if data is not None:
        b = bin(len(data))[2:]
        data_len = bitstring_to_bytes(b)
        msg += data_len + data
    else:

        msg += '\x00'*2
    sock.send(msg)




class Client_receiver(threading.Thread):
    """Threading Class that receives data from the client
    paramters: sock -> type socket.socket
    """
    def __init__(self, sock):
        super(Client_receiver, self).__init__()
        self.sock = sock
        if not isinstance(sock, socket._socketobject):
            raise Exception('Not socket Object')

    def run(self):
        #rsa phase begin
        rsa_key_r = generate_rsa()
        rsa_key_u = rsa_key_r.publickey()
        t_id = random._urandom(1)
        c = chr(128)
        data = rsa_key_u.exportKey('DER')
        send(self.sock, t_id, c, data=data)
        data = receive(self.sock)
        if check_c(chr(128), data[1]) is False:
            raise Exception('Wrong operation')
        msg = get_message_from_data(data)
        client_rsa_key_u = RSA.importKey(msg)
        send(self.sock, t_id, chr(1))
        #rsa phase end
        #aes phase begin
        aes_key = RSA.Random.new().read(16)
        t_id = random._urandom(1)
        aes = create_AES(aes_key)
        t_id = random._urandom(1)
        c = chr(128)
        data = client_rsa_key_u.encrypt(aes_key, 10)[0]
        send(self.sock, t_id, c, data=data)
        data = receive(self.sock)
        if check_t_id(data[0], t_id) is False:
            raise Exception('Wrong id')
        if check_c(c, data[1]) is False:
            raise Exception('Wrong operation')
        msg = get_message_from_data(data)
        key = rsa_key_r.decrypt(msg)
        if key != aes_key:
            raise Exception('Wrong key')
        c = chr(1)
        send(self.sock, t_id, c)
        #aes phase end
        #auth phase begin
        t_id = random._urandom(1)
        c = chr(64)
        send(self.sock, t_id, c)
        data = receive(self.sock)
        if check_c(data[1], chr(8)) is False:
            raise Exception('Wrong operation')
        if check_t_id(data[0], t_id) is False:
            raise Exception('Wrong id')
        crypt = rsa_key_r.decrypt(get_message_from_data(data))
        msg = decrypt_AES(aes, crypt)
        if passphrase == msg:
            c = chr(1)
            t_id = random._urandom(1)
            send(self.sock, t_id, c)
            D_handler(self.sock, aes, rsa_key_r, client_rsa_key_u ).start()
        else:
            c = chr(0)
            t_id = random._urandom(1)
            send(self.sock, t_id, c)
        #auth phase end



if __name__ == '__main__':
    pass

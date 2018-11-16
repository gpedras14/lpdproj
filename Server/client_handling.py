

#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading
import Crypto.Cipher.AES as AES
import Crypto.PublicKey.RSA as RSA
from Crypto import Random
import random
import string
from response_handler import Data_handler as D_handler

"""Handles the data received from the client to the server
and reedirects it to the data handler class"""
passphrase = 'N1pRzIIFtc'

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
        auth = False
        enc_phase_1 = False
        enc_phase_2 = False
        t_id = None
        rsa_key_r = None
        client_rsa_key_u = None
        aes = None
        iv = None
        AES_key = None
        try:
            while not enc_phase_1:
                rsa_key_r = generate_rsa()
                rsa_key_u = rsa_key_r.publickey()
                self.sock.send(rsa_key_u.exportKey('DER'))
                data = self.sock.recv(1024)
                if len()
                #pass key to base64
                client_rsa_key_u = RSA.importKey(data)
                enc_phase_1 = True
            while not enc_phase_2:
                AES_key = generate_AES_key()
                iv = Random.new().read(AES.block_size)
                aes = create_AES(aes_key, iv)
                msg = encrypt_RSA(aes_key)
                self.sock.send(msg)
                data = self.sock.recv(256)
                client_d = decrypt_RSA(data)
                t_id = random._urandom(2)
                if client_d == AES_key:
                    enc_phase_2 = True
            while not auth:
                data = t_id + '\x01'
                data = client_rsa_key_u.encrypt(AES_key, random.randint(2,50))
                self.sock.send(data.encode())
                data = self.sock.recv(256)
                msg = rsa_key_r.decrypt(data)
                t_id, c_msg = msg[0], msg[2:]
                if c_msg == passphrase:
                    auth = True
                    D_handler(self.sock, AES_key, rsa_key_r, client_rsa_key_u).start()
                else:
                    pass
            pass
        except:
            pass
        finally:
            pass
        #1st phase: authentication
        #2nd phase: issue commands
        #3rd phase: answer to those commands
        #4th phase: repeat at 2nd phase
        pass


if __name__ == '__main__':
    pass



#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading
import Crypto.Cipher.AES as AES
import Crypto.PublicKey.RSA as RSA
from Crypto import Random
import random
import string

"""Handles the data received from the client to the server
and reedirects it to the data handler class"""
passphrase = 'N1pRzIIFtc'


class Client_receiver(threading.Thread):
    """Threading Class that receives data from the client
    paramters: sock -> type socket.socket
    """
    def __init__(self, sock):
        super(Client_receiver, self).__init__()
        self.sock = sock
        if type(sock) is not type(socket.socket):
            raise

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
                rsa_key_r = RSA.generate(2048)
                rsa_key_u = rsa_key_r.publickey()
                sock.send(rsa_key_u.exportKey().encode())
                data = sock.recv(450)
                client_rsa_key_u = RSA.importKey(data)
                enc_phase_1 = True
            while not enc_phase_2:
                AES_key = ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(AES.block_size))
                iv = Random.new().read(AES.block_size)
                aes = AES.new(AES_key, AES.MODE_CFB, iv)
                msg = client_rsa_key_u.encrypt(AES_key, random.randint(2,50))
                sock.send(msg.encode())
                data = sock.recv(245)
                client_d = rsa_key_r.decrypt(data)
                t_id = random._urandom(2)
                if client_d == AES_key:
                    enc_phase_2 = True
            while not auth:
                data = t_id + '\x01'
                sock.send(data.encode())
                data = sock.recv(245)
                msg = rsa_key_r.decrypt(data)
                t_id, c_msg = msg[0], msg[2:]
                if c_msg == passphrase:
                    auth = True
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



#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading
import Crypto.Cipher.AES as AES
import Crypto.PublicKey.RSA as RSA

"""Handles the data received from the client to the server
and reedirects it to the data handler class"""

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
        try:
            while not enc_phase_1:
                rsa_key_r = RSA.generate(2048)
                rsa_key_u = rsa_key_r.publickey()
                sock.send(rsa_key_u.exportKey().encode())
                
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

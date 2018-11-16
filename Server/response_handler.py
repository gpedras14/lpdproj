#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading

class Data_handler(threading.Thread):
    def __init__(self, sock, AES_key, rsa_key_r, client_rsa_key_u):
        super(Data_handler, self).__init__()
        self.sock = sock
        self.AES_key = AES_key
        self.rsa_key_r = rsa_key_r
        self.client_rsa_key_u = client_rsa_key_u
        if type(sock) is not type(socket.socket):
            raise
        if type(data) is type(b''):
            raise

    def run(self):
        #handle data
        #repond
        pass



if __name__ == '__main__':
    pass

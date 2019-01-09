#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading
import random
from client_handling import *

def get_operation(pass_request, command_line, script_command, reponse, more_data, close_connection, error):
    result = pass_request*(2**7) + command_line*(2**6) + script_command*(2**5) + reponse*(2**4) + more_data*(2**3) + close_connection*(2**2) + error*(2)
    return result

def check_operation(op_int):
    pass_request = op_int & 128
    command_line = op_int & 64
    script_command = op_int & 32
    reponse = op_int & 16
    more_data = op_int & 8
    close_connection = op_int & 4
    error = op_int & 2
    return (pass_request, command_line, script_command, reponse, more_data, close_connection, error, 0)

def generenate_transaction_id():
    result = random._urandom(1)
    return result

def check_message(t_id, msg):
    reponse = ''
            



class Data_handler(threading.Thread):
    def __init__(self, sock, AES_key, rsa_key_r, client_rsa_key_u):
        super(Data_handler, self).__init__()
        self.sock = sock
        self.AES_key = AES_key
        self.rsa_key_r = rsa_key_r
        self.client_rsa_key_u = client_rsa_key_u
        if not isinstance(sock, socket._socketobject):
            raise Exception('Not a socket type')

    def run(self):
        print 'Done\n'



if __name__ == '__main__':
    pass

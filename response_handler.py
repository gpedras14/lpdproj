#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading

class data_handler(threading.Thread):
    def __init__(self, sock, data):
        threading.Thread.__init__()
        self.sock = sock
        self.data = data
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

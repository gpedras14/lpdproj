

#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading

"""Handles the data received from the client to the server
and reedirects it to the data handler class"""


class Client_receiver(threading.Thread):
    """Threading Class that receives data from the client
    paramters: sock -> type socket.socket
    """
    def __init__(self, sock):
        threading.Thread.__init__()
        self.sock = sock
        if type(sock) is not type(socket.socket):
            raise

    def run(self):
        while True:
            data = None
            d = sock.recv(1024)
            data = d
            while d is not 0:
                d = sock.recv(1024)
                data += d
            #pass it to response handler


if __name__ == '__main__':
    pass

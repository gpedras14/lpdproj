
#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import Crypto.Cipher.AES
import threading
import client_handling.Client_receiver as C_receiver

clients_threads = []

class Connection_listener(threading.Thread):
    def __init__(self, sock):
        super(Connection_listener, self).__init__()
        self.sock = sock

    def run(self):
        while True:
            sock.listen(2)
            t =  sock.accept()
            clients_threads.append(t)
            C_receiver(t[0]).start()

def main():
    pass


if __name__ == '__main__':
    main()

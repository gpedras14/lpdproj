
#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import Crypto.Cipher.AES
import threading

class Connection_listener(threading.Thread):
    def __init__(self, sock):
        threading.Thread.__init__()
        self.sock = sock

    def run(self):
        while True:
            sock.listen(2)
            sock, addr =  sock.accept()
            #pass to receive, send

def main():
    pass


if __name__ == '__main__':
    main()

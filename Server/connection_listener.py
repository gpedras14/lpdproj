
#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import Crypto.Cipher.AES
import threading
from client_handling import Client_receiver as C_receiver
import ssh_http_logs
import database_op

clients_threads = []

class Connection_listener(threading.Thread):
    def __init__(self, sock):
        super(Connection_listener, self).__init__()
        self.sock = sock

    def run(self):
        while True:
            self.sock.listen(2)
            sock, addr =  self.sock.accept()
            ssh_http_logs.extract_direct_link()
            #clients_threads.append(t)
            C_receiver(sock).start()

def main():
    database_op.flush_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.bind(('localhost', 5001))
    thrd = Connection_listener(sock)
    ssh_http_logs.extract_connections()
    thrd.start()


if __name__ == '__main__':
    main()

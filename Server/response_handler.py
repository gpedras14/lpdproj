#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading
import random
import client_handling
import database_op
import ssh_http_logs
import console_scripts


def check_opearion(c, msg):
    data = ''
    error = False
    if c == chr(32):
        #sql command
        if msg == chr(0):
            #get http logs
            ssh_http_logs.extract_http_log()
            rows = database_op.get_query_response('select * from http_log;')
            for row in rows:
                for v in row:
                    data += v
                    data += ','
                data+='\n'
        elif msg == chr(1):
            #get ssh logs
            ssh_http_logs.extract_ssh_log()
            rows = database_op.get_query_response('select * from ssh_logs;')
            for row in rows:
                for v in row:
                    data += v
                    data += ','
                data+='\n'
        elif msg == chr(2):
            #get directly link devices
            ssh_http_logs.extract_direct_link()
            rows = database_op.get_query_response('select * from d_link ;')
            for row in rows:
                for v in row:
                    data += v
                    data += ','
                data += '\n'
        elif msg == chr(3):
            #get connections 
            ssh_http_logs.extract_connections()
            rows = database_op.get_query_response('select * from connections ;')
            for row in rows:
                for v in row:
                    data += v
                    data += ','
                data += '\n'
        elif msg == chr(4):
            #get report
            file_name = console_scripts.report_sec()
            with open(file_name) as f:
                data = f.read()
        elif msg == chr(5):
            #flush database
            try:
                database_op.flush_db()
            except:
                error = True
                data = "The aplication was unable to flush the database"
        elif msg == chr(6):
            #update all tables
            try:
                database_op.extract_http_log()
                database_op.extract_ssh_log()
                database_op.extract_direct_link()
                database_op.extract_connections()
            except:
                error = True
                data = "The application was unable to update all the tables"

    elif c == chr(16):
        if msg == chr(0):
            #get ssh for graph
            rows = database_op.get_query_response('select * from ssh_logs;')
            for row in rows:
                for v in row:
                    data += v
                    data += ','
                data += '\n'
        elif msg == chr(1):
            #get http for graph
            rows = database_op.get_query_response('select * from http_log ;')
            for row in rows:
                for v in row:
                    data += v
                    data += ','
                data += '\n'
        elif msg == chr(2):
            #get connections
            rows = database_op.get_query_response('select * from connections;')
            for row in rows:
                for v in row:
                    data += v
                    data += ','
                data += '\n'
        elif msg == chr(3):
            rows = database_op.get_query_response('select * from d_link ;')
            for row in rows:
                for v in row:
                    data += v + ','
                data += '\n'
    return data, error

class Data_handler(threading.Thread):
    def __init__(self, sock, aes, rsa_key_r, client_rsa_key_u):
        super(Data_handler, self).__init__()
        self.sock = sock
        self.aes = aes
        self.rsa_key_r = rsa_key_r
        self.client_rsa_key_u = client_rsa_key_u
        if not isinstance(sock, socket._socketobject):
            raise Exception('Not a socket type')

    def run(self):
        flag = 1
        while flag == 1:
            data = client_handling.receive(self.sock)
            t_id = data[0]
            c = data[1]
            data = client_handling.get_message_from_data(data)
            data = self.rsa_key_r.decrypt(data)
            data, error =check_opearion(c, data)
            if not error:
                if data != '':
                    if len(data) > 255:
                        res = ''
                        pacs = len(data)//255
                        left = len(data) % 255
                        for i in range(pacs):
                            tmp = self.client_rsa_key_u.encrypt(data[255*i:255*i + 255], 10)[0]
                            while len(tmp) < 256:
                                tmp = '\x00' + tmp
                                print 'adding padding'
                            res += tmp
                        tmp = self.client_rsa_key_u.encrypt(data[255*pacs:], 10)[0]
                        while len(tmp) < 256:
                            tmp = '\x00' + tmp
                            print 'adding padding'
                        res += tmp
                        data = res
                    else:
                        data = self.client_rsa_key_u.encrypt(data, 10)[0]
                    client_handling.send(self.sock, t_id, chr(1), data=data)
                else:
                    client_handling.send(self.sock, t_id, chr(1))
            else:
                client_handling(self.sock, t_id, chr(0), data=data)


            



if __name__ == '__main__':
    pass

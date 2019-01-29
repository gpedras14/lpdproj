
#!/usr/bin/python
# -*- coding: utf8 -*-

import socket
import threading
import Crypto.Cipher.AES as AES
import Crypto.PublicKey.RSA as RSA
from Crypto import Random
import random
import string
import numpy as np 
import matplotlib.pyplot as plt

def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


def generate_rsa(size=2048):
    rsa = RSA.generate(size)
    return rsa

def generate_AES_key(size=16):
    aes_key = ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(size))
    return aes_key

def create_AES(aes_key, iv=None, block_size=AES.block_size, mode=AES.MODE_CFB):
    if iv is None:
        iv = Random.new().read(block_size)
    elif len(iv) is not block_size:
        raise
    aes = AES.new(aes_key, mode, iv)
    return aes

def encrypt_AES(aes, msg):
    result = aes.encrypt(aes.IV+msg)
    return result

def decrypt_AES(aes, data):
    result = aes.decrypt(data)[len(aes.IV):]
    return result

def encrypt_RSA(rsa_key_u, msg):
    result = None
    if len(msg)<=256:
        result = rsa_key_u.encrypt(msg, random.randint(2,50))
    else:
        chunks = len(msg)//256
        bytes_left = len(msg)%256
        offset = 0
        for i in range(chunks):
            n = 256*(i+1)
            result += rsa_key_u.encrypt(msg[offset:n], random.randint(2,50))
            offset = n
        if bytes_left is not 0:
            result += encrypt(msg[offset:bytes_left], random.randint(2,50))
    return result[0]


def decrypt_RSA(rsa_key_r, data):
    msg = None
    result = ''
    if len(data)<=256:
        msg = rsa_key_r.decrypt(data)[0]
        result = msg
    else:
        chunks = len(data)//256
        bytes_left = len(data)%256
        offset = 0
        for i in range(chunks):
            n = 256*(i+1)
            print str(n - offset)
            result += rsa_key_r.decrypt(data[offset:n])[0]
            offset = n
        if bytes_left is not 0:
            result += rsa_key_r.decrypt(data[offset:bytes_left])[0]
    return result


rsa_server_key_u = None
rsa_key_r = None
aes = None
AES_key = None
sock = None

def http_logs(data):
    names = []
    values = []
    arr = data.split('\n')
    for line in arr:
        day = line.split(',')[1].split('-')[2]
        if day not in names:
            names.append(day)
            values[names.index(day)] += 1
        else:
            names.append(day)
            values.append(1)
    plt.figure(1, figsize=(9,3))
    plt.subplot(131)
    plt.bar(names, values)
    plt.xlabel('day')
    plt.ylabel('accesses')
    plt.subtitle('Http accesses')
    plt.show()


def ssh_graph_logs(data):
    #year-month-day-hh:mm:ss,
    names = []
    values = []
    arr = data.split('\n')
    for line in arr:
        date_line = line.split(',')[0].split('-')
        if date_line[2] not in names:
            names.append(date_line[2])
        else :
            values[names.index(date_line[2])] += 1
    plt.figure(1, figsize=(9,3))
    plt.subplot(131)
    plt.bar(names, values)
    plt.xlabel('day')
    plt.ylabel('attempts')
    plt.subtitle('Ssh attempts')
    plt.show()

def check_t_id(expected_id, m_t_id):
    if expected_id != m_t_id:
        return False
    else:
        return True

def check_c(expected_c, c):
    if expected_c != c:
        return False
    else:
        return True

def get_message_from_data(data):
    if len(data) == 4:
        return None
    else:
        return data[4:]


def receive():
    global sock
    data = sock.recv(4)
    data_len = int(data[2:4].encode('hex'), 16)
    if data_len > 0:
        data += sock.recv(data_len)
    print str(len(data))
    return data


def send( t_id, c, data=None):
    global sock
    msg = t_id + c
    if data is not None:
        b = bin(len(data))[2:]
        data_len = bitstring_to_bytes(b)
        msg += data_len + data
    else:
        msg += '\x00'*2
    sock.send(msg)



def enc_phase_rsa():
    global rsa_key_r, rsa_server_key_u
    rsa_key_r = generate_rsa()
    rsa_key_u = rsa_key_r.publickey()
    data = receive()
    if not check_c(chr(128), data[1]):
        #error
        raise Exception('Wrong Operation')
    msg = get_message_from_data(data)
    if msg is None:
        raise Exception('No key')
    rsa_server_key_u = RSA.importKey(msg)
    send( data[1], chr(128), data=rsa_key_u.exportKey('DER'))
    data = receive()
    if check_c(chr(1), data[1]) is False:
        raise Exception('Wrong Operation')
    enc_phase_aes()


def auth_phase():
    global aes, rsa_server_key_u
    data = receive()
    if check_c(data[1], chr(64)) is False:
        raise Exception('Wrong Operation')
    t_id = data[0]
    c = chr(8)
    passphrase = raw_input('Please type the password: ')
    crypt = encrypt_AES(aes, passphrase)
    crypt = rsa_server_key_u.encrypt(crypt, 10)[0]
    send(t_id, c, data=crypt)
    data = receive()
    if check_c(data[1], chr(1)) is False:
        raise Exception('Unsuccess')

    

def enc_phase_aes():
    global sock, aes, AES_key, rsa_key_r
    data = receive()
    t_id = data[0]
    msg = get_message_from_data(data)
    msg = rsa_key_r.decrypt(msg)
    if check_c(data[1], chr(128)) is False:
        raise Exception('Wrong Operation')
    AES_key = msg
    aes = create_AES(AES_key)
    send(t_id, chr(128), data=rsa_server_key_u.encrypt(AES_key, 10)[0])
    data = receive()
    if check_c(data[1], chr(1)) is False:
        raise
    auth_phase()


def connect_to_app(ip, port = 5001):
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))

def gen_t_id():
    return random._urandom(1)

def menu(n=0):
    if n == 0:
        print """Proj_LPD
        -------------------
        1. Database Operations
        2. Application report
        3. Logs
        4. Extras
        """
    elif n == 1:
        print """Database Opeartions
        ------------------------
        1. Flush Database
        2. Update all tables
        """
    elif n == 2:
        print """Application report
        ----------------------
        1. Download report
        2. SSH attempts graph
        3. HTTP attempts graph
        """
    elif n==3:
        print """Logs
        1. Get ssh logs
        2. Get http logs
        3. Get connections
        4. Get Directly connected devices
        """
    elif n==4:
        print """Extras"""

def option(n):
    t_id = gen_t_id()
    if n == 1:
        menu(1)
        inp = raw_input('choice: ')
        t=int(inp)
        if t == 1:
            c = chr(32)
            data = chr(5)
        elif t == 2:
            c = chr(32)
            data = chr(6)
    if n==2:
        menu(2)
        inp = raw_input('choice: ')
        t = int(inp)
        if t == 1:
            c = chr(32)
            data = chr(4) # get report
        elif t==2:
            c = chr(16)
            data = chr(0)
        elif t==3:
            c = chr(16)
            data = chr(1)
    if n==3:
        menu(3)
        inp = raw_input('choice: ')
        t = int(inp)
        if t == 1:
            c = chr(32)
            data = chr(1)
        elif t==2:
            c = chr(32)
            data = chr(0)
        elif t==3:
            c = chr(32)
            data = chr(3)
        elif t ==4:
            c = chr(32)
            data = chr(2)
    crypt = rsa_server_key_u.encrypt(data, 10)[0]
    send(t_id, c, data=crypt)
    rv = receive()
    message = get_message_from_data(rv)
    if message is not None:
        message = rsa_key_r.decrypt(message)
    if rv[1] == chr(0):
        print 'Error occured:\n%s' % message
    else:
        print 'Success'
        if c == chr(32) and data == chr(4):
            file_name = ''.join(random.choice(string.ascii_letters) for _ in range(5))
            with open(file_name, 'w') as f:
                f.write(message)
            print 'File downloaded, file name: %s' % file_name
        elif c == chr(32) and data == chr(0):
            file_name = ''.join(random.choice(string.ascii_letters) for _ in range(5))
            with open(file_name, 'w') as f:
                f.write(message)
            print 'csv file downloaded, file name: %s' % file_name
            lines = message.split('\n')
            print 'ip date request         status code'
            for line in lines:
                l = line.split(',')
                tmp = ''
                for g in l:
                    tmp += g + " "
                print tmp
        elif c==chr(32) and data == chr(1):
            file_name = ''.join(random.choice(string.ascii_letters) for _ in range(5))
            with open(file_name, 'w') as f:
                f.write(message)
            print 'csv file downloaded, file name: %s' % file_name
            lines = message.split('\n')
            print 'date ip port status'
            for line in lines:
                l = line.split(',')
                tmp = ''
                for g in l:
                    tmp += g + " "
                print tmp
        elif c == chr(32) and data == chr(3):
            file_name = ''.join(random.choice(string.ascii_letters) for _ in range(5))
            with open(file_name, 'w') as f:
                f.write(message)
            print 'csv file downloaded, file name: %s' % file_name
            lines = message.split('\n')
            print 'ip country port status'
            for line in lines:
                l = line.split(',')
                tmp = ''
                for g in l:
                    tmp += g + " "
                print tmp
        elif c == chr(32) and data == chr(2):
            file_name = ''.join(random.choice(string.ascii_letters) for _ in range(5))
            with open(file_name, 'w') as f:
                f.write(message)
            print 'csv file downloaded, file name: %s' % file_name
            lines = message.split('\n')
            print 'MAC address   ether_type    interface'
            for line in lines:
                l = line.split(',')
                tmp = ''
                for g in l:
                    tmp += g + " "
                print tmp




def test_response():
    global rsa_key_r, rsa_server_key_u, aes
    t_id = random._urandom(1)
    c = chr(32)
    data = chr(4)
    data_len = chr(0) + chr(1)
    data = rsa_server_key_u.encrypt(data, 10)[0]
    send(t_id, c, data=data)
    data = receive()
    data = get_message_from_data(data)
    print 'size of pack: %d' % len(data)
    if len(data) > 256:
        res = ''
        pacs = len(data)//256
        for i in range(pacs):
            res += rsa_key_r.decrypt(data[256*i: 256*i + 256])
        data = res
    else:
        data = rsa_key_r.decrypt(data)
    with open('file.pdf', 'w') as f:
        f.write(data)

def user_input():
    flag = 1
    n = 0
    while flag == 1:
        menu(n)
        inp = raw_input('choice: ')
        option(int(inp))

def main():
    connect_to_app('localhost')
    enc_phase_rsa()


if __name__ == '__main__':
    main()
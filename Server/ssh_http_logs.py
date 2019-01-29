#!/usr/bin/python
# -*- coding: utf8 -*-

import os
import database_op
from database_op import execute_insert, get_query_response
import console_scripts

ssh_log_path = 'logs/ssh_log'
http_log_path = 'logs/http_log'
f_tell_ssh = 0
f_tell_http = 0

months = {'Jan':'01', 'Feb':'02', 'Mar':'03', 'Apr':'04', 'May':'05', 'Jun':'06', 'Jul':'07', 'Aug':'08', 'Sep':'09', 'Oct':'10', 'Nov':'11', 'Dec':'12'}


def extract_direct_link():
	values = ()
	database_op.default_opearion()
	fil = os.popen('arp -n')
	fil.readline()
	ether_type = 'ether'
	info = fil.readline().replace('  ', '')
	info = info.split(' ')
	mac_addr = info[1]
	interface = info[3].replace('\n', '')
	values = (mac_addr, ether_type, interface)
	rows = get_query_response('select mac_address from d_link where mac_address = "'+ mac_addr + '"')
	if len(rows) == 0:
		execute_insert(database_op.INSERT_DIRECT_LINK, values)

def extract_connections():
	values =()
	database_op.default_opearion()
	fil = os.popen('netstat -nt')
	fil.readline()
	fil.readline()
	info = fil.readline()
	l = info.split(' ')
	new_l = []
	for value in l:
		if value != '':
			new_l.append(value)
	ip = new_l[4].split(':')[0]
	port = new_l[4].split(':')[1]
	status = new_l[5].replace('\n', '')
	country = console_scripts.get_ip_location(ip).country.name.encode('utf-8')
	values = (ip, country, port, status)
	rows = get_query_response('select ip from connections where ip = "'+ip+'"')
	if len(rows) == 0:
		execute_insert(database_op.INSERT_CONNECTIONS, values)


def extract_http_log():
	values = ()
	database_op.default_opearion()
	with open(http_log_path, 'r') as f:
		f.seek(f_tell_http)
		for line in f:
			splited_line = line.split(' - - ')
			ip = splited_line[0]
			date = splited_line[1].split('/')
			day = date[0][1:]
			month = date[1]
			year = date[2][0:4]
			time = date[2][4:8]
			info = splited_line[1].split('"')
			request = info[1]
			status_code = info[2][1:len(info[2])-3]
			values = (ip, year+'-'+months[month]+'-'+day+'-'+time, request, status_code)
			execute_insert(database_op.INSERT_HTTP_LOG, values)
		f_tell_http=f.tell()

def extract_ssh_log():
	values = ()
	database_op.default_opearion()
	with open(ssh_log_path, 'r') as f:
		f.seek(f_tell_ssh)
		for line in f:
			splited_line = line.split('  ')
			month = months[splited_line[0]] 
			day = splited_line[1][:2]
			time = splited_line[2:8]
			year = '2018'
			date = year+'-'+month+'-'+day+'-'+time
			if 'from' in line:
				ip_line = line.split('from')
				ip_line = ip_line[1].split('port')[0]
				ip = ip_line.replace(' ','').replace('\n', '')
			else:
				ip = None
			if 'port' in line:
				port_line = line.split('port')
				port = port_line[1][1:5]
			else:
				port = None
			status = line.split(']:')[1]
			if 'from' in status:
				status = status.split('from')[0]
			values = (date, ip, port, status)
			execute_insert(database_op.INSERT_SSH_LOG, values)
		f_tell_ssh = f.tell()

if __name__ == '__main__':
	extract_direct_link()


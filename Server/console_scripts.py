#!/usr/bin/python
# -*- coding: utf8 -*-

import os
import socket
import geoip2.database

path = 'geoip/geo_country.mmdb'

def get_current_netstat():
	lines = []
	result = os.popen('netstat -nat')
	for line in result:
		result.append(line)
	return lines


def get_current_netstat_foreign_ips(lines = []):
	new_lines = []
	ips = []
	filtred = []
	tmp = ''
	result = os.popen('netstat -nat')
	for line in result:
		lines.append(line)
	lines = lines[2:]
	for l in lines:
		filtred = []
		arr = l.split(' ')
		for c in arr:
			if c is not '':
				filtred.append(c)
		new_lines.append(filtred)
	for arr in new_lines:
		tmp = arr[4].split(':')[0]
		if len(tmp) is not 0:
			ips.append(tmp)
	return ips


def scan_ports(first, last, host='localhost'):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setdefaulttimeout(1)
	result = []
	for port in range(first, last):
		if sock.connect_ex((host, port)) is 0:
			service = ''
			try:
				service = socket.getservbyport(port)
				result.append((port, service))
			except:
				result.append((port, ''))
	return scan_ports


def get_ip_location(ip):
	global path
	geo = geoip2.database.Reader(path)
	data = geo.country(ip)
	return data



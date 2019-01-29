#!/usr/bin/python
# -*- coding: utf8 -*-

import os
import socket
import geoip2.database
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import datetime
import database_op
import random
import string

path = 'geoip/geo_country.mmdb'

def report_sec():
	file_name = ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(10))
	file_name += '.pdf'
	logins = database_op.get_query_response('select * from logins;')
	http = database_op.get_query_response('select * from http_log;')
	ssh = database_op.get_query_response('select * from ssh_logs;')
	d_link = database_op.get_query_response('select * from d_link;')
	#connect = database_op.get_query_response('select * from connections;')
	now = datetime.datetime.now()
	c = canvas.Canvas(file_name)
	c.setLineWidth(.3)
	c.setFont('Helvetica', 17)
	c.drawString(30, 750, 'Security Report of application')
	c.drawString(500, 750, now.strftime("%Y-%m-%d"))

	c.drawString(30, 735, 'Applications logins')
	c.drawString(30, 710, 'Number of logins to this momment:'+str(len(logins)))
	if len(logins) != 0:
		c.drawString(30, 675, 'Last Login: '+str(logins[0]))

	c.drawString(30, 655, 'SSH atempts')
	c.drawString(30, 630, 'Number of ssh attempts to this momment: '+str(len(ssh)))
	errors = 0
	failed = 0
	illegal = 0
	ips = []
	countries = []
	for row in ssh:
		if 'error' in row[3]:
			error += 1
			ips.append(row[1])
			countries.append(get_ip_location(row[1].encode('utf-8')).country.name)
		elif 'Failed' in row[3]:
			failed += 1
			ips.append(row[1])
			countries.append(get_ip_location(row[1].encode('utf-8')).country.name)
		elif 'Illegal' in row[3]:
			illegal += 1
			ips.append(row[1])
			countries.append(get_ip_location(row[1].encode('utf-8')).country.name)
	c.drawString(30, 615, 'Number of failed attempts: '+str(failed))
	c.drawString(30, 600, 'Number of illegal attempts: '+str(illegal))
	c.drawString(30, 585, 'Number of errors: '+str(errors))
	c.drawString(30, 570, 'Other :'+str(len(ssh) - failed - errors - illegal))


	c.drawString(30, 545, 'Suspiscious addresses: '+str(len(ips)))
	l=545
	for ip, country in zip(ips, countries):
		c.drawString(30, 545 - 15, 'IP: ' + ip + " Country: " + country)
		l-=15
	l -=20
	c.drawString(30, l, 'HTTP report ')
	l -= 15
	c.drawString(30, l, 'Http accesses: '+str(len(http)))
	l -= 15
	success = 0
	errors = 0
	for row in http:
		if '200' in row[3]:
			success += 1
		elif '400' in row[3]:
			errors += 1
	c.drawString(30, l, 'Success attempts: '+str(success))
	l-=15
	c.drawString(30, l, 'Error attempts (400 code): '+str(errors))
	l-=15
	c.drawString(30, l, 'Other code: '+str(len(http) - errors - success))
	l-=20
	c.drawString(30, l, 'Directly connected devices: ' + str(len(d_link)))
	l-=15
	for row in d_link:
		l-=15
		c.drawString(30, l, 'MAC: '+str(row[0]) + " interface: " + str(row[2]))

	c.save()
	return file_name



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
		if sock.connect_ex((host, port)) == 0:
			service = ''
			try:
				service = socket.getservbyport(port)
				result.append((port, service))
			except:
				result.append((port, ''))
	return result


def get_ip_location(ip):
	global path
	geo = geoip2.database.Reader(path)
	data = geo.country(ip)
	return data


if __name__ == '__main__':
	report_sec()

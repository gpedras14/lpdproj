#!/usr/bin/python
# -*- coding: utf8 -*-

import sqlite3
from sqlite3 import Error
import os

path = 'database/server.db'
INSERT_DIRECT_LINK = ''' INSERT INTO d_link ( 
mac_address, ether_type, interface)
VALUES (?, ?, ? )'''

INSERT_CONNECTIONS = ''' INSERT INTO connections ( 
ip, country, port, status)
VALUES (?, ?, ?, ?)'''

INSERT_SSH_LOG = '''INSERT INTO ssh_logs(
date, ip, port, status)
VALUES (?, ?, ?, ?)'''

INSERT_LOGINS = ''' INSERT INTO logins (date)
VALUES (?) ;'''

INSERT_HTTP_LOG = ''' INSERT INTO http_log ( 
ip, date, request, status_code)
VALUES (?, ? , ? , ?)'''

def flush_db():
	os.popen('rm '+path)
	os.popen('touch '+path)
	default_opearion()

def get_db():
	global path
	result = os.popen('pwd')
	line = result.read()
	line = line[0:len(line)-1]
	full_path = path + line
	return full_path


def execute_insert(sql_inf, values):
	try:
		db = sqlite3.connect(path, isolation_level=None)
		conn = db.cursor()
		conn.execute(sql_inf, values)
		db.close()
	except Error as e:
		print e


def get_query_response(query):
	result = []
	db = sqlite3.connect(path)
	conn = db.cursor()
	rows = conn.execute(query)
	result = rows.fetchall()
	return result


def create_table(conn, create_table_sql):
	try:
		c = conn.cursor()
		c.execute(create_table_sql)
	except Error as e:
		print e

def default_opearion():
	conn = sqlite3.connect(path)
	sql_http_log_table= """ CREATE TABLE IF NOT EXISTS http_log (
	ip TEXT,
	date TEXT,
	request TEXT,
	status_code TEXT
	);"""

	sql_ssh_logs_table = """ CREATE TABLE IF NOT EXISTS ssh_logs (
	date TEXT,
	ip TEXT,
	port INTEGER,
	status TEXT
	); """

	sql_connections_table = """ CREATE TABLE IF NOT EXISTS connections (
	ip TEXT,
	country TEXT,
	port INTEGER,
	status TEXT
	); """

	sql_direct_link_table = """ CREATE TABLE IF NOT EXISTS d_link(
	mac_address TEXT,
	ether_type TEXT,
	interface TEXT
	); """

	sql_logins_table = """ CREATE TABLE IF NOT EXISTS logins (
	date TEXT
	);"""


	create_table(conn, sql_connections_table)
	create_table(conn, sql_direct_link_table)
	create_table( conn, sql_ssh_logs_table)
	create_table(conn, sql_http_log_table)
	create_table(conn, sql_logins_table)

if __name__ == '__main__':
	default_opearion()
	print 'dne'
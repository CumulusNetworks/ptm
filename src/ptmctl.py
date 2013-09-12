#!/usr/bin/env python

# The MIT License (MIT)
# 
# Copyright (c) 2013 Cumulus Networks Inc.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# 

import socket
import os, os.path
import subprocess
import csv
import re
import StringIO
from itertools import groupby
import argparse

PTM_EOF_LEN = 4
PTM_HEADER_LEN = 10
PTM_BRIEFSTATUS_LEN = 22
ptm_msghdr_fieldnames = ('length', 'version')
ptm_sockname = "\0/var/run/ptmd.socket"

def cmpfn(s):
    return [int(''.join(g)) if k else ''.join(g) for k, g in groupby(s, str.isdigit)]

def ptm_get_link_status():
    ''' Get output of "ip link show up" and parse for up status'''
    try:
        link_out = subprocess.Popen((['/bin/ip','-o', 'link','show']),
                                    stdout=subprocess.PIPE,
                                    shell=False).communicate()[0]
    except EnvironmentError as e:
        print e,e.errno
        sys.exit(e.errno)

    link_status = {}
    link_out_lines = link_out.split("\n")

    for line in link_out_lines:
        if line is '':
            continue
        fields = line.split(":")
        iface = fields[1][1:]           # strip the leading space
        if 'UP,LOWER_UP' in fields[2]:
            link_status[iface] = 'up'
        else:
            link_status[iface] = 'down'

    return link_status

class PtmClientError(Exception): pass

class PtmClient(socket.socket):
    def __init__(self):
        try:
            socket.socket.__init__(self, socket.AF_UNIX, socket.SOCK_STREAM)
            self.connect(ptm_sockname)

        except socket.error, (errno, string):
            raise PtmClientError("socket err [%d]: %s\n" % (errno, string))

        self.setblocking(1)

    #Get the initial brief status update
    def ptm_get_brief_status (self, display=True, watch=False):
        if display:
            short_fmt = "%-8s %-8s"
            print "----------------"
            print  short_fmt % ("Port", "Status")
            print "----------------"

        self.setblocking(1)

        while True:
            data = self.recv(PTM_EOF_LEN)
            if re.search("EOF", data):
                break
            data1 = self.recv(PTM_BRIEFSTATUS_LEN - PTM_EOF_LEN)
            data = data + data1
            output = data.split()
            if display:
                print short_fmt % (output[0], output[1])

    #Now get the interesting CSV stuff
    def ptm_get_dump_status (self, watch=False):

        if not watch:
            self.sendall('dump-status')
        else:
            self.setblocking(1)

        ptmstat = {}
        while True:
            data = self.recv(PTM_EOF_LEN)
            if re.search("EOF", data):
                break
            data1 = self.recv(PTM_HEADER_LEN - PTM_EOF_LEN)
            data = data + data1
            f = StringIO.StringIO(data)
            reader = csv.DictReader(f, ptm_msghdr_fieldnames)
            len = 0
            for row in reader:
                len = int(row['length'])
                break
            data = self.recv(len)
            f = StringIO.StringIO(data)
            reader = csv.DictReader(f)
            for row in reader:
                ptmstat[row['port']] = [row['status'], row['expected nbr'], row['observed nbr'], row['last update']]

        link_stat = ptm_get_link_status()

        long_fmt = "%-6s %-6s %-20s %-20s %-10s"
        print "---------------------------------------------------------------------"
        print  long_fmt % ("Port", "Status", "Expected Nbr", "Observed Nbr", "Last Updated")
        print "---------------------------------------------------------------------"

        for i in sorted(ptmstat, key=cmpfn):
            if i in link_stat:
		if link_stat[i] is 'up':
                	print long_fmt % (i, ptmstat[i][0], ptmstat[i][1], ptmstat[i][2], ptmstat[i][3])
            	else:
                	print long_fmt % (i, link_stat[i], ptmstat[i][1], ptmstat[i][2], ptmstat[i][3])
	    else:
                	print long_fmt % (i, "N/A", ptmstat[i][1], ptmstat[i][2], ptmstat[i][3])

parser = argparse.ArgumentParser(description='ptmctl arguments parser')
parser.add_argument('-w', '--watch', help='monitor status change', action='store_true')

args = parser.parse_args()

c = PtmClient()

# On connect, the brief status is always given, unconditionally
c.ptm_get_brief_status(False)

c.ptm_get_dump_status()

# Brief status is default
if args.watch:
    c.ptm_get_dump_status(watch=True)

c.close()

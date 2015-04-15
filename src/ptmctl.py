#!/usr/bin/env python

import socket
import os, os.path
import subprocess
import csv
import re
import sys
import StringIO
from itertools import groupby
import argparse
import json

PTM_EOF_LEN = 4
PTM_HEADER_LEN = 10

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
        if len(fields) < 3:
            continue
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
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.connect(ptm_sockname)

        except socket.error, (errno, string):
            print "Service not running, unable to connect to server"
            sys.exit(1)

        self._sock.setblocking(1)
        self._sock.settimeout(1)

    def recv(self, bufsize, flags=False):
        try:
            return self._sock.recv(bufsize, flags)
        except socket.timeout as errno:
            print "Timed out waiting for socket read"
            sys.exit(1)

    def sendall(self, data):
        return self._sock.sendall(data)

    def setblocking(self, flags=True):
        self._sock.setblocking(flags)

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

    #dump json output
    def ptm_get_json (self):

        cmd = 'get-status detail'
        self.sendall(cmd)

        ptmstr = {}
        self.settimeout(None)
        while True:
            data = self.recv(PTM_EOF_LEN)
            if "EOF" in data:
                break
            data = "".join([data, self.recv(PTM_HEADER_LEN - PTM_EOF_LEN)])
            f = StringIO.StringIO(data)
            reader = csv.DictReader(f, ptm_msghdr_fieldnames)
            row = next(reader);
            clen = int(row['length'])
            data = self.recv(clen)
            f = StringIO.StringIO(data)
            reader = csv.DictReader(f)
            ptmstr[row['port']] = [row for row in reader if 'port' in row]
            # end for row loop
        # dump into json
        print json.dumps(ptmstr, indent=4)
        # end while(true)

    #Get debug info (default=lldp)
    def ptm_get_debug (self, mod='lldp'):

        cmd = "".join(['get-debug ', mod])
        self.sendall(cmd)

        ptmstr = {}
        colwidth = {}
        self.settimeout(None)
        rownum = 0
        while True:
            data = self.recv(PTM_EOF_LEN)
            if "EOF" in data:
                break
            data = "".join([data, self.recv(PTM_HEADER_LEN - PTM_EOF_LEN)])
            f = StringIO.StringIO(data)
            reader = csv.DictReader(f, ptm_msghdr_fieldnames)
            row = next(reader);
            clen = int(row['length'])
            data = self.recv(clen)
            f = StringIO.StringIO(data)
            reader = csv.DictReader(f)
            for row in reader:
                # read in row
                if rownum == 0:
                    # save the first row to print the header
                    header = row
                if 'port' in row:
                    ptmstr[row['port']] = row
                else:
                    ptmstr[rownum] = row

                # adjust col width size
                for f in reader.fieldnames:
                    # split multi-word column titles into 2 rows
                    hsplit = f.split(" ",1)
                    maxh = len(hsplit[0])
                    if len(hsplit) > 1:
                        maxh = max(len(hsplit[0]), len(hsplit[1]))
                    if rownum == 0:
                        colwidth[f] = max(maxh, len(row[f]))
                    else:
                        colwidth[f] = max(colwidth[f], max(maxh, len(row[f])))
                # end for row loop
                rownum = rownum+1
        # end while(true)
        if rownum == 0:
          print "NULL Response from PTM - illegal command?"
          sys.exit(1)

        # print the row header
        print "%s" % ("-" * 80)
        for f in reader.fieldnames:
          # split multi-word column titles into 2 rows
          hsplit = f.split(" ",1)
          print '%-*s ' % (colwidth[f], hsplit[0]),
        print ""
        for f in reader.fieldnames:
          # split multi-word column titles into 2 rows
          hsplit = f.split(" ",1)
          if len(hsplit) > 1:
            print '%-*s ' % (colwidth[f], hsplit[1]),
          else:
            print '%-*s ' % (colwidth[f], " "),
        print ""
        print "%s" % ("-" * 80)
        # print the rows

        if 'port' not in header:
          for i in ptmstr:
            for f in reader.fieldnames:
              print '%-*s ' % (colwidth[f], ptmstr[i].get(f)),
            print ""
        else:
            # per-port output
          for i in sorted(ptmstr, key=cmpfn):
            for f in reader.fieldnames:
              print '%-*s ' % (colwidth[f], ptmstr[i].get(f)),
            print ""

    #Get the status update (default brief)
    def ptm_get_status (self, detail=False):

        if detail:
            self.sendall('get-status detail')
        else :
            self.sendall('get-status')

        ptmstr = {}
        colwidth = {}
        self.settimeout(None)
        rownum = 0
        while True:
            data = self.recv(PTM_EOF_LEN)
            if "EOF" in data:
                break
            data = "".join([data, self.recv(PTM_HEADER_LEN - PTM_EOF_LEN)])
            f = StringIO.StringIO(data)
            reader = csv.DictReader(f, ptm_msghdr_fieldnames)
            row = next(reader);
            clen = int(row['length'])
            data = self.recv(clen)
            f = StringIO.StringIO(data)
            reader = csv.DictReader(f)
            for row in reader:
              # read in row
              if rownum == 0:
                # save the first row to print the header
                header = row
              if 'port' in row:
                ptmstr[row['port']] = row
              else:
                ptmstr[rownum] = row
              # adjust col width size (inside row loop)
              for f in reader.fieldnames:
                # split multi-word column titles into 2 rows
                hsplit = f.split(" ",1)
                maxh = len(hsplit[0])
                if len(hsplit) > 1:
                  maxh = max(len(hsplit[0]), len(hsplit[1]))
                if rownum == 0:
                  colwidth[f] = max(maxh, len(row[f]))
                else:
                  colwidth[f] = max(colwidth[f], max(maxh, len(row[f])))
              # end for row loop
            rownum = rownum+1
        # end while(true)
        if rownum == 0:
          print "NULL Response from PTM - illegal command?"
          sys.exit(1)

        # print the row header
        seplen = 0
        for f in reader.fieldnames:
            seplen += (colwidth[f]+len("  "))
        print "%s" % ("-" * seplen)
        for f in reader.fieldnames:
          # split multi-word column titles into 2 rows
          hsplit = f.split(" ",1)
          print '%-*s ' % (colwidth[f], hsplit[0]),
        print ""
        for f in reader.fieldnames:
          # split multi-word column titles into 2 rows
          hsplit = f.split(" ",1)
          if len(hsplit) > 1:
            print '%-*s ' % (colwidth[f], hsplit[1]),
          else:
            print '%-*s ' % (colwidth[f], " "),
        print ""
        print "%s" % ("-" * seplen)
        # print the rows
        if 'port' not in header:
          for i in ptmstr:
            for f in reader.fieldnames:
              print '%-*s ' % (colwidth[f], ptmstr[i].get(f)),
            print ""
        else:
          # per-port output
          link_stat = ptm_get_link_status()

          for i in sorted(ptmstr, key=cmpfn):
            if i in link_stat:
              if link_stat[i] is 'up':
                for f in reader.fieldnames:
                  print '%-*s ' % (colwidth[f], ptmstr[i].get(f)),
              else:
                for f in reader.fieldnames:
                  if f == 'status':
                    print '%-*s ' % (colwidth[f], "no-info"),
                  else:
                    print '%-*s ' % (colwidth[f], ptmstr[i].get(f)),
            else:
              # not in link_stat
              for f in reader.fieldnames:
                if f == 'status':
                  print '%-*s ' % (colwidth[f], "N/A"),
                else:
                  print '%-*s ' % (colwidth[f], ptmstr[i].get(f)),
            print ""

parser = argparse.ArgumentParser(description='ptmctl arguments parser')
parser.add_argument('-d', '--detail', help='print details', action='store_true')
parser.add_argument('-b', '--bfd', help='print BFD details', action='store_true')
parser.add_argument('-l', '--lldp', help='print LLDP details', action='store_true')
parser.add_argument('-j', '--json', help='json output', action='store_true')

args = parser.parse_args()

c = PtmClient()

if args.bfd:
    c.ptm_get_debug(mod='bfd')
elif args.lldp:
    c.ptm_get_debug(mod='lldp')
elif args.json:
    c.ptm_get_json()
else :
    c.ptm_get_status(detail=args.detail)

c.close()

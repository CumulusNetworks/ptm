#!/usr/bin/env python

# Copyright 2013,2014,2015,2016,2017 Cumulus Networks, Inc. All rights reserved.
#
# This file is licensed to You under the Eclipse Public License (EPL);
# You may not use this file except in compliance with the License. You
# may obtain a copy of the License at
# http://www.opensource.org/licenses/eclipse-1.0.php


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
import collections
import signal
import sys
import ipaddr

# ptm hdr = length,(5) version,(5) type,(5) cmdid,(5) client\n(17)
PTM_HEADER_LEN = 37
PTM_VERSION = 2
PTM_MSG_TYPE_NOTIFICATION = 1
PTM_MSG_TYPE_CMD = 2
PTM_MSG_TYPE_RESPONSE = 3
PTMCTL_CMDID = 0

ptm_msghdr_fieldnames = ('length', 'version', 'type', 'cmdid', 'client')
ptm_sockname = "\0/var/run/ptmd.socket"

def signal_handler (signal, frame):
    print '\nCtrl-c detected\n'
    sys.exit(0)

def ptm_output_print(self, args, ptmstr, reader, colwidth):
    try:
        _ptm_output_print(self, args, ptmstr, reader, colwidth)
    except IOError:
        sys.exit(0)

def _ptm_output_print(self, args, ptmstr, reader, colwidth):

    if args.json:
        # dump into json
        print json.dumps(ptmstr, indent=4)
        sys.exit(0)

    # if cmd failure - then just print the cmd_ext_status
    if ptmstr[0].get("cmd_status"):
      if ptmstr[0].get("cmd_status") == "fail":
        print 'ERR: %s' % (ptmstr[0].get("cmd_ext_status"))
      else:
        print 'INFO: %s' % (ptmstr[0].get("cmd_ext_status"))
      print ""
      sys.exit(0)

    # print the row header
    seplen = 0
    for f in reader.fieldnames:
        seplen += (colwidth[f]+len("  "))
    print "%s" % ("-" * seplen)
    for f in reader.fieldnames:
      # split multi-word column titles into 2 rows
      # print top row
      hsplit = f.split(" ",1)
      print '%-*s ' % (colwidth[f], hsplit[0]),
    print ""
    for f in reader.fieldnames:
      # print the bottom row
      hsplit = f.split(" ",1)
      if len(hsplit) > 1:
        print '%-*s ' % (colwidth[f], hsplit[1]),
      else:
        # print blanks instead
        print '%-*s ' % (colwidth[f], " "),
    print ""
    print "%s" % ("-" * seplen)
    # print the rows
    for i in ptmstr:
      for f in reader.fieldnames:
        print '%-*s ' % (colwidth[f], ptmstr[i].get(f)),
      print ""

def ptm_output_parser(self, args, display=True, ignore_notify=True):

    ptmstr = {}
    colwidth = {}
    rownum = 0
    done = False
    while (not done):
        cnotify = False
        # if we are not in "listen mode" and first row is read
        # reduce the socket timeout
        if (rownum == 1) and (ignore_notify == True):
            self._sock.settimeout(3)
        data = self.recv(PTM_HEADER_LEN)
        if (len(data) < PTM_HEADER_LEN):
            done = True
            continue
        f = StringIO.StringIO(data)
        hdr_reader = csv.DictReader(f, ptm_msghdr_fieldnames)
        row = next(hdr_reader);
        clen = int(row['length'])
        cnotify = (int(row['type']) == 1)
        data = self.recv(clen)
        if (cnotify and ignore_notify):
            # we are done processing
            done = True
            continue
        f = StringIO.StringIO(data)
        reader = csv.DictReader(f)
        for row in reader:
          # read in row
          if rownum == 0:
            # save the first row to print the header
            header = row
          else:
            if (cnotify and not ignore_notify):
              if (i for x in header if x not in row):
                # we have a different notification msg
                # reset the local vars
                colwidth = {}
                ptmstr = {}
                header = row
                rownum = 0
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
          if 'cmd_status' in row:
            done = True
            break
          # end for row loop
        # print notifications
        if (cnotify and display):
            ptm_output_print(self, args, ptmstr, reader, colwidth)
        rownum = rownum+1
    # end while(not done)
    if rownum == 0:
        print "No Response from PTM"
        sys.exit(1)

    if (display):
        # print the output
        ptm_output_print(self, args, ptmstr, reader, colwidth)

class PtmClientError(Exception): pass

class PtmClient(socket.socket):
    def __init__(self):
        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.connect(ptm_sockname)

        except socket.error, (errno, string):
            print "Unable to connect to PTMD [%s]" % (string)
            sys.exit(1)

        self._sock.setblocking(1)
        self._sock.settimeout(30)

    def recv(self, bufsize, flags=False):
        try:
            return self._sock.recv(bufsize, flags)
        except socket.timeout as string:
            return ""
        except socket.error, (errno, string):
            print "Unable to receive data from PTMD [%s]" % (string)
            sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(1)

    def sendall(self, data):
        try:
            return self._sock.sendall(data)
        except socket.error, (errno, string):
            print "Unable to send command to PTMD [%s]" % (string)
            sys.exit(1)

    def setblocking(self, flags=True):
        self._sock.setblocking(flags)

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

    def create_ptm_hdr(self, args, msglen):
        ptm_dict = collections.OrderedDict()
        ptm_hdr = []
        ptm_hdr.append("{:4d}".format(msglen))
        ptm_hdr.append("{:4d}".format(PTM_VERSION))
        ptm_hdr.append("{:4d}".format(PTM_MSG_TYPE_CMD))
        ptm_hdr.append("{:4d}".format(PTMCTL_CMDID))
        ptm_hdr.append("{:16s}".format(args.client))
        for x,y in zip(ptm_msghdr_fieldnames, ptm_hdr):
            ptm_dict[x] = y
        ph = StringIO.StringIO()
        ph_writer = csv.DictWriter(ph, fieldnames=ptm_msghdr_fieldnames, lineterminator='\n')
        ph_writer.writerow(ptm_dict)
        return ph

    def ptm_listen_for_notifcations (self, args):

        # issue a get-status just to recv notifications
        c.ptm_get_status(args, display=False)
        print 'Listen to notifications - press Ctrl-C to exit\n'
        signal.signal(signal.SIGINT, signal_handler)
        self.settimeout(None)
        while (True):
            ptm_output_parser(self, args, ignore_notify=False)

    #get bfd client related info
    def ptm_get_bfd_client (self, args, sess=False):

        # create the cmd hdr
        cmd_dict = collections.OrderedDict()
        cmd_dict['cmd'] = 'get-bfd-client'
        if (sess == True):
            cmd_dict['sessions'] = 'yes'

        if (args.client):
            cmd_dict['client'] = args.client

        if (args.detail):
            cmd_dict['detail'] = 'yes'

        ch = StringIO.StringIO()
        ch_writer = csv.DictWriter(ch, fieldnames=cmd_dict.keys(), lineterminator='\n')
        ch_writer.writeheader()
        ch_writer.writerow(cmd_dict)

        # create the ptm hdr
        ph = self.create_ptm_hdr(args, len(ch.getvalue()))

        # serialize
        # first ptm hdr, followed by cmd hdr, data
        cmd = "".join([ph.getvalue(), ch.getvalue()])
        self.sendall(cmd)

        ptm_output_parser(self, args)

    #send bfd command
    def ptm_send_bfd_cmd (self, args):

        if (os.geteuid()):
            print "Cannot run this command. Not a privileged user"
            sys.exit(1)

    # create the cmd hdr
        cmd_dict = collections.OrderedDict()
        if (args.start_bfd_sess):
            cmd_dict['cmd'] = 'start-bfd-sess'
        if (args.stop_bfd_sess):
            cmd_dict['cmd'] = 'stop-bfd-sess'

        if (args.src):
            cmd_dict['srcIPaddr'] = args.src
        if (args.dst):
            cmd_dict['dstIPaddr'] = args.dst
        if (args.multihop):
            cmd_dict['multiHop'] = '1'
        if (args.ifname):
            cmd_dict['ifName'] = args.ifname
        if (args.vnid):
            cmd_dict['vnid'] = args.vnid
        if (args.minrx):
            cmd_dict['requiredMinRx'] = args.minrx
        if (args.mintx):
            cmd_dict['upMinTx'] = args.mintx
        if (args.detectmult):
            cmd_dict['detectMult'] = args.detectmult
        if (args.client):
            cmd_dict['client'] = args.client
        if (args.seqid):
            cmd_dict['seqid'] = args.seqid
        if (args.ldmac):
            cmd_dict['local_dst_mac'] = args.ldmac
        if (args.ldip):
            cmd_dict['local_dst_ip'] = args.ldip
        if (args.rdmac):
            cmd_dict['remote_dst_mac'] = args.rdmac
        if (args.rdip):
            cmd_dict['remote_dst_ip'] = args.rdip
        if (args.dminrx):
            cmd_dict['decay_min_rx'] = args.rdminrx
        if (args.fwdifrx):
            cmd_dict['forwarding_if_rx'] = args.fwdifrx
        if (args.cpdown):
            cmd_dict['cpath_down'] = args.cpdown
        if (args.chktk):
            cmd_dict['check_tnl_key'] = args.chktk
        if (args.maxhopcnt):
            cmd_dict['maxHopCnt'] = args.maxhopcnt
        if (args.client):
            cmd_dict['client'] = args.client
        if (args.afi):
            cmd_dict['afi'] = args.afi
        if (args.sendEvent):
            cmd_dict['sendEvent'] = args.sendEvent

        # print
        ch = StringIO.StringIO()
        ch_writer = csv.DictWriter(ch, fieldnames=cmd_dict.keys(), lineterminator='\n')
        ch_writer.writeheader()
        ch_writer.writerow(cmd_dict)

        # create the ptm hdr
        ph = self.create_ptm_hdr(args, len(ch.getvalue()))

        # serialize
        # first ptm hdr, followed by cmd hdr, data
        cmd = "".join([ph.getvalue(), ch.getvalue()])
        self.sendall(cmd)

        ptm_output_parser(self, args)

    #Get the status update
    def ptm_get_status (self, args, display=True):

        cmd_dict = collections.OrderedDict()
        cmd_dict['cmd'] = 'get-status'
        if (args.lldp):
            cmd_dict ['module'] = 'lldp'
        elif (args.bfd):
            cmd_dict ['module'] = 'bfd'

        if (args.detail):
            cmd_dict['detail'] = 'yes'

        ch = StringIO.StringIO()
        ch_writer = csv.DictWriter(ch, fieldnames=cmd_dict.keys(), lineterminator='\n')
        ch_writer.writeheader()
        ch_writer.writerow(cmd_dict)

        # create the ptm hdr
        ph = self.create_ptm_hdr(args, len(ch.getvalue()))

        # serialize
        # first ptm hdr, followed by cmd hdr, data
        cmd = "".join([ph.getvalue(), ch.getvalue()])
        self.sendall(cmd)

        ptm_output_parser(self, args, display)

parser = argparse.ArgumentParser(description='ptmctl arguments parser')

# add mutual exclusion
group = parser.add_mutually_exclusive_group()

group.add_argument('-l', '--lldp', help='print LLDP details', action='store_true')
group.add_argument('-b', '--bfd', help='print BFD details', action='store_true')
group.add_argument('--start_bfd_sess', action='store_true', help=argparse.SUPPRESS)
group.add_argument('--stop_bfd_sess', action='store_true', help=argparse.SUPPRESS)
group.add_argument('--bfd_clients', action='store_true', help='list BFD clients')
group.add_argument('--bfd_client_sess', action='store_true',
                    help='list BFD client sessions')
group.add_argument('--listen', action='store_true', help=argparse.SUPPRESS)
parser.add_argument('-d', '--detail', help='print details', action='store_true')
parser.add_argument('-j', '--json', help='json output', action='store_true')
parser.add_argument('--src', help=argparse.SUPPRESS)
parser.add_argument('--dst', help=argparse.SUPPRESS)
parser.add_argument('--multihop', action='store_true', help=argparse.SUPPRESS)
parser.add_argument('--ifname', help=argparse.SUPPRESS)
parser.add_argument('--vnid', help=argparse.SUPPRESS)
parser.add_argument('--minrx', help=argparse.SUPPRESS)
parser.add_argument('--mintx', help=argparse.SUPPRESS)
parser.add_argument('--detectmult', help=argparse.SUPPRESS)
parser.add_argument('--client', help=argparse.SUPPRESS)
parser.add_argument('--afi', help=argparse.SUPPRESS)
parser.add_argument('--sendEvent', help=argparse.SUPPRESS)
parser.add_argument('--seqid', default="1", help=argparse.SUPPRESS)
parser.add_argument('--ldmac', help=argparse.SUPPRESS)
parser.add_argument('--ldip', help=argparse.SUPPRESS)
parser.add_argument('--rdmac', help=argparse.SUPPRESS)
parser.add_argument('--rdip', help=argparse.SUPPRESS)
parser.add_argument('--dminrx', help=argparse.SUPPRESS)
parser.add_argument('--fwdifrx', help=argparse.SUPPRESS)
parser.add_argument('--cpdown', help=argparse.SUPPRESS)
parser.add_argument('--chktk', help=argparse.SUPPRESS)
parser.add_argument('--maxhopcnt', help=argparse.SUPPRESS)

args = parser.parse_args()

c = PtmClient()

if (args.start_bfd_sess or args.stop_bfd_sess):
    if (not args.dst):
      print("ERR: Destination/Peer IP not specified")
      sys.exit(-1)
    if (args.multihop and not args.src):
      print("ERR: Src IP mandatory for multihop")
      sys.exit(-1)
    if (not args.multihop and not args.ifname):
      print("ERR: Port name mandatory for singlehop")
      sys.exit(-1)
    try:
        dstip = ipaddr.IPAddress(args.dst)
        if (args.src):
            srcip = ipaddr.IPAddress(args.src)
    except ValueError as e:
        print e
        sys.exit(-1)
    if (args.src and (dstip.version != srcip.version)):
      print("ERR: Cannot mix-n-match ipv4/v6 addresses")
      sys.exit(-1)
    if (dstip.version == 6):
        if (dstip.is_link_local != srcip.is_link_local):
            print("ERR: Both Src and Dst IPv6 need to be link-local or global")
            sys.exit(-1)
        if ((dstip.is_link_local and srcip.is_link_local) and
            (args.multihop)):
            print("ERR: ipv6 link-local addr need to be single-hop")
            sys.exit(-1)
    c.ptm_send_bfd_cmd(args)
elif (args.bfd_clients):
    c.ptm_get_bfd_client(args)
elif (args.bfd_client_sess):
    c.ptm_get_bfd_client(args, sess=True)
elif (args.listen):
    c.ptm_listen_for_notifcations(args)
else :
    c.ptm_get_status(args)

c.close()

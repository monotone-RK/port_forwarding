#!/usr/bin/env python
# -*- coding: utf-8 -*-
#******************************************************************************/
# Port Forwarding Script Written in Python                          monotone-RK/
#                                               Ver:1.0 Last updated 2013.04.28/
#******************************************************************************/
import os
import re
import sys
import platform
import subprocess
from optparse import OptionParser

#** Options                                                                  **/
#******************************************************************************/  
optparser = OptionParser() 
optparser.add_option("-v","--version",action="store_true",dest="showversion",
                     default=False,help="show the version")
(options, args) = optparser.parse_args()

#** Usage                                                                    **/
#******************************************************************************/  
USAGE = """## Port Forwarding Script Written in Python
## DATE:2013.05.29
Usage: python pf.py [options] command port_type
(e.g. python pf.py open www.dyn)
command
  open   : open a new forwarding port
  close  : close specified forwarding port
  reopen : re-open specified forwarding port 
  list   : show list of all port forwardings
  status : show current status of opened port forwardings
  help   : show this page
port_type
  ssh : 22
  www : 80
  smb : 139
  all : all of ssh, www, smb
Options:
  -h, --help     show this help message and exit
  -v, --version  show the version"""

#** Determine the ssh's destination                                          **/
#******************************************************************************/  
INTERNAL = "username@internalserver"
EXTERNAL = "username@gatewayserver"
gatebase = EXTERNAL

if os.path.isfile("/etc/resolv.conf"):
    conf = open("/etc/resolv.conf", "r")
    for l in conf:
        # replace your remote domain name with 'internaldomain.foo.bar.jp'
        if re.search("domain\s+internaldomain.hogehoe.fugafuga.jp", l):
            gatebase = INTERNAL
    conf.close()
#** Loopback IP duplication for for SMB                                      **/
#******************************************************************************/  
ip_dup = {
    #"name":"sudo ifconfig eth0:0 local_IP localmask", 
    "smb0" :"sudo ifconfig lo0 alias 192.168.100.12  255.255.255.0"}

#** SMB                                                                      **/
#******************************************************************************/  
smb_ports = {
    #"name":"ssh -f -N -L local_IP:localport:remote_IP:remoteport GATE", 
    "smb0" :"ssh -f -N -L 192.168.100.12:8139:192.168.0.1:139 GATE"}

#** SSH                                                                      **/
#******************************************************************************/  
ssh_ports = {
    #"name":"ssh -f -N -L localport:remote_IP:remoteport GATE", 
    "ssh0" :"ssh -f -N -L 2212:192.168.0.2:22 GATE"}

#** WWW, IRC                                                                 **/
#******************************************************************************/  
www_ports = {
    # dynamic port forwarding with SOCKS
    "dyn"  :"ssh -f -N -D 10080 GATE",
    # staic port forwarding
    #"name":"ssh -f -N -L localport:remote_IP:remoteport GATE",
    "www"  :"ssh -f -N -L 8011:192.168.0.3:80 GATE"}

#** functions                                                                **/
#******************************************************************************/  
def showVersion():
    print "Port Forwarding Script Written in Python v1.0 last upated:2013.05.29"

def anyinclude(pl, value):
    ret = False
    for p in pl:
        if p.find(value) != -1:
            ret = True
    return ret

def rp(string):
    return re.sub(r"GATE", gatebase, string)

def dl(string):
    return re.sub(r"GATE", "", string)

#** process                                                                  **/
#******************************************************************************/  
if options.showversion:
    showVersion()
    sys.exit()

if len(args) == 0:
    print USAGE
    sys.exit()

if re.search("Windows", platform.system()):
    SSH = "ssh$"
else:
    SSH = "(ssh -f -N -L|D\s)"

command = args[0]
del args[0]

ps_list = [] 
IO = subprocess.Popen(["ps", "ax"], shell=False, stdout=subprocess.PIPE)
for io in IO.stdout.readlines():
    if re.search(SSH, io.strip()) and re.search("(\d+)", io.strip()):
        ps_list.append(io.strip())

# *----- add selected ports to dup_list and ports_list -----*
dup_list   = {}
ports_list = {}
if re.search("^open$", command) or re.search("^close$", command) or re.search("^reopen$", command) or re.search("^re$", command):
    for arg in args:
        # all ports
        if  re.search("^all$", arg):
            for key in sorted(ip_dup.keys()):
                if "smb."+key not in dup_list:
                    dup_list["smb."+key] = ip_dup[key]
            for key in sorted(ssh_ports.keys()):
                if "ssh."+key not in ports_list:
                    ports_list["ssh."+key] = ssh_ports[key]
            for key in sorted(smb_ports.keys()):
                if "smb."+key not in ports_list:
                    ports_list["smb."+key] = smb_ports[key]
            for key in sorted(www_ports.keys()):
                if "www."+key not in ports_list:
                    ports_list["www."+key] = www_ports[key]
        # ssh ports
        elif re.search("^ssh$", arg) or re.search("^ssh\.all$", arg):
            for key in sorted(ssh_ports.keys()):
                if "ssh."+key not in ports_list:
                    ports_list["ssh."+key] = ssh_ports[key]
        elif re.search("^ssh\.(.+)", arg):
            sshgrp1 = re.search("^ssh\.(.+)", arg).group(1)
            if sshgrp1 in ssh_ports:
                if "ssh."+sshgrp1 not in ports_list:
                    ports_list["ssh."+sshgrp1] = ssh_ports[sshgrp1]
            else: print "No such port forwarding rule: ssh."+sshgrp1
        # smb ports                   
        elif re.search("^smb$", arg) or re.search("^smb\.all$", arg):
            for key in sorted(ip_dup.keys()):
                if "smb."+key not in dup_list:
                    dup_list["smb."+key] = ip_dup[key]
            for key in sorted(smb_ports.keys()):
                if "smb."+key not in ports_list:
                    ports_list["smb."+key] = smb_ports[key]
        elif re.search("^smb\.(.+)", arg):
            smbgrp1 = re.search("^smb\.(.+)", arg).group(1)
            if smbgrp1 in ip_dup:
                if "smb."+smbgrp1 not in dup_list:
                    dup_list["smb."+smbgrp1] = ip_dup[smbgrp1]
            else: print "No such port forwarding rule: dup."+smbgrp1
            if smbgrp1 in smb_ports:
                if "smb."+smbgrp1 not in ports_list:
                    ports_list["smb."+smbgrp1] = smb_ports[smbgrp1]
            else: print "No such port forwarding rule: smb."+smbgrp1
        # www ports                   
        elif re.search("^www$", arg) or re.search("^www\.all$", arg):
            for key in sorted(www_ports.keys()):
                if "www."+key not in ports_list:
                    ports_list["www."+key] = www_ports[key]
        elif re.search("^www\.(.+)", arg):
            wwwgrp1 = re.search("^www\.(.+)", arg).group(1)
            if wwwgrp1 in www_ports:
                if "www."+wwwgrp1 not in ports_list:
                    ports_list["www."+wwwgrp1] = www_ports[wwwgrp1]
            else: print "No such port forwarding rule: www."+wwwgrp1
        # Selected ports are none
        else: print "No such port forwarding rule: "+arg 

# *----- commands processes -----*
if re.search("^open$", command): 
    include_flag = False
    delif_list = []
    for key, value in ports_list.iteritems():
        if anyinclude(ps_list, dl(value)):
            print "This port is already opened -> %s : %s" % (key, rp(value))
            include_flag = True
            delif_list.append(key)
    if include_flag:
        for key in delif_list:
            del ports_list[key]
    for value in sorted(dup_list.values()):
        os.system(rp(value))
    for value in sorted(ports_list.values()):
        os.system(rp(value))
elif re.search("^close$", command): 
    pf = []
    for value in sorted(ports_list.values()):
        for p in ps_list:
            if re.search(dl(value), p):
                pf.append(re.search("(\d+)", p).group(1))
    for ps in pf:
        os.system("kill -9 %s" % ps)
elif re.search("^reopen$", command) or re.search("^re$", command):
    noinclude_flag = False
    delif_list = []
    pf = []
    for key, value in ports_list.iteritems():
        if not anyinclude(ps_list, dl(value)):
            print "No such opened port: "+key
            noinclude_flag = True
            delif_list.append(key)
    if noinclude_flag:
        for key in delif_list:
            try:
                del ports_list[key]
                del dup_list[key]
            except KeyError:
                pass
    if len(ports_list) == 0 and len(dup_list) == 0:
        print "There are no selected ports"
        sys.exit()
    for value in sorted(ports_list.values()):
        for p in ps_list:
            if re.search(dl(value), p):
                pf.append(re.search("(\d+)", p).group(1))
    for value in sorted(dup_list.values()):
        for p in ps_list:
            if re.search(dl(value), p):
                pf.append(re.search("(\d+)", p).group(1))
    for ps in pf:
        os.system("kill -9 %s" % ps)
    if not len(dup_list) == 0:
        for value in sorted(dup_list.values()):
            os.system(rp(value))
    if not len(ports_list) == 0:
        for value in sorted(ports_list.values()):
            os.system(rp(value))
elif re.search("^list$", command) or re.search("^ls$", command):
    print "==========\/ port forwarding list \/=========="
    print "[ssh]"
    for key, value in ssh_ports.iteritems():
        print "ssh.%s : %s" % (key, rp(value))
    print "[smb]"
    for key, value in smb_ports.iteritems():
        print "smb.%s : %s" % (key, rp(value))
    print "[www]"
    for key, value in www_ports.iteritems():
        print "www.%s : %s" % (key, rp(value))
elif re.search("^status$", command) or re.search("^st$", command):
    print "==========\/ port forwarding status \/=========="
    print "[ssh]"
    for key, value in ssh_ports.iteritems():
        if anyinclude(ps_list, value):
            print "ssh.%s : %s" % (key, value)
        elif anyinclude(ps_list, dl(value)+INTERNAL):
            print "ssh.%s : %s" % (key, dl(value)+INTERNAL)
        elif anyinclude(ps_list, dl(value)+EXTERNAL):
            print "ssh.%s : %s" % (key, dl(value)+EXTERNAL)
    print "[smb]"
    for key, value in smb_ports.iteritems():
        if anyinclude(ps_list, value):
            print "smb.%s : %s" % (key, value)
        elif anyinclude(ps_list, dl(value)+INTERNAL):
            print "smb.%s : %s" % (key, dl(value)+INTERNAL)
        elif anyinclude(ps_list, dl(value)+EXTERNAL):
            print "smb.%s : %s" % (key, dl(value)+EXTERNAL)
    print "[www]"
    for key, value in www_ports.iteritems():
        if anyinclude(ps_list, value):
            print "www.%s : %s" % (key, value)
        elif anyinclude(ps_list, dl(value)+INTERNAL):
            print "www.%s : %s" % (key, dl(value)+INTERNAL)
        elif anyinclude(ps_list, dl(value)+EXTERNAL):
            print "www.%s : %s" % (key, dl(value)+EXTERNAL)
else: 
    print USAGE


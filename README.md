port_forwarding
===============
Port Forwarding Script Written in Python (version 2.x more than 2.6), refering to -> https://github.com/shtaxxx/portforwarding
DATE:2013.05.29

###Usage: 
python pf.py [options] command port_type
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

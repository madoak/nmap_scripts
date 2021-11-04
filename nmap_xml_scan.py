#/usr/bin/env python
#install requirements: pip install python-libnmap
#install requirements: pip install python-nmap
import datetime
import nmap
import json
from libnmap.parser import NmapParser
import sys
import time
def nmapScanssl(hosttoscan, porttoscan):
	nmScan = nmap.PortScanner()
	state = nmScan.scan(hosttoscan, porttoscan, '--script ssl-cert', '-Pn')
	print(state)
	with open(hosttoscan+'.txt', "a")as f:
		for key, value in state.items():
			f.write('%s: %s\n' % (key, value))
			f.write('\n')
	hosttoscan = ""
	porttoscan = ""
def nmapScancipher(hosttoscan, porttoscan):
	nmScan = nmap.PortScanner()
	state = nmScan.scan(hosttoscan, porttoscan, '--script ssl-enum-ciphers', '-Pn')
	print(state)
	with open(hosttoscan+'.txt', "a")as f:
		for key, value in state.items():
			f.write('%s: %s\n' % (key, value))
			f.write('\n')
	hosttoscan = ""
	porttoscan = ""
def nmapScan(hosttoscan, porttoscan):
	nmScan = nmap.PortScanner()
	state = nmScan.scan(hosttoscan, porttoscan, '-sV', '-Pn')
	print(state)
	with open(hosttoscan+'.txt', "a")as f:
		for key, value in state.items():
			f.write('%s: %s\n' % (key, value))
			f.write('\n')
	hosttoscan = ""
	porttoscan = ""
def nmapScanvuln(hosttoscan, porttoscan):
	nmScan = nmap.PortScanner()
	state = nmScan.scan(hosttoscan, porttoscan, '--script vuln', '-Pn')
	print(state)
	with open(hosttoscan+'.txt', "a")as f:
		for key, value in state.items():
			f.write('%s: %s\n' % (key, value))
			f.write('\n')
	hosttoscan = ""
	porttoscan = ""
start = time.time()
now = datetime.datetime.now()
print("Start date and time: ", now.strftime('%Y-%m-%d %H:%M:%S'))

nmap_report = NmapParser.parse_fromfile(sys.argv[1])
openports = []
opentcp = []
openudp = []
openhosts = []
openportprotoserviceversion = []
servicePort = []
servicePortNoBanner = []
servicePortCount = []
for h in nmap_report.hosts:
        for s in h.services:
                if s.state != "open|filtered":
                        openports.append(s.port)
                        openhosts.append(h.ipv4)
                        if s.protocol == "tcp":
                                opentcp.append(s.port)
                        else:
                                openudp.append(s.port)
                        hosttoscan = h.ipv4
                        porttoscan = str(s.port)
                        print ('To scan:',hosttoscan, porttoscan)
                        nmapScan(hosttoscan, porttoscan)
                        nmapScanssl(hosttoscan, porttoscan)
                        nmapScancipher(hosttoscan, porttoscan)
                        nmapScanvuln(hosttoscan, porttoscan)
                        hosttoscan ="" 
                        porttoscan =""
                        
                        
end = time.time()
print('Runtime:',format(end-start))

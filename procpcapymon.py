#!/usr/bin/python -u

#
#  Copyright 2015 Diana A. Vasile
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#


import logging
import binascii
import pcappy
import sys
import dpkt
import ctypes
import os
import webbrowser
from collections import OrderedDict,defaultdict
from multiprocessing import Process
from collections import deque
# ===================================


# TODO display top entries received rather than the last ones for the purpose of this demo


d= defaultdict(list)
associate = defaultdict(list)
# hardcoded value for mac address of router used
dac53mac = "0026f2010eb2"
macvendors = {}
ls = []

# by reading from nmap ma
def buildMacVendorsMap():
	macs=open('nmap-mac-prefixes','r')
	macs_lines=macs.readlines()
	for line in macs_lines:
		macvendors[line[0:6]] = line[7:].strip()

def sanitizeMac(mac):
 	temp = mac.replace(":", "").replace("-", "").replace(".", "").upper()
 	return temp[:2] + ":" + ":".join([temp[i] + temp[i+1] for i in range(2,12,2)])

def buildmesg():
	# number of cells per html page
	cells = 8
	f= open("display.html","w")	
	# uses only those devices who have consented to their data being displayed by connecting to dac53
#	array = list(set(associate[dac53mac][:]))
	# uses all of the sending devices
	array = ls[:]
	# prepend the array with placeholders so that we do not get out of bounds exceptions
	l = len(array)
	if l < cells:
		dif = cells-l
		for x in range(0,dif):
			array = [""] + array
	# the main html setup for the page before building the rest with the data
	mesg = """<html>
		<head>
			<meta http-equiv="refresh" content="10" >
			<style>
				table.style1 { 
					color: #333;
					font-family: Helvetica, Arial, sans-serif;
					margin-top:500px
					width: 440px; 
					border-collapse: collapse; border-spacing: 0;}
				
				table.style1 td, th { 
					border: 1px solid transparent; 
					height: 70px; 
					font-size: 40px;
					transition: all 0.3s;  
					}

				table.style1 th {
					background: #DFDFDF;  
					font-weight: bold;
					}

				table.style1 td {
					background: #FAFAFA;
					text-align: center;
					}
	
				table.style1 tr:nth-child(even) td { background:#FEFEFE; }   

				table.style1 tr:nth-child(odd) td { background: #F1F1F1; }  

				table.style1 tr td:hover { background: #666; color: #FFF; } /* Hover cell effect! */

			</style>
		</head>
		<body>
		<div align="center" >
		<table class="pure-table">
		<tr>
			<td><table class="style1"><tr><th>D8:BB:2C:66:E6:AF<br>Apple</th></tr><tr><td>LothianWIFI</td></tr><tr><td>Otopeni Airport</td></tr><tr><td>#WIFI@Changi</td></tr><tr><td>Furama BK 120</td></tr><tr><td>...</td></tr></table></td>
			<td>"""+prettify(array.pop())+"""</td>
			<td>"""+prettify(array.pop())+"""</td>
			<td>"""+prettify(array.pop())+"""</td>
		</tr>
		<tr>
			<td>"""+prettify(array.pop())+"""</td>
			<td>"""+prettify(array.pop())+"""</td>
			<td>"""+prettify(array.pop())+"""</td>
			<td>"""+prettify(array.pop())+"""</td>
		</tr>
		</table>
		</div>
		</body>
		</html>"""
	f.write(mesg)
	f.flush()
	f.close()

def prettify(key):

	if key == "":
		return ""

	# the number of lines displayed in each cell excluding the cell header (containing mac and vendor)
	maxDisplayLines = 5 

	# get the device's manufacturer by the mac prefix
	prefix = key[0:6].upper()
	vendor = ""
	try:
		vendor = macvendors[prefix]
	except KeyError:
		print "Vendor info not found for mac prefix " + prefix
		pass
	
	# build the html text
	thead = "<table class=\"style1\"><tr><th>"+sanitizeMac(key)+"<br>" + vendor +"</th></tr>"
	tbody = ""
	smac = set(d[key])
        count = 0
        for k in smac:
                if count == maxDisplayLines - 1:
			tbody = tbody + "<tr><td>...</td></tr>"
                        break
                count = count + 1
                tbody = tbody + "<tr><td>" + k + "</td></tr>"
	# include placeholder lines to match the max number of display lines
        if len(smac) < maxDisplayLines:
                dif = maxDisplayLines - len(smac)
                for x in range(0,dif):
                        tbody =tbody + "<tr><td/></tr>"
 	
	tbody = tbody + "</table>"
	return thead + tbody

# the main function
def proc():
	# prebuild a hashmap of the mac prefixes to vendors data.
	buildMacVendorsMap()
	global f
	
	# TODO use debug flag rather than comment out. 
	# use trace to find bugs
	# sys.settrace(utils.trace)
	logging.basicConfig(filename='example.log',level=logging.INFO)
	errbuf = None

	# start the pcap setup. including setting the errbuf, enabling rfmon and setting the buffer's size
	p = None
	p = pcappy.pcap_create("en0", errbuf)
	if(errbuf !=None):
		print "error: pcap_create failed"
		print errbuf
		f.close()
	if(pcappy.pcap_can_set_rfmon(p) != 0):	
		print "can set rfmon"
		if (pcappy.pcap_set_rfmon(p,1) == 0):
			print "activated rfmon"
		else:
			print "failed to activate rfmon"
			f.close()
			return
	pcappy.pcap_set_buffer_size(p,512)
	status = pcappy.pcap_activate(p)
	if status != 0:
		print "failed to activate pcap handler"
		f.close()
		return

	# start the pcap loop, 0 = infinitely (can specify a certain nb of values for a limited capture - 
	# this does not necessarily mean you'll get those results - i.e. 2000 captures might only get 20 
	# suitable messages), with the pcap handler processing function specified
	pcappy.pcap_loop(p,0,pcappy.pcap_handler(process),None)
	# when finished, close the pcap handler	
	pcappy.pcap_close(p)


def process(usr,hdr,data):
	try:
		buildmesg()
		raw_data = ctypes.string_at(data, 512)
		tap = dpkt.radiotap.Radiotap(raw_data)
		t_len=binascii.hexlify(raw_data[2:3])   
                t_len=int(t_len,16)                     #Convert to decimal
                wlan = dpkt.ieee80211.IEEE80211(raw_data[t_len:])
		msg_type = wlan.type
		msg_subtype = wlan.subtype
		if msg_type == 0:
			src_mac = binascii.hexlify(wlan.mgmt.src)
                	dst_mac = binascii.hexlify(wlan.mgmt.dst)
			if msg_subtype == 0x0 or msg_subtype == 0x02 or msg_subtype == 0x0b:
                        	print "Associate " + sanitizeMac(src_mac) + " to router " +  sanitizeMac(dst_mac)
				associate[dst_mac].append(src_mac)
			elif msg_subtype == 0x0a or msg_subtype == 0x0c:
				print "Disassociate " + sanitizeMac(src_mac) + " from router " +  sanitizeMac(dst_mac)
				associate[dst_mac].append(src_mac)
			elif msg_subtype == 4: #probe req
                		ssid = wlan.ies[0].info
				if ssid == None or ssid == "":
					return
				if ssid == "dac53":
					associate[dac53mac].append(src_mac)
				logging.info("mac is " + sanitizeMac(src_mac) +" and ssid is " + unicode(ssid))
				d[src_mac].append(ssid)
				if src_mac not in ls:
					ls.append(src_mac)

	except dpkt.dpkt.NeedData:
		print "empty raw data"
		pass
	except KeyError, e:
		print "Key error occurred"
		print e
		pass
	except UnicodeDecodeError:
		print "Decoding error"
		pass

if __name__ == '__main__':
	c = Process (target= proc)
	c.start()
	c.join()	
	

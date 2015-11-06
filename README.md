# WiFi-802.11-Demo-Sniffer
This 802.11 sniffer is written in Python provides a useful demo tool to raise awareness at the amount of data phones release into the wild for anyone to read.

It works by calling ./procpcapymon.py

It is an early, unrefined version and its processes need to be killed at the cmdline. 

It works by putting the laptop in monitor mode and recording all the 802.11 packets it observes. It then builds an html page: display.html, which contains a table of a few of the mac addresses with the manufacturer details and 4 SSIDs it has observed. 


TODOs:
- make it display the most useful top of devices, rather than the last observed
- add a debug flag in order to set up systracing; currently commented out in the code
- make it exit gracefully rather than a need for a process kill


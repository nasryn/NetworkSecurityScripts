========================
   DNS Activity Monitor
========================





INTRODUCTION
------------

This script works to parse DNS logs and creating a profile for a DNS intrusion detection system. You
will be need a pre-configured VMware Workstation virtual machine with dns proxy installed.



Setup
------------
Update /etc/resolv.conf file to look like:
    nameserver 127.0.0.1

This setting will make all of the program inside Debian_cns use your own server. In other words any DNS requests
made within this VM will be resolved and recorded in the logs by the DNS server located on the same VM.

*** If you run dhclient again it may update resolv.conf file. Make sure you restore the resolv.conf file after you
run dhclient.


You may also protect the resolv.conf from being changed by setting immutable flag with:
    chattr +i /etc/resolv.conf

The +i option (attribute) write protects /etc/resolv.conf file so that no one can modify it including root user.



If you want to remove immutable flag run
chattr -i /etc/resolv.conf


Install dns2proxy:

Navigate to ~/Development/mana/sslstrip-hsts/dns2proxy. You will find a python program dns2proxy.py.
Run python dns2proxy.py in a terminal. This will start your own DNS server. It will listen to every dns
request your system will make including dns requests from your browser.



Traces
The dns requests log file (dnslog.txt) can be found in dns2proxy.py current working directory. Generally it is the
same place where dns2proxy.py is located.


The dnslog.txt file will be the one analyzed. This file contains all the queries made to your server from various client programs
(e.g. iceweasel). As a result when you browse to some website all the dns request Iceweasel makes to render the
web page will be logged in dnslog.txt file. This will be the file that you will use as an input to your program.


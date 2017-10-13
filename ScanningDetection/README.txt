=================================
    Network Detection Scan
=================================


CONTENTS OF THIS FILE
---------------------

 * Introduction
 * Features
 * Implementation
 * Integration (with other modules)
 * Installation and configuration
 * Useful Resources
 * Troubleshooting (known Theme issues)
 * Developers: Extending the module
 * Future developments
 * Contributions are welcome!!
 * Credits / Contact
 * Link references


INTRODUCTION
------------

This Network Detection Scan allows users to parse tcpdump logfiles as well as
realtime scans. Using the characteristics described in the NMAP manual
(https://nmap.org/book/man.html), this program can detect three types of scans.



Detecting From Logfiles
-----------------------

First, a logfiles have been attached as tests:

 * sV, sV, F: single, and network

These log files contain example data in which the attacking VM (IP: 192.168.6.131)
scans for specific IPs (Meta: 192.168.6.1334) as well as whole
networks.



How Detection Is Decided
------------------------

According to the NMAP manual:

 * F (fast) scan: scans the 100 most common ports
 * sS (deep scan detection): scans 1000 ports
 * sV (service detection): like sS, but includes information about services

sV detection has priority. If each IP scan from the log is parsed, a list of options can be found.
By default, this list is two elements long; however, when services are scanned for, this list gets
longer. So, to detect an sV scan, we detect the length of this list.

sS detection has second priority. Unique ports scanned are kept accounted of. If they reach a count of 1000,
then sS detection has been determined.

F has final priority. This is detected when the number of unique ports scanned is 100.



IMPLEMENTATION
--------------


* * Logfiles * *

To scan for log files in the current directory, simply run the command:

            python scanproject.py

This will scan the current directory and write to a file in the current directory: results.txt.
This file will be overwritten each time it is run.


* * Realtime * *

To run a realtime scan on a monitoring system, run the following command:

            python scanproject.py --online

This will continuously scan. It will append each scan to the results.txt file.



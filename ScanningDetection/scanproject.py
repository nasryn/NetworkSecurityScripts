# Nasryn El-Hinnawi
# Computer Network Security
# Project 3 - Scanning Detection

import os
from datetime import datetime
import argparse
import subprocess as sub


def get_time_delta(current_time, previous_time):
    FMT = '%H:%M:%S.%f'
    return datetime.strptime(current_time, FMT) - datetime.strptime(previous_time, FMT)


def parse_lines(lines, realtime=False):
    scans = {}
    replies = []
    port_list_to_count = []
    check_sV = False
    sourceIP = None
    check_sS = False
    check_F = False
    printed_scan = ''
    printed_scans = []
    previous_time = None
    first_check = True
    first_check_sS = True
    times_list = []
    targetip_ports = dict()
    targetIPs = []

    for line in lines:

        components = line.replace(',', '').split()

        if not components:
            continue

        current_time = components[0]

        if all(x in components for x in ['Request', '(Broadcast)']):
            sourceIP = components[-3]
            targetIP = components[4]

            if targetIP not in targetIPs and current_time not in times_list:
                targetIPs.append(targetIP)
                if realtime:
                    print 'scanning from ' + sourceIP + 'at ' + current_time.rsplit('.', 1)[0]

            if sourceIP not in scans:
                scans[current_time] = sourceIP
                previous_time = current_time


            else:
                tdelta = get_time_delta(current_time, previous_time)
                if tdelta.seconds > 2:
                    scans[current_time] = sourceIP
                    replies = []
                    port_list_to_count = []
                    check_sV = False
                    check_sS = False
                    check_F = False
                    first_check = True
                    first_check_sS = True
                    targetip_ports = dict()


        if 'Reply' in line:
            targetIP = components[3]
            if targetIP not in replies:
                replies.append(targetIP)

        if all(x in components for x in ['IP', '[S]']):

            targetRaw = components[4].replace(':', '')
            targetIP, port = targetRaw.rsplit('.', 1)

            if targetIP not in targetip_ports:
                targetip_ports[targetIP] = [port]
            else:
                tmp_port = targetip_ports[targetIP]
                tmp_port.append(port)
                targetip_ports[targetIP] = list(set(tmp_port))

            port_list_to_count.append(targetRaw)
            start_check = components.index('options') + 1
            stop_check = components.index('length')

            length_dict = {key: len(value) for key, value in targetip_ports.items()}

            if first_check_sS and check_sS:
                check_sS = False
                first_check_sS = False

            if all(value == 1000 for value in length_dict.values()):

                check_sV = len(components[start_check:stop_check]) > 3
                check_sS = True and not check_sV

                if check_sS and not check_sV:
                   if previous_time not in times_list:
                       times_list.append(previous_time)
                       check_sS = False
                       continue

                if check_sV:
                    check_sS = False

                if check_sV or check_sS:
                    check_F = False

            if all(value == 100 for value in length_dict.values()):

                check_F = True if all(value == 100 for value in length_dict.values()) else False

                if first_check and check_F:
                    check_F = False
                    first_check = False

            if check_sV:
                printed_scan = '\tnmap -sV from ' + sourceIP + ' at ' + previous_time.rsplit('.', 1)[0] + '\n'
                times_list.append(previous_time)
                check_sV = False
                check_sS = False
                check_F = False


            elif check_sS:
                printed_scan = '\tnmap -sS from ' + sourceIP + ' at ' + previous_time.rsplit('.', 1)[0] + '\n'

                times_list.append(previous_time)

                check_sV = False
                check_sS = False
                check_F = False


            elif check_F:
                if previous_time not in times_list:
                    printed_scan = '\tnmap -F from ' + sourceIP + ' at ' + previous_time.rsplit('.', 1)[0] + '\n'
                else:
                    times_list.append(previous_time)
                check_sV = False
                check_sS = False
                check_F = False


            if printed_scan not in printed_scans:
                print printed_scan
                printed_scans.append(printed_scan)

                if realtime:
                    write(printed_scan)



    return printed_scans


def write(scan):
    results = open('results.txt', 'a')
    results.write(scan)
    results.close()

def get_log_files():
    return [f for f in os.listdir('TCPDump Examples') if (os.path.isfile(f) and f.split('.')[-1] == 'log')]


def main():
    online = argparse.ArgumentParser(description="Run analysis in real-time")
    online.add_argument('--online', action='store_true')
    args = online.parse_args()

    if os.path.isfile('results.txt'):
        os.remove('results.txt')

    if args.online:
        print("Running in real-time.")
        p = sub.Popen(('tcpdump', '-l', '-i', 'any', '-Q', 'in'), stdout=sub.PIPE)

        found = parse_lines(iter(p.stdout.readline, b''), realtime=True)


    else:
        files = get_log_files()

        for file in files:

            f = open(file, 'r')
            lines = f.readlines()
            write_file = str(file + '-->')
            write(write_file)
            print write_file
            found = parse_lines(lines)
            f.close()



    return 0

main()
# Nasryn El-Hinnawi
# Computer Network Security
# Project 2

from datetime import datetime

# 'Struct'-like data structure
class DNSLogs:
    time = datetime.min
    url = ''
    redirects = []
    uniqueCount = 0

# Read in text file
def ReadText(filename):
    with open(filename) as fp:
        Output = fp.readlines()
    return Output

# Write Text
def WriteText(filename, logs):
    with open(filename, 'w+') as ResultsFile:
        ResultsFile.write(logs)

# Creates one long string for each log
def formatLogToWrite(log):
    logToString = '\n' + log.url + ": " + str(log.uniqueCount) + " Time: " \
                    + log.time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + '\n'

    for redirect in log.redirects:
        logToString += '\t'
        logToString += redirect;
        logToString += '\n'

    return logToString

# Parse raw log file
def parseRawDNS(rawDnsLogs):

    dnsLogs = []
    oldDate = datetime.min
    newDate = None

    for i in range(len(rawDnsLogs)):

        # Want to keep datetime together
        dnsLine = rawDnsLogs[i].rsplit(None, len(rawDnsLogs[i].split()) - 2)
        newDate = datetime.strptime(dnsLine[0], "%Y-%m-%d %H:%M:%S.%f")
        url = dnsLine[6].rstrip('.')

        # Calculate time between requests
        deltaSeconds = (newDate - oldDate).total_seconds()

        oldDate = newDate

        # Create a new log when time lapsed is longer than 35 seconds
            # This probably could be shorter
        if deltaSeconds >= 35:
            tmpLog = DNSLogs()
            tmpLog.url = url
            tmpLog.time = newDate
            redirects = []
            continue

        # Appends only unique redirects
        if url not in redirects:
            redirects.append(url)

        tmpLog.redirects = redirects
        tmpLog.uniqueCount = len(redirects)

        if tmpLog not in dnsLogs:
            dnsLogs.append(tmpLog)

    return dnsLogs

def main():

    dnslog = ReadText("dnslog.txt")
    dnsLogsParsed = parseRawDNS(dnslog)
    logsToWrite = "".join([formatLogToWrite(log) for log in dnsLogsParsed])
    WriteText('dnslogs_report.txt', logsToWrite)

main()
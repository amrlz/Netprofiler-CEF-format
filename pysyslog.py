#!/usr/bin/env python
import socket
import logging
import socketserver
import sys
import getopt
import json
from collections import defaultdict
from cefevent import CEFEvent

## These are the defaults.
LOG_FILE = 'pysyslog.log'
BOUND_IP, PORT = "0.0.0.0", 8080 

def main(argv):
    """
    Main function to set up socket listener for supplied args
    """
    logfile = LOG_FILE
    boundip = BOUND_IP
    port = PORT
    try:
        opts, args = getopt.getopt(argv, "hl:p:i:", ["logfile=", "port=", "boundip="])
    except getopt.GetoptError:
        show_help()
    for opt, arg in opts:
        if opt == '-h':
            show_help()
            sys.exit()
        elif opt in ("-l", "--logfile"):
            logfile = arg
        elif opt in ("-p", "--port"):
            port = arg
        elif opt in ("-i", "--boundip"):
            boundip = arg
    print('       Writing to: {}'.format(logfile))
    print('     Listening on: {}'.format(port))
    print('         Bound to: {}'.format(boundip))
    print('Ignored Arguments: {}'.format(args))
    print('')
    print('Starting Server, press Ctrl+C to shutdown.')
    print('')

    logging.basicConfig(level=logging.INFO, format='', datefmt='',
                        filename=logfile, filemode='a')

    try:
        server = socketserver.UDPServer((boundip, port), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.1)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print("Crtl+C Pressed. Shutting down.")

def show_help():
    """
    Help message to display if bad arguments or help requested.
    """
    print('-------------------------------------------------------------------------------')
    print('Basic Usage: pysyslog.py')
    print('')
    print('Command line switches are optional. The following switches are recognized.')
    print(' -l <logfile>      -- Specify the log file to write to. Default is pysyslog.log')
    print(' -p <port>         -- Specify the port to listen on. Default is 514')
    print(' -i <boundip>      -- Specify the IP address to listen on. Default is 0.0.0.0')
    print('-------------------------------------------------------------------------------')
    sys.exit(2)


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """
    The actual core of the script, this listens on the socket.
    """

    def handle(self):
        l = []
        finalist = []
        li = defaultdict(list)
        try:
            data = bytes.decode(self.request[0].strip(), encoding="utf-8")
        except UnicodeError:
            data = 'unkown packet contents'

        # socket = self.request[1]
        if data[:5] == '<132>':
            #print(data)
            c = CEFEvent()
            data = data.split(']')
            data0 = data[0].split('[')
            data1 = data0[1].replace('" ','",')
            data1 = ''.join(data0[1].split(','))
            data1 = data1.split('" ')
            event_category = data1[0].split()[0]
            severity = data1[0].split('=')[1].replace('"','')
            for i in data1[1:]:
                i = i.replace('"','') 
                l.append(i)
            for i in l:
                param = i.split('=')
                li[param[0]].append(param[1])
            c.set_field('name',''.join(li.get('ALERT_TYPE')))
            c.set_field('deviceVendor', 'RiverbedTechnology,Inc.')
            c.set_field('deviceProduct', 'netrofiler-ve')
            c.set_field('deviceVersion', '10.19')
            c.set_field('signatureId', event_category)
            c.set_field('severity', severity)
            c.set_field('cs1', ''.join(li['PEAK_BYTES_IN']))
            c.set_field('cs1Label','PEAK_BYTES_IN')
            c.set_field('cs2', ''.join(li['PEAK_PACKETS_IN']))
            c.set_field('cs2Label','PEAK_PACKETS_IN')
            c.set_field('cs3', ''.join(li['PEAK_BYTES_IN']))
            c.set_field('cs3Label','PEAK_BYTES_OUT')
            c.set_field('cs4', ''.join(li['PEAK_PACKETS_OUT']))
            c.set_field('cs4Label','PEAK_PACKETS_OUT')
            c.set_field('shost',''.join(li['SOURCES']))
            c.set_field('start',''.join(li['EARLIEST_UTC']))
            c.set_field('end',''.join(li['LATEST_UTC']))
            #c.set_field('dhost',''.join(li.get('DESTINATIONS')))
            c.set_field('sourceTranslatedPort', ''.join(li['PORT']))
            c.set_field('dst', ''.join(li['TARGET_IP']))
            c.set_field('message', data[1])
            print(c.build_cef())
            #print(severity)
            #logging.info(c.build_cef())
            byte_message = bytes(c.build_cef(), "utf-8")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(byte_message, ('localhost', 8888))
            
        else:
            # Equal signs will be automatically escaped (and so will pipes (|) and backslashes (\\), as per the white paper specification)
            #print(data)
            data = data.split('] ')
            data2 = data[0].split('][')[1].split()[0]
            version = data[0].split('][')[0].split(']: ')[1].split()[4].split('=')[1].replace('"','')
            vendor = data[0].split('][')[0].split(']: ')[1].split()[3].split('=')[1].replace('"','')
            device_type = data[0].split('][')[0].split(']: ')[0].split()[3]
            data1 = ''.join(data[1])
            jsonstring = json.loads(data1) 
            
            c = CEFEvent()
            c.set_field('name', jsonstring['type'])
            c.set_field('deviceVendor', vendor)
            c.set_field('deviceProduct', device_type)
            c.set_field('deviceVersion', version)
            c.set_field('signatureId', data2)
            c.set_field('severity', jsonstring['alertlevel'])
            #c.set_field('severity', jsonstring['severity'])
            #c.set_field('message', data)
            #c.set_field('shost',jsonstring.get(['sources'])[0]['name']) 
            #c.set_field('dhost',jsonstring['destinations'][0]['name'])
            c.set_field('request', jsonstring['url'])
            c.set_field('start', jsonstring['start'])
            c.set_field('end', jsonstring.get('end'))
            c.set_field('sourceAddress', '10.65.170.112')
            c.set_field('sourcePort', 8080)
            c.set_field('proto', str(jsonstring.get('protocols_and_ports')).replace('[','').replace(']','').replace("'",'').split('/')[0])
            # Finally, generate the CEF line
            print(c.build_cef())
            print(version, vendor, device_type)
            #logging.info(c.build_cef())
            byte_message = bytes(c.build_cef(), "utf-8")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(byte_message, ('localhost', 8888))
if __name__ == "__main__":
    main(sys.argv[1:])


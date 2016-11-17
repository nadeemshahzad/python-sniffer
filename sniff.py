import socket
import struct
import binascii
import logging

class PacketSniffer:
     ''' Make a raw socket object '''
     def __init__(self):
           self.s=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x800))
     ''' This method headers from recieved packets and extract information 
         of Mac and IP address and ports '''
     def sniff(self):
           while True:
               p=self.s.recvfrom(2048)
               mac_add=p[0][0:14]
               ip_add=p[0][14:34]
               tcp_header=p[0][34:54]
               mac=struct.unpack("!6s6s2s",mac_add)
               ip=struct.unpack("12s4s4s",ip_add)
               tcp=struct.unpack("!HH9ss6s",tcp_header)
               pkt_header1="DestinationInfo. Mac=%s IP=%s Port=%s" % (binascii.hexlify(mac[0]),socket.inet_ntoa(ip[1]),tcp[0])
               pkt_header2="SourceInfo. Mac=%s IP=%s Port=%s" % (binascii.hexlify(mac[1]),socket.inet_ntoa(ip[2]),tcp[1])
               pkt_header=pkt_header1+" "+pkt_header2
               print "____________________________Packet Headers_______________________________"
               print pkt_header1
               print pkt_header2
               self.log_to_file(pkt_header)
     ''' Logs Packet headers to file'''      
     def log_to_file(self,h):
               logger=logging.getLogger('PythonSniffer')
               hdlr=logging.FileHandler('/tmp/PythonSniffer.log')
               frmt=logging.Formatter('%(asctime)s %(message)s')
               hdlr.setFormatter(frmt)
               logger.addHandler(hdlr)
               logger.setLevel(logging.DEBUG)
               logger.debug(h)
sniffer=PacketSniffer()
sniffer.sniff()

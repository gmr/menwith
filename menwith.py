#!/usr/bin/env python
'''
menwith - memcache command statistics

Requires libpcap and pylibpcap - Based upon the pylibpcap example code by davidma@eskimo.com - http://pylibpcap.sourceforge.net/

The name is a nod to the NSA's Menwith Hill listening station.
'''

import pcap
import sys
import string
import time
import socket
import struct
import binascii
from operator import itemgetter

protocols = {socket.IPPROTO_TCP:'tcp', socket.IPPROTO_UDP:'udp'}

commands = {'get': {},  'gets':{}, 'set': {}, 'incr': {}, 'decr': {},'delete': {},'append':{},'prepend':{}, 'cas':{}, 'replace':{},'stats': 0}
          
def decode_ip_packet(s):
  d={}
  d['version']=(ord(s[0]) & 0xf0) >> 4
  d['header_len']=ord(s[0]) & 0x0f
  d['tos']=ord(s[1])
  d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
  d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
  d['flags']=(ord(s[6]) & 0xe0) >> 5
  d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
  d['ttl']=ord(s[8])
  d['protocol']=ord(s[9])
  d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
  d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
  d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
  if d['header_len']>5:
    d['options']=s[20:4*(d['header_len']-5)]
  else:
    d['options']=None
  d['data']=s[4*d['header_len']:]
  return d

def dumphex(s):
  bytes = map(lambda x: '%.2x' % x, map(ord, s))
  for i in xrange(0,len(bytes)/16):
  	print binascii.b2a_hex(string.join(bytes[i*16:(i+1)*16]))
  
def process_packet(pktlen, data, timestamp):
  if not data:
    return

  if data[12:14]=='\x08\x00':
    decoded=decode_ip_packet(data[14:])
    bytes = map(lambda x: '%.2x' % x, map(ord, decoded['data']))
    d = [];
    for i in range(decoded['header_len'] + 27, len(bytes) - 2):
     	d.append('%c' % decoded['data'][i])
    if len(d) > 0:
      command_done = False
      command_string = ''.join(d)
      end = command_string.find(' ')
      if end == -1:
        command_name = command_string
        command_done = True
      else:
        command_name = command_string[0:end]
      
      if command_done is False:
        key_end = command_string.find(' ', end + 1);
        if key_end == -1:
          key = command_string[end + 1:]
          command_done = True
        else:
          key = command_string[end + 1:key_end]
      
      if commands.has_key(command_name):
        if command_name == 'stats':
          commands[command_name] += 1
        else:
          if commands[command_name].has_key(key):
            commands[command_name][key] += 1
          else:
            commands[command_name][key] = 1

if __name__=='__main__':

  if len(sys.argv) < 2:
    print 'usage: menwith <interface>'
    sys.exit(0)
  p = pcap.pcapObject()
  dev = sys.argv[1]
  net, mask = pcap.lookupnet(dev)
  p.open_live(dev, 1600, 0, 100)

  filter_string = 'dst port 11211'
  print 'Filter: %s' % filter_string
  print 'Processing data, press CTRL-C to exit and get data.'
  
  start_time = time.time()

  p.setfilter(filter_string, 0, 0)
  p.setnonblock(1)
  try:
    while 1:
      p.dispatch(1, process_packet)
      
  except KeyboardInterrupt:
    print '%d packets received, %d packets dropped, %d packets dropped by interface.' % p.stats()
    duration = time.time() - start_time;
    print 'Listened for %f seconds.' % duration
    
    for (command, data) in commands.items():
      if command == 'stats':
        if data > 0:
          print '\nstats requests: %i\n' % data
        
      else:
        if len(data.items()):
          print '\nTop 10 %s commands:\n' % command
          items = sorted(data.items(), key=itemgetter(1), reverse=True)
          x = 0
          for (key,value) in items:
            print ' %s: %i' % (key,value)
            x += 1
            if x == 10:
              break

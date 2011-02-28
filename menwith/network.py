"""
Main PCAP interface for listening on the NIC for data
"""
from socket import ntohs
from struct import unpack
from Queue import Queue

import memcache
import pcap

# Data buffers so we lose as little data as possible
raw_data_buffer = str()
tcp_data_buffer = str()

# Queue for popping decoded tcp data back to the memcache data aggregator
_data_queue = None

# We'll toggle this when we start processing and when stop_listening is called
_process_device = False


def tcp_packet_to_dict(packet_in):
    """
    Decode an inbound IP packet and build a dictionary of data points
    @TODO examine this function, make sure we're not losing data by
    not looking for the packet end. In addition figure out why packet['data']
    is including what I can only assume is the TCP header
    """    
    packet = dict()
    packet['version'] = (ord(packet_in[0]) & 0xf0) >> 4
    packet['header_len'] = ord(packet_in[0]) & 0x0f
    packet['tos'] = ord(packet_in[1])
    packet['total_len'] = ntohs(unpack('H', packet_in[2:4])[0])
    packet['id'] = ntohs(unpack('H', packet_in[4:6])[0])
    packet['flags'] = (ord(packet_in[6]) & 0xe0) >> 5
    packet['fragment_offset'] = ntohs(unpack('H', packet_in[6:8])[0] & 0x1f)
    packet['ttl'] = ord(packet_in[8])
    packet['protocol'] = ord(packet_in[9])
    packet['checksum'] = ntohs(unpack('H', packet_in[10:12])[0])
    packet['source_address'] = pcap.ntoa(unpack('i', packet_in[12:16])[0])
    packet['destination_address'] = pcap.ntoa(unpack('i', packet_in[16:20])[0])
    
    # If our header size is more than 5 bytes, we have options
    if packet['header_len'] > 5:
        packet['options'] = packet_in[20:4 * (packet['header_len'] - 5)]
    else:
        packet['options'] = None
        
    # Append the rest of the packet data to our data element
    packet['data'] = packet_in[4 * packet['header_len']:]
    
    # Return the packet and how much data we have used of it
    return packet, len(packet_in)


def process_raw_data(data_in):
    """
    Take raw socket data and look for full ip packets, dispatching them to
    the handler when received
    """
    global raw_data_buffer, tcp_data_buffer
    
    # Append our raw_data_buffer with our new data
    raw_data_buffer += data_in
    
    # Make sure we have enough data to build a packet
    if len(raw_data_buffer) < 15:
        
        # We don't so loop knowing our module level buffer is filled
        return
    
    # Make sure with have an IP packet before continuing
    if raw_data_buffer[12:14] == '\x08\x00':
        
        # Get a packet from our data, ignoring the IP header
        packet_data, bytes_removed = tcp_packet_to_dict(raw_data_buffer[14:])

        # Update our raw data global buffer
        raw_data_buffer = str()

        # Decode the packet data into hex values
        hex_bytes = map(lambda x: '%.2x' % x, map(ord, packet_data['data']))

        # Decode the hex bytes into a parable string via a list intermediary
        data = list();

        # Start at the offset of the TCP header, ignoring the last 2 bytes
        # However this doesn't make sense since our previous function is
        # Supposed to not be returning the header in the data payload
        # @TODO figure that part out
        for x in range(decoded['header_len'] + 27, len(hex_bytes) - 2):
            data.append('%c' % decoded['data'][x])

        # Append our tcp data buffer
        tcp_data_buffer += ''.join(data)
        
        # Attempt to process our tcp data buffer
        remove_len = menwith.memcache.parse_raw_data(tcp_data_buffer)
        
        # Remove the processed data from our buffer
        tcp_data_buffer = tcp_buffer_data[remove_len:]


def stop_listening():
    """
    Causes the blocking listen call to stop
    """
    global _process_device
    
    # If we called _process_device without listening assert it
    if not _process_device:
        assert False, "Device is not processing"
    
    # Toggle the bool looped on in the listen method
    _process_device = False
    

def listen(device, port=11211, queue=None):
    """
    Pass in a local device and port to listen on to grab packets for decoding
    """
    global _process_device, _data_queue
    
    # Make sure we're not processing already, prevent multi-threaded use
    if _process_devide:
        raise Exception("Can not process more than one device at a time")
    
    # Assign our data queue
    _data_queue = queue
    
    # @TODO Lookup the purpose of the command and return values
    net, mask = pcap.lookupnet(device)

    # Create our PCAP object for parsing packets    
    p = pcap.pcapObject()
    
    # @TODO Look up these parameters and their meaning
    p.open_live(dev, 1600, 0, 100)

    # Create our pcap filter looking for ip packets for the memcached server
    p.setfilter('dst port %i' % port, 0, 0)

    # Set our operation to non-blocking
    p.setnonblock(True)

    # Toggle our flag that we're actively processing
    _process_device = True

    # Loop until stop_listening is called
    while _process_device:
    
      # When we receive data from pcap, process it
      p.dispatch(1, process_raw_data)

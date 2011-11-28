"""
Main PCAP interface for listening on the NIC for data

"""
import logging
import pcap
from socket import ntohs, IPPROTO_TCP, IPPROTO_UDP
import struct

from . import memcache

# Ethernet constants
_ETHERTYPE_IPV4 = '\x08\x00'

# IPv4 Constants
_IPV4_BASE_HEADER_SIZE = 20 # Default IPv4 header size
_IPV4_OPTIONS_OFFSET = 20  # Bit 160

# TCP Constants
_TCP_BASE_HEADER_SIZE = 24

# Port we want to use by default
_MEMCACHED_PORT = 11211

# How many bytes to read
_SNAPSHOT_LENGTH = 65535

# Doesn't do anything in Linux
_TIMEOUT = 100


class TCPCapture(object):

    def __init__(self, queue, device, port=_MEMCACHED_PORT):
        """Create a new TCPCapture object for the given device and port.

        :param Queue queue: The cross-thread queue to create
        :param str device: The device name (eth0, en1, etc)
        :param int port: The port to listen on
        :raises: ValueError

        """
        self._logger = logging.getLogger('menwith.network.TCPCapture')
        self._logger.debug('Setup with queue: %r', queue)
        self._queue = queue
        self._running = False

        # Create the PCAP object
        self._pcap = self._setup_libpcap(device, port)

    def _char_conversion(self, value):
        """Convert the bytes to a character returning the converted string.

        :param str value: The string to convert
        :returns: str

        """
        return ''.join(['%c' % byte for byte in value])

    def _ethernet_decode(self, packet_in):
        """Extract the ethernet header, returning the ethernet header and
        the remaining parts of the packet.

        :param str packet_in: The full packet
        :returns: tuple

        """
        return (self._format_bytes(packet_in[0:6], ':'),
                self._format_bytes(packet_in[6:12], ':'),
                packet_in[12:14],
                packet_in[14:])

    def _format_bytes(self, value, delimiter=''):
        """Format a byte string returning the formatted value with the
        specified delimiter.

        :param str value: The byte string
        :param str delimiter: The optional delimiter
        :returns: str

        """
        return delimiter.join(['%0.2x' % ord(byte) for byte in value])

    def _ipv4_decode(self, packet_in):
        """Extract the IP header and populate a dictionary of values, returning
        a the dictionary and the remaining data to extract.

        :param str packet_in: The IP packet data
        :returns: tuple

        """
        out = {'version': struct.unpack('b', packet_in[0])[0] >> 4,
               'ihl': (struct.unpack('b', packet_in[0])[0] & 0x0F) * 4,
               'total_length': ntohs(struct.unpack('H', packet_in[2:4])[0]),
               'identification': ntohs(struct.unpack('H', packet_in[4:6])[0]),
               'flags': (ord(packet_in[6]) & 0xe0) >> 5,
               'fragment_offset': (ntohs(struct.unpack('H',
                                                       packet_in[6:8])[0]) &
                                   0x1f),
               'ttl': ord(packet_in[8]),
               'protocol': ord(packet_in[9]),
               'checksum': ntohs(struct.unpack('H', packet_in[10:12])[0]),
               'source': pcap.ntoa(struct.unpack('i', packet_in[12:16])[0]),
               'destination': pcap.ntoa(struct.unpack('i',
                                                      packet_in[16:20])[0])}

        # If our header size is more than 5 bytes, we have options
        if out['ihl'] > _IPV4_BASE_HEADER_SIZE:
            out['options'] = packet_in[_IPV4_BASE_HEADER_SIZE:out['ihl']]
        else:
            out['options'] = None

        # Return the decoded packet
        return out, packet_in[out['ihl']:]

    def _process_packet(self, packet_length, packet_in, timestamp):
        """Called by libpcap's dispatch call, we receive raw data that needs
        to be decoded then appended to the tcp buffer. When a full IP packet
        is received, construct the TCP header dictionary.

        :param int packet_length: The length of the packet received
        :param str packet_in: The packet to be processed
        :param float timestamp: The timestamp the packet was received

        """
        # Extract the parts of the packet
        dest, source, ethertype, payload = self._ethernet_decode(packet_in)
        self._logger.debug(('Destination MAC Address: %s '
                            'Source MAC Address: %s'), dest, source)

        # If we have an IPv4 ethertype, process it
        if ethertype == _ETHERTYPE_IPV4:

            # Process the IPv4 Header
            ipv4_header, ipv4_payload = self._ipv4_decode(payload)

            # Log the IPv4 Header values
            self._logger.debug('IPv4 Header: %r', ipv4_header)

            # Determine how to decode
            if ipv4_header['protocol'] == IPPROTO_TCP:

                # Decode the TCP Header
                tcp_header, tcp_payload = self._tcp_decode(ipv4_payload)

                # Log the TCP Header values
                self._logger.debug('TCP Header: %r', tcp_header)

                # Add the TCP data to the Queue for decoding
                if tcp_payload:
                    self._queue.put(tcp_payload)

    def _setup_libpcap(self, device, port):
        """Setup the pcap object and return the handle for it.

        :returns: pcap.pcapObject

        """
        # Validate the device
        if not self._validate_device(device):
            raise ValueError('Can not validate the device: %s' % device)

        # Create the pcap object
        pcap_object = pcap.pcapObject()

        # Open the device in promiscuous mode
        try:
            pcap_object.open_live(device, _SNAPSHOT_LENGTH, True, _TIMEOUT)
            self._logger.info('Opened %s', device)
        except Exception as error:
            raise OSError('Permission error opening device %s' % error)

        # Set our filter up
        filter = 'dst port %i' % port

        # Create our pcap filter looking for ip packets for the memcached server
        pcap_object.setfilter(filter, 1, 0)
        self._logger.info('Filter set to: %s', filter)

        # Set our operation to non-blocking
        pcap_object.setnonblock(1)

        # Return the handle to the pcap object
        return pcap_object

    def _tcp_decode(self, packet_in):
        """Extract the TCP header and populate a dictionary of values, returning
        a the dictionary and the remaining data to extract.

        :param str packet_in: The TCP packet data
        :returns: tuple

        """
        self._logger.debug('TCP Packet: %r', packet_in)
        out = {'source_port': ntohs(struct.unpack('H', packet_in[0:2])[0]),
               'dest_port': ntohs(struct.unpack('H', packet_in[2:4])[0]),
               'data_offset': struct.unpack('B', packet_in[12])[0] >> 4}
        return out, self._char_conversion(packet_in[(_TCP_BASE_HEADER_SIZE +
                                                     out['data_offset']):])

    def _validate_device(self, device_name):
        """Validate the given device name as being available to the application.
        While this is more hoops than just pcap.lookupdev, we can get a full
        list of ip addresses we're listening for from this method.

        :param str device_name: The device name to validate
        :returns: Bool

        """
        # Get all the devices available
        devices = pcap.findalldevs()

        # Iterate through the devices looking for the one we care about
        for device in devices:

            # Is this the droid, err device we are looking for?
            if device[0] == device_name:
                self._logger.debug('Validated device %s', device_name)

                # Output ip addresses if there are any
                if device[2]:
                    ip_addresses = list()
                    for address_info in device[2]:
                        ip_addresses.append(address_info[0])
                    self._logger.info('IP addresses to listen on: %r',
                                      ip_addresses)

                # Device validates
                return True

        # It was not found
        return False

    def process(self):
        """Start processing packets, dispatching received packets to the
        TCPCapture._process_raw_data method.

        Will loop as long as self._running is True

        """
        # We want to process
        self._running = True

        # Iterate as long as we're processing
        while self._running:

            # Dispatch the reading of packets, as many as we can get
            self._pcap.dispatch(1, self._process_packet)

    def stop(self):
        """Causes the blocking listen call to stop."""
        # Toggle the bool looped on in the listen method
        self._running = False

        # Log that the processing has been told to stop
        self._logger.info('Indicated that processing of packets should stop')

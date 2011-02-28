"""
Defines behaviors for decoding Memcached Protocols
"""

COMMANDS = ('append', 'car', 'decr', 'delete', 'get', 'gets', 'incr', 
            'prepend','replace', 'set', 'stats')


  
def parse_raw_data(packet_in):
    """
    Examines the packet_in to determine if it's a text or binary protocol packet_in    
    """
    
    return data_processed_length
    
def parse_ascii_packet(packet_in):
    """
    Parses the inbound packet, looking for valid ASCII memcache commands and data
    """
    pass
    
def parse_binary_packet(packet_in):
    """
    Parses the inbound packet, looking for valid binary memcache commands and data
    """
    

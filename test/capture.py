__author__ = 'gmr'

import Queue
import sys
sys.path.insert(0, '..')

from menwith import network

def tcp_capture_test():

    queue = Queue.Queue()
    tcp_capture = network.TCPCapture(queue, 'en0', 11211)
    tcp_capture.process()


if __name__ == '__main__':
    import logging

    logging.basicConfig(level=logging.DEBUG)
    tcp_capture_test()


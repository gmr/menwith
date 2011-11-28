"""
Controls execution, management of application
"""
import logging
import signal
import threading
import time

from Queue import Queue

# Menwith modules
import ui

threads = list()


class Capture(threading.Thread):
    """Thread that manages the TCPCapture instance"""
    def run(self):
        # Scope this here so we have prettier errors in initialization
        from . import network

        self._tcp_capture = network.TCPCapture(self.queue,
                                               self.options.device,
                                               self.options.port)
        self._tcp_capture.process()

    def stop_process(self):

        self._tcp_capture.stop()


class Decode(threading.Thread):
    """Thread that manages the memcached protocol decoder instance"""
    def run(self):
        # Scope this here so we have prettier errors in initialization
        from . import memcache

        self._decoder = memcache.Decoder(self.queue)
        self._decoder.process()

    def stop_process(self):
        self._decoder.stop()

    def values(self):
        return self._decoder.counts, self._decoder.keys

def signal_handler(frame, signum, action):
    """
    Signal handler will stop the processor which will in turn
    stop everything else when it dies
    """
    if signal in [signal.SIGTERM]:
        for thread in threading.enumerate():
            thread.stop_process()


def start(options):

    signal.signal(signal.SIGTERM, signal_handler)

    # Create a queue to share data
    _data_queue = Queue()

    # Start the memcached protocol decoder
    decoder = Decode()
    decoder.options = options
    decoder.queue = _data_queue
    decoder.start()

    # Start our user interface if we're in interactive mode
    if options.interactive:

        # Pick which type of interface we will use
        if options.window:
            interface = ui.wxWindows()
        else:
            interface = ui.Curses()

        # Start the interface thread
        interface.options = options
        interface.start()

    # Kick off the network data capture thread
    capture = Capture()
    capture.options = options
    capture.queue = _data_queue
    capture.start()

    # Loop as long as our processor is alive
    while capture.is_alive() and decoder.is_alive():
        try:
            time.sleep(.5)
        except KeyboardInterrupt:
            capture.stop_process()
            decoder.stop_process()

    # If we're running interactively shut everything down and exit
    if options.interactive:
        interface.stop()
        return

    # Gather the data from the decoder
    counts, keys = decoder.values()

    print counts
    print keys

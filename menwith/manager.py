"""
Controls execution, management of application
"""
import os
import signal
import threading
import time

from Queue import Queue

# Menwith modules
import ui

# Empty values for our threads
aggregator, interface, processor = None, None, None

# Queue for sharing data across threads
_data_queue = None

class Aggregator(threading.Thread):

    def run(self):
        # We'll use this to carry all of the data found in DataProcessor, using Queues to pull the data in
        print self.options
        print self.queue
    

    def stop(self):
        pass
        

class Processor(threading.Thread):

    def run(self):

        # Scope this here so we have prettier errors in initialization
        import network

        # Start our network listener
        network.listen(self.options.device, self.options.port, self.queue)
    
    def stop(self):
        #network.stop_listening()
        pass


def signal_handler(frame, signum, action):
    """
    Signal handler will stop the processor which will in turn 
    stop everything else when it dies
    """
    if signal in [signal.SIGTERM]:
        processor.stop_listening()


def start(options):

    global aggregator, interface, processor, _data_queue

    signal.signal(signal.SIGTERM, signal_handler)

    # Create a queue to share data
    _data_queue = Queue()

    # Start the data aggregator thread
    aggregator = Aggregator()
    aggregator.options = options
    aggregator.queue = _data_queue
    aggregator.start()
    
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

    # Kick off the data processor thread
    processor = Processor()
    processor.options = options
    processor.queue = _data_queue
    processor.start()

    # Loop as long as our processor is alive    
    while processor.is_alive():
        time.sleep(.5)
        
    # If we're running interactively shut everything down and exit
    if options.interactive:
        interface.stop()
        aggregator.stop()
        return
    
    # Gather the data from the aggregator
    
    # Report on the data from the aggregator

    
    
    
            
        
        
    

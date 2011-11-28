__author__ = 'gmr'

import logging
import optparse
import signal

from . import manager
from . import __version__

OUTPUT_FORMATS = ['formatted', 'csv', 'xsl']
REQUIRES_FILE_OUTPUT = ['csv', 'xls']
parser = None

def _check_values(values, args):

    error = False

    # Piggyback checking of needed modules here
    try:
        import pcap
    except ImportError:
        error = ('Could not import pcap, please check your libpcap and python '
                 'pcap library install.')

    # Make sure they specified a mode
    if not values.interactive and not values.gather:
        error = 'You must select either interactive or gather mode.'

    # Make sure they've not specified interactive AND gather mode
    if values.interactive and values.gather:
        error = 'You can not select both interactive and tether mode.'

    # If they specified an output format, make sure they specify a file
    if values.gather:

        # If the specified an output format and no file
        if not values.file and values.output in REQUIRES_FILE_OUTPUT:
            error = 'You must specify a file when using csv or xsl output.'

        if values.window:
            error = 'You can only use WX view in interactive mode'

    elif values.interactive:

        if values.window:
            try:
                import wx
            except ImportError:
                error = 'Windowed interactive mode specified but wxWidgets \
is not installed, please install wxWidgets.'

        else:
            try:
                import curses
            except ImportError:
                error = 'Could not start interactive mode as curses could \
not be loaded. Please install curses.'

    if error:
        parser.error(error)

    return values, args

def _options():
    """Setup and process the command line options"""
    global parser

    # Set our various display values for our Option Parser
    usage = 'usage: %prog [values]'
    version = '%%prog %s' % __version__
    description = 'Listen on a network device analyzing memcached traffic'

    # Create our parser and setup our command line values
    parser = optparse.OptionParser(usage=usage,
                                   version=version,
                                   description=description)

    # Monkey patch in our check_values function
    parser.check_values = _check_values

    # Setup our command line values
    parser.add_option('--device', '-d',
                      default='eth0',
                      help='Local device to listen on for memcached traffic\n\
                            Default: eth0')

    parser.add_option('--port', '-p',
                      default=11211,
                      type="int",
                      help='Specify the port memcached is running on\n\
                            Default: 11211')

    parser.add_option('--interactive', '-i',
                      action='store_true',
                      default=False,
                      help='Utilize in interactive full screen mode')

    parser.add_option('--gather', '-g',
                      action='store_true',
                      default=False,
                      help='Gather data and report findings non-interactively')

    parser.add_option('--timeout', '-t',
                      default=60,
                      type='int',
                      help='Duration in seconds to listen in gather mode\n\
                            Default: 60')

    parser.add_option('--output', '-o',
                      default='formatted',
                      type='choice',
                      choices=OUTPUT_FORMATS,
                      help='Output format for gather mode\n\
                            Default: formatted\n\
                            values: formatted, csv, xsl')

    parser.add_option('--file', '-f',
                      help='File to write output to when using gather mode')

    parser.add_option('--replay', '-r',
                      help='Replay a tcpdump file instead of listening on a\
                            network device. Note that the -d and -t values\
                            are ignored when replying a tcpdump file.')

    parser.add_option('--window', '-w',
                      action='store_true',
                      default=False,
                      help='Use wx instead of curses for interactive mode')

    parser.add_option('--verbose', '-v',
                      default=False,
                      action='store_true',
                      help='Verbose output mode')

    # Return the validated values and arguments
    return parser.parse_args()

def main():

    # Get the options
    options, args = _options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Run the application
    try:
        manager.start(options)
    except KeyboardInterrupt:
        manager.signal_handler(None, signal.SIGTERM, None)

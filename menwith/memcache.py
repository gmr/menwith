"""
Defines behaviors for decoding Memcached Protocols
"""
import logging
import Queue
import re

_KEY_FORMAT = '([a-z0-9\:\-\_\.\!\?\@\#\$\%\^\&\*\(\)\=\+\~\`\;\"\'\<\>\,\/]*)'

_PATTERNS = {'get': re.compile('get %s\r\n' % _KEY_FORMAT),
             'stats': re.compile('stats\r\n')
            }

_QUEUE_GET_TIMEOUT = 1


class Decoder(object):
    """Takes raw data from the TCP packet and attempts to decode it against
    the memcached protocol and increment counters as appropriate.

    """
    def __init__(self, queue):
        """Create a new Decoder object.

        :param Queue.Queue queue: The queue that will have the TCP payload

        """
        self._logger = logging.getLogger('menwith.memcache.Decoder')
        self._logger.debug('Setup with queue: %r', queue)
        self._queue = queue
        self._running = False
        self._counts = self._setup_counter()
        self._keys = dict()

    def _count_key_use(self, key):
        """Append the key to the key count if it doesn't exist and then
        increment the counter.

        :param str key: The key to append
        """
        if key not in self._keys:
            self._keys[key] = 0
        self._keys[key] += 1
        self._logger.debug('Key %s incremented to %i', key, self._keys[key])

    def _setup_counter(self):
        """Create a counter object with a default value of 0 for all supported
        commands.

        :returns: dict

        """
        counter = dict()
        for key in _PATTERNS:
            counter[key] = 0
        return counter

    def _process_payload(self, data):
        """Process a TCP payload looking for data to match the expected
        patterns.

        :param str data: The data to process.

        """
        for command in _PATTERNS:
            response = _PATTERNS[command].match(data)
            if response:
                self._counts[command] += 1
                self._logger.debug('Incremented %s command count', command)
                data = response.groups()
                if data:
                    self._count_key_use(data[0])
                break

    @property
    def counts(self):
        """Return the value of the counts dictionary.

        :returns: dict

        """
        return self._counts.copy()

    @property
    def keys(self):
        """Return the value of the keys dictionary.

        :returns dict

        """
        return self._keys

    def process(self):
        """Blocking method to process packets as they come in to be decoded.
        Will exit when we are no longer running.

        """
        # Set the runtime state
        self._running = True

        # Loop while we are running
        while self._running:

            try:
                tcp_payload = self._queue.get(timeout=_QUEUE_GET_TIMEOUT)
            except Queue.Empty:
                continue

            # Process the tcp_payload
            self._process_payload(tcp_payload)

        # We're done
        self._logger.debug('Exiting process')

    def stop(self):
        """Causes the blocking listen call to stop."""
        # Toggle the bool looped on in the listen method
        self._running = False

        # Log that the processing has been told to stop
        self._logger.info('Indicated that processing of packets should stop')

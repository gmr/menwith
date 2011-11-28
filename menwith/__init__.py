"""
Menwith main import / handler

Menwith listens to memcached traffic to determine current behaviors
such as top commands and keys utilized. It, in addition, can determine
the average key size and data size across all traffic snapshots.

"""

__version__ = '2.0p0'

import cli
import manager
import memcache
import network
import ui

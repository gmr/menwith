#!/usr/bin/env python
from setuptools import setup

setup(name='menwith',
      version='2.0p0',
      description='memcached usage monitoring tool',
      maintainer='Gavin M. Roy',
      maintainer_email='gmr@myyearbook.com',
      url='http://github.com/gmr/menwith',
      packages = ['menwith'],
      install_requires = ['pylibpcap>=0.6.2'],
      entry_points=dict(console_scripts=['menwith=menwith.cli:main']),
      zip_safe=True)

#!/usr/bin/env python
# Copyright (c) 2014, Grok
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os

from setuptools import find_packages, setup, Command

def read(*paths):
  """Build a file path from *paths* and return the contents."""
  with open(os.path.join(*paths), 'r') as f:
    return f.read()

sdict = {}

execfile('agamotto/version.py', {}, sdict)

setup(
  name='agamotto',
  version=sdict['version'],
  description='Agamotto is a module that provides helper functions for testing the configuration of a running server',
  long_description=read('README.rst'),
  author='Joe Block',
  author_email='jpb@numenta.com',
  keywords=['server testing'],
  license='Apache',
  url='http://github.com/groksolutions/agamotto',
  download_url='https://github.com/GrokSolutions/agamotto/archive/%s.tar.gz' % (sdict['version'], ),
  install_requires=['requests', 'unittest2'],
  test_suite='tests.unit',
  packages=find_packages(exclude=['tests*']),
  include_package_data=True,
  classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: Apache Software License',
    'Natural Language :: English',
    'Operating System :: OS Independent',
    'Programming Language :: Python'
  ],
)

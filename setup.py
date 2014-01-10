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

try:
  from setuptools import setup, Command
except ImportError:
  from distutils.core import setup, Command

class PyTest(Command):
  user_options = []
  def initialize_options(self):
    pass
  def finalize_options(self):
    pass
  def run(self):
    import subprocess
    errno = subprocess.call(['py.test'])
    raise SystemExit(errno)

sdict = {}

execfile('agamotto/version.py', {}, sdict)

sdict.update({
  'name' : 'agamotto',
  'description' :
    'Agamotto is a module that provides helper functions for testing the configuration of a running server',
  'url': 'http://github.com/groksolutions/agamotto',
  'download_url' :
    'https://github.com/GrokSolutions/agamotto/archive/%s.tar.gz' % (
      sdict['version'],),
  'author' : 'Joe Block',
  'author_email' : 'jpb@groksolutions.com',
  'keywords' : ['server testing'],
  'license' : 'Apache',
  'install_requires': [
    'requests',
    'unittest2'],
  'test_suite': 'tests.unit',
  'packages' : ['agamotto'],
  'classifiers' : [
    'Development Status :: 1 - Planning',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: Apache Software License',
    'Natural Language :: English',
    'Operating System :: OS Independent',
    'Programming Language :: Python'],
  'zip_safe' : False,
  'cmdclass' : {'test': PyTest},
})

setup(**sdict)

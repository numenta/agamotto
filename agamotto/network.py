# Copyright 2014 Numenta
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
import socket


def isPortOpen(host, port):
  """See if host is accepting connections on port. Note that it does no
     protocol checking, just checks that it can make a connection."""
  s = socket.socket()
  try:
    s.connect((host, port))
    return True
  except socket.error:
    return False


def isListening(port):
  """Confirm localhost is accepting connections on port"""
  return isPortOpen('localhost', port)


def probePort(matchtext, host='127.0.0.1', port=80, command=None):
  """
  Connect to port on host, send an optional command, then return the response.

  Usage:
    self.assertTrue(agamotto.network.probePort(host='localhost',
                    matchtext='<title>', port=80,
                    command="GET / HTTP/1.1\nHost: localhost\n\n"),
                    'Did not see a title in https result')
  """
  s = socket.socket()
  s.connect((host, port))
  if command:
    s.send(command)
  rawData = s.recv(1024)
  s.close()
  return matchtext in rawData


def checkHttp(matchtext, url='http://localhost', verifyCertificate=False):
  """
  Connect to an http(s) socket, send a path, return the content returned by
  the other end. If you're using not using a self-signed certificate, set
  verifyCertificate to True and we will raise an exception if your cert isn't
  properly signed.

  Usage:
    self.assertTrue(agamotto.network.checkHttp(url='http://localhost/index.html',
                    matchtext='<title>', 'Did not see a title in https result')
  """
  raw = requests.get(url, verify=verifyCertificate).text
  return matchtext in raw

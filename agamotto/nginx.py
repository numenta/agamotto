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

# Author: Joe Block <jpb@numenta.com>

from pynginxconfig import NginxConfig


def loadNginxConfig(configPath='/etc/nginx/nginx.conf'):
  """
  Load the nginx configuration, then parse with pynginxconfig.

  Default to loading from /etc/nginx/nginx.conf
  """
  with open (configPath, 'r') as configFile:
    raw=configFile.readlines()
    confData = ''.join(raw)
  nc = NginxConfig()
  nc.load(confData)
  return nc


def getHostConfigurations(configPath='/etc/nginx/nginx.conf'):
  """
  pynginxconfig returns an ugly data structure, but it is better than parsing
  the nginx configuration file ourself.

  Return a dict of host configurations for all server names found in the nginx
  configuration file for easy validation.

  It is valid to have multiple entries with the same name in a server's data
  (rewrite rules, for example), so when we find an entry with a name that
  already exists in the dict, we convert that entry to a list.
  """

  nginxConfigData = loadNginxConfig(configPath)
  serverData = {}
  for k in nginxConfigData.get_value(nginxConfigData.get([('http',), ]) ):
    if type(k) is dict:
      values = k['value']
      servernames = []
      for entry in values:
        if type(entry) is tuple:
          if entry[0].lower() == 'server_name':
            servernames = entry[1].split()
            conf = {}
            for v in values:
              if type(v) is tuple:
                entryKey = v[0]
                entryValue = v[1]
                if entryKey in conf.keys():
                  # We've already found an entry with this key name. Convert
                  # this dict entry to a list, and append.
                  if type(conf[entryKey]) is list:
                    conf[entryKey].append(entryValue)
                  else:
                    t = [conf[entryKey]]
                    t.append(entryValue)
                    conf[entryKey] = t
                  conf[entryKey].sort()
                else:
                  conf[entryKey] = entryValue
            for s in servernames:
              # Yes, we will end up with duplicated dict entries when a server
              # entry has more than one DNS name. This makes it easier to find
              # the entry corresponding to a given DNS name.
              serverData[s] = conf
  return serverData


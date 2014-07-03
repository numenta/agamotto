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

from agamotto.utils import execute


def exists(groupname):
  """Return True if groupname exists on the system"""
  try:
    return int(execute("getent group %s | wc -l" % (groupname))) > 0
  except:
    return False


def gid(groupname):
  """Return the gid associated with group groupname"""
  try:
    return execute("getent group %s" % (groupname)).split(':')[2]
  except:
    return None


def members(groupname):
  """Return the members of group groupname"""
  try:
    members = execute('getent group %s' %
                      groupname).split(':')[3].strip().split(',')
    if members == ['']:
      return []
    else:
      return members
  except:
    return []

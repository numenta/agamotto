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


def exists(username):
  """Check if username exists"""
  try:
    return int(execute("getent passwd %s | wc -l" % (username))) > 0
  except:
    return False


def uid(username):
  """Return the uid for username"""
  try:
    return int(execute("getent passwd %s" % (username)).split(':')[2])
  except:
    return -1


def gid(username):
  """Return the gid for username"""
  try:
    return int(execute("getent passwd %s" % (username)).split(':')[3])
  except:
    return -1


def gecos(username):
  """Return the gecos info for username"""
  try:
    return execute("getent passwd %s" % (username)).split(':')[4]
  except:
    return None


def home(username):
  """Return username's home directory"""
  try:
    return execute("getent passwd %s" % (username)).split(':')[5]
  except:
    return None


def shell(username):
  """Return username's shell"""
  try:
    return execute("getent passwd %s" % (username)).split(':')[6]
  except:
    return None

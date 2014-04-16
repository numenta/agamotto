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


def hasRunLevel(serviceName, runLevel):
  """Parse chkconfig output and return True if serviceName is set to run at
  that runLevel"""
  try:
    raw = execute("chkconfig --list %s" % (serviceName)).split()
  except:
    # chkconfig will exit non-zero if there are no entries for serviceName
    return False
  for stanza in raw[1:]:
    level = int(stanza[:1])
    status = stanza[2:]
    if runLevel == level and status == "on":
      return True
  return False


def disabled(serviceName):
  """Return True if serviceName is not enabled in run level 3"""
  return hasRunLevel(serviceName, 3) == False


def enabled(serviceName):
  """Return True if serviceName is enabled in the run level 3"""
  return hasRunLevel(serviceName, 3)

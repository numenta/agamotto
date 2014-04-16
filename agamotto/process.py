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

def running(processname):
  """Look for processname in the list of running processes"""
  try:
    return int(execute("ps wax | grep -v grep |  grep -c '%s'" % (processname))) > 0
  except Exception, e:
    # Pipeline exits nonzero if it doesn't find process, so return False
    # instead of letting the exception take out the test.
    return False


def is_running(processname):
  """Synonym for running to make the tests look prettier"""
  return running(processname)


def stdoutContains(command, required):
  """Run command, check for string required in the output"""
  try:
    return execute(command).find(required) >= 0
  except:
    return False

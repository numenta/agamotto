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

import re
import subprocess
import sys
import time



def execute(command, verbose=False, tries=3, delay=1, debug=0):
  """Run command, up to tries times. Print output while running if
  verbose=True.
  """
  strikes = 0
  if debug > 0:
    print "tries: %s" % tries
  while strikes < tries:
    strikes = strikes + 1
    if debug > 0:
      print "attempt %s of %s to run %s" % (strikes, tries, command)
    try:
      results = runCommand(command, verbose)
      return results
    except Exception, error:
      sys.stderr.write('ERROR running %s:\n%s\n' % (command, str(error)))
      time.sleep(delay)
  sys.stderr.write("%s failed after %s attempts\n" % (command, strikes))
  raise Exception("%s failed after %s attempts\n" % (command, strikes))



def runCommand(command, verbose=False):
  """Execute command, return the output. If verbose == true, print the output
     as the command runs.
  """
  process = subprocess.Popen(command, shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
  output = ""

  # Poll process for new output until finished
  for line in iter(process.stdout.readline, ""):
    if verbose:
      print line
    output += line

  process.wait()
  exitCode = process.returncode

  if exitCode == 0:
    return output
  else:
    raise Exception(command, exitCode, output)



def grep(text, regex):
  """
  Return just the lines that match our regex
  """
  cooked = []
  if type(text) is list:
    raw = text
  if type(text) is str:
    raw = text.split('\n')
  for line in raw:
    if re.search(regex, line):
      cooked.append(line)
  return cooked



def grepc(text, regex):
  """
  Return the count of the lines that match our regex
  """
  return len(grep(text, regex))


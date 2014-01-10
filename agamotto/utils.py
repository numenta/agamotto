# Copyright 2014 Numenta

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import subprocess

def execute(command, verbose=False):
  """Execute command, return the output. If verbose == true, print the output
     as the command runs."""
  process = subprocess.Popen(command, shell=True,
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  output = ""

  # Poll process for new output until finished
  for line in iter(process.stdout.readline, ""):
    if verbose:
      print line,
    output += line

  process.wait()
  exitCode = process.returncode

  if exitCode == 0:
    return output
  else:
    raise Exception(command, exitCode, output)

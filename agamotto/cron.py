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


def userCrontask(user, crontask):
  """Check that user has a specific entry in their crontab."""
  try:
    raw = execute("sudo crontab -u %s -l" % (user))
  except:
    return False
  if raw.find(crontask) >= 0:
    return True
  else:
    return False


def entry(crontask):
  """99% of the time we only care about root's crontab, so add a helper for
     that case."""
  return userCrontask('root', crontask)

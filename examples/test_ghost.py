#!/usr/bin/env python
# ----------------------------------------------------------------------
# Copyright (C) 2015 Numenta Inc. All rights reserved.
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

"""
Test for GHOST: glibc vulnerability (CVE-2015-0235)
https://access.redhat.com/articles/1332213
"""
import agamotto
import subprocess
import unittest2 as unittest



class TestForGhostVulnerability(unittest.TestCase):

  def testGlibcVulnerableToGhost(self):
    """
    glibc not vulnerable to CVE-2015-0235 (GHOST)
    """
    # We run this test in an external helper script because if the vulnerability
    # exists, the test I found blows away the calling process and we don't want
    # to miss seeing other test failures.
    try:
      self.assertEquals(subprocess.check_call(
        "/path/to/your/tests/helpers/ghost-test-helper.py"), 0,
        "glibc vulnerable to ghost!")
    except:
      self.fail("glibc vulnerable to ghost!")


if __name__ == "__main__":
  unittest.main()

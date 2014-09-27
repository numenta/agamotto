Agamotto
========

Agamotto is a helper module to make it easier to test a running system with
Python.

Why not use serverspec? I work in a Python shop and want our devs to be able
to easily write their own tests. Making the test suite use the same language
they use daily removes a potential friction point.

Installation
============
```bash
python setup.py install
```
TODO: Make this pip installable

Usage
=====
```python

import agamotto
import unittest2 as unittest

class TestKnownSecurityIssues(unittest.TestCase):

  def testBashHasCVE_2014_6271Fix(self):
    """Confirm that fix has been installed for CVE-2014-6271 Bash Code
    Injection Vulnerability via Specially Crafted Environment Variables
    """
    self.assertFalse(agamotto.process.stdoutContains("(env x='() { :;}; echo vulnerable'  bash -c \"echo this is a test\") 2>&1",
                     'vulnerable'), 'Bash is vulnerable to CVE-2014-6271')


  def testBashHasCVE_2014_7169Fix(self):
    """Confirm that fix has been installed for CVE-2014-7169 Bash Code
    Injection Vulnerability via Specially Crafted Environment Variables
    """
    self.assertFalse(agamotto.process.stdoutContains("env X='() { (a)=>\' bash -c \"echo echo vuln\"; [[ \"$(cat echo)\" == \"vuln\" ]] && echo \"still vulnerable :(\" 2>&1",
                     'still vulnerable'), 'Bash is vulnerable to CVE-2014-7169')


  def testNoAccountsHaveEmptyPasswords(self):
    """/etc/shadow has : separated fields. Check the password field ($2) and
       make sure no accounts have a blank password.
    """
    self.assertEquals(agamotto.process.execute(
      'sudo awk -F: \'($2 == "") {print}\' /etc/shadow | wc -l').strip(), '0',
      "found accounts with blank password")


  def testRootIsTheOnlyUidZeroAccount(self):
    """/etc/passwd stores the UID in field 3. Make sure only one account entry
    has uid 0.
    """
    self.assertEquals(agamotto.process.execute(
                      'awk -F: \'($3 == "0") {print}\' /etc/passwd').strip(),
                      'root:x:0:0:root:/root:/bin/bash')



if __name__ == '__main__':
  unittest.main()
```

Then run py.test.

Caveats
=======
We're a CentOS shop. This hasn't even been tested on stock RHEL, let alone
Debian or Ubuntu. Pull requests adding that functionality are welcome, of course.

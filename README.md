Agamotto
========

Agamotto is a helper module to make it easier to test a running system with
Python.

Why not use serverspec? I work in a Python shop and want our devs to be able
to easily write their own tests. Making the test suite use the same language
they use daily removes a potential friction point.

Usage
=====
```python

import agamotto as a
import unittest2 as unittest


class TestMysql(unittest.TestCase):

  def test_mysql_user(self):
    self.assertTrue(a.user.exists('mysql'))


  def test_mysql_server_installed(self):
    self.assertTrue(a.package.is_installed('mysql-server'))


  def test_mysql_client_installed(self):
    self.assertTrue(a.package.is_installed('mysql'))


  def test_mysql_config_exists(self):
    self.assertTrue(a.file.exists('/etc/my.cnf'))


  def test_mysql_bound_to_localhost(self):
    self.assertTrue(a.file.contains('/etc/my.cnf',
                    'bind-address            = 127.0.0.1'))


  def test_mysql_running(self):
    self.assertTrue(a.process.is_running('/bin/sh /usr/bin/mysqld_safe'))


  def test_mysql_initscript(self):
    self.assertTrue(a.file.exists('/etc/init.d/mysqld'))


if __name__ == '__main__':
  unittest.main()

```

Then run py.test.

Caveats
=======
We're a CentOS shop. This hasn't even been tested on stock RHEL, let alone
Debian or Ubuntu. Pull requests adding that functionality are welcome, of course.
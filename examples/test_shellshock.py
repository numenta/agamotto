#!/usr/bin/env python
# ----------------------------------------------------------------------
# Copyright (C) 2014 Numenta Inc. All rights reserved.
#
# The information and source code contained herein is the
# exclusive property of Numenta Inc.  No part of this software
# may be used, reproduced, stored or distributed in any form,
# without explicit written authorization from Numenta Inc.
# ----------------------------------------------------------------------
"""
Test shellshock and the other bash bugs
"""
import agamotto
import unittest2 as unittest


class TestForBashSecurityBugs(unittest.TestCase):

  def testForBashCVE_2014_6271(self):
    """Is bash immune to CVE-2014-6271?
    """
    self.assertFalse(agamotto.process.stdoutContains("(env x='() { :;}; echo vulnerable'  bash -c \"echo this is a test\") 2>&1",
                                                     'vulnerable'),
                     'Bash is vulnerable to CVE-2014-6271')


  def testForBashCVE_2014_7169(self):
    """Is bash immune to CVE-2014-7169?
    """
    self.assertFalse(agamotto.process.stdoutContains("env X='() { (a)=>\' bash -c \"echo echo vuln\"; [[ \"$(cat echo)\" == \"vuln\" ]] && echo \"still vulnerable :(\" 2>&1",
                                                     'still vulnerable'),
                     'Bash is vulnerable to CVE-2014-7169')


  def testForBashCVE_2014_6277(self):
    """Is bash immune to CVE-2014-6277?
    """
    self.assertFalse(agamotto.process.stdoutContains("foo='() { echo still vulnerable; }' bash -c foo 2>&1",
                                                     'still vulnerable'),
                     'Bash is vulnerable to CVE-2014-7169')


  def testForBashCVE_2014_7186_a(self):
    """Is bash immune to CVE-2014-7186 using test from shellshocker.net?"""
    self.assertFalse(agamotto.process.stdoutContains("bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo 'CVE-2014-7186 vulnerable, redir_stack'",
                                                     'CVE-2014-7186 vulnerable, redir_stack'),
                     'Vulnerable to CVE-2014-7186')


  def testForBashCVE_2014_7186_b(self):
    """Is bash immune to CVE-2014-7186 using eblake@redhat.com's test?"""
    # Try Eric Blake's test too
    self.assertTrue(agamotto.process.stdoutContains('bash -c "export f=1 g=\'() {\'; f() { echo 2;}; export -f f; bash -c \'echo \$f \$g; f; env | grep ^f=\'"',
                                                    "f=1"),
                    "Fails Eric Blake's 7186 test")


  def testForBashCVE_2014_7187(self):
    """Is bash immune to CVE-2014-7187 using test from shellshocker.net?"""
    self.assertFalse(agamotto.process.stdoutContains('(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | bash || echo "CVE-2014-7187 vulnerable, word_lineno"',
                                                     'CVE-2014-7187 vulnerable, word_lineno'),
                     'CVE-2014-7187 vulnerable, word_lineno')


if __name__ == '__main__':
  unittest.main()

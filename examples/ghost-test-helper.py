#!/usr/bin/env python
# Original source: https://gist.github.com/anonymous/39e31113f9c08529caad
#
# Check for GHOST: glibc vulnerability (CVE-2015-0235)
#
# Run this as an external script since it crashes the running process
# if the vulnerability is found.

import ctypes
import sys

libc=ctypes.CDLL("libc.so.6")
for i in xrange(2500):
   sys.stdout.write(".")
   libc.gethostbyname("0" * i)

print "\nTested Ok"

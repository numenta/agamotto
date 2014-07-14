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


import grp
import os
import pwd


def contains(path, data):
  """Return True if data is present in file path."""
  try:
    raw = open(path).read()
  except:
    return False
  if raw.find(data) >= 0:
    return True
  return False


def does_not_contain(path, data):
  """Return False if data is present in file path"""
  return not contains(path, data)


def exists(path):
  """Test if a path exists"""
  return os.path.exists(path)


def isDirectory(path):
  """Test if path is a directory"""
  return os.path.isdir(path)


def isExecutable(path):
  """Test if file at path is executable"""
  return os.access(path, os.X_OK)


def isFile(path):
  """Test if path is a file"""
  return os.path.isfile(path)


def owner(path):
  """Return name of owner of file/directory at path"""
  return pwd.getpwuid(os.stat(path).st_uid).pw_name


def group(path):
  """Return name of group that owns the file/directory at path"""
  return grp.getgrgid(os.stat(path).st_gid).gr_name


def mode(path):
  """Return octal mode of path as a string"""
  return "%s" % oct(os.stat(path).st_mode)[-3:]


def octalMode(path):
  """Return the raw octal value"""
  return oct(os.stat(path).st_mode)

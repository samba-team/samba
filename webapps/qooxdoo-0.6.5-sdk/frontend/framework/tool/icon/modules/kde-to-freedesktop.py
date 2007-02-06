#!/usr/bin/env python
################################################################################
#
#  qooxdoo - the new era of web development
#
#  http://qooxdoo.org
#
#  Copyright:
#    2007 1&1 Internet AG, Germany, http://www.1and1.org
#
#  License:
#    LGPL: http://www.gnu.org/licenses/lgpl.html
#    EPL: http://www.eclipse.org/org/documents/epl-v10.php
#    See the LICENSE file in the project's top-level directory for details.
#
#  Authors:
#    * Sebastian Werner (wpbasti)
#
################################################################################

import os
import sys
import shutil
import optparse

def rmgeneric(path, __func__):
  try:
    __func__(path)
  except OSError, (errno, strerror):
    print ERROR_STR % {'path' : path, 'error': strerror }


def removeall(path):
  if not os.path.isdir(path):
    return

  files=os.listdir(path)

  for x in files:
    fullpath=os.path.join(path, x)
    if os.path.isfile(fullpath):
      f=os.remove
      rmgeneric(fullpath, f)
    elif os.path.isdir(fullpath):
      removeall(fullpath)
      f=os.rmdir
      rmgeneric(fullpath, f)



def copy_file(kde, fd, options):
  img_sizes = [16, 22, 32, 48, 64, 72, 96, 128]
  found = []
  notfound = []

  if options.verbose:
    print "    - Processing: %s -> %s" % (kde, fd)

  for size in img_sizes:
    kde_file = "%s/%sx%s/%s.png" % (options.input, size, size, kde)
    fd_file = "%s/%sx%s/%s.png" % (options.output, size, size, fd)

    if os.path.exists(kde_file):
      fd_dir = os.path.dirname(fd_file)
      if not os.path.exists(fd_dir):
        os.makedirs(fd_dir)

      shutil.copyfile(kde_file, fd_file)
      found.append(size)

    else:
      notfound.append(size)

  if options.verbose:
    dbg = "      "
    for size in img_sizes:
      if size in found:
        ret = "Y"
      else:
        ret = "N"
      dbg += " [%s] %s" % (ret, size)

    print dbg



def main():
  parser = optparse.OptionParser("usage: %prog [options]")
  parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=False, help="Quiet output mode.")
  parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="Verbose output mode.")
  parser.add_option("--input", "-i", action="store", dest="input", metavar="DIRECTORY", help="Input directory")
  parser.add_option("--output", "-o", action="store", dest="output", metavar="DIRECTORY", help="Output directory")

  (options, args) = parser.parse_args(sys.argv[1:])

  if options.input == None or options.output == None:
    basename = os.path.basename(sys.argv[0])
    print "You must define both, the input and output folders!"
    print "usage: %s [options]" % basename
    print "Try '%s -h' or '%s --help' to show the help message." % (basename, basename)
    sys.exit(1)

  print "    - Cleaning up..."
  removeall(options.output)

  dat = open("%s/../data/kde_freedesktop.dat" % os.path.dirname(sys.argv[0]))

  print "    - Copying files..."
  for line in dat.readlines():
    line = line.strip();

    if line == "" or line[0] == "#":
      continue

    if not line[0] in ["+", "*"]:
      continue

    line = line[1:]

    (fd, kde) = map(lambda x: x.strip(), line.split("="))
    copy_file(kde, fd, options)



if __name__ == "__main__":
    sys.exit(main())

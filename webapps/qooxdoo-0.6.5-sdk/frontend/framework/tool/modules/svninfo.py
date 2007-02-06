#!/usr/bin/env python
################################################################################
#
#  qooxdoo - the new era of web development
#
#  http://qooxdoo.org
#
#  Copyright:
#    2006-2007 1&1 Internet AG, Germany, http://www.1and1.org
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

import os, sys, re, optparse
import filetool



DIRINFO = re.compile("dir\n([0-9]+)\nhttps://.*/svnroot/qooxdoo/(\w+)/(\w+)/", re.M | re.S)



def query(path):
  if os.path.exists(path):
    entries = os.path.join(path, ".svn", "entries")

    if os.path.exists(entries):
      content = filetool.read(entries)

      mtch = DIRINFO.search(content)
      if mtch:
        folder = mtch.group(2)
        if folder in [ "tags", "branches" ]:
          folder = mtch.group(3)

        revision = mtch.group(1)

        return revision, folder

  return None, None



def format(revision, folder):
  return "(r%s) [%s]" % (revision, folder)



if __name__ == '__main__':
  try:
    parser = optparse.OptionParser()

    (options, args) = parser.parse_args()

    revision, folder = query(args[0])
    if revision != None:
      print format(revision, folder)


  except KeyboardInterrupt:
    print
    print "  * Keyboard Interrupt"
    sys.exit(1)

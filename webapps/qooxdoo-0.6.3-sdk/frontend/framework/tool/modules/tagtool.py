#!/usr/bin/env python

import sys, string, re, optparse
import config, filetool, comment, random


R_TAG = re.compile("random\(.*\)")



def main():
  parser = optparse.OptionParser()

  parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=False, help="Quiet output mode.")
  parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="Verbose output mode.")
  parser.add_option("--encoding", dest="encoding", default="utf-8", metavar="ENCODING", help="Defines the encoding expected for input files.")

  (options, args) = parser.parse_args()
  
  if len(args) == 0:
    print "Needs one or more arguments (files) to tag!"
    sys.exit(1)
    
  for fileName in args:
    if options.verbose:
      print "  * Tagging %s" % fileName
    
    origFileContent = filetool.read(fileName, options.encoding)
    patchedFileContent = R_TAG.sub("random(%s)" % random.randint(100, 999), origFileContent)
    
    if patchedFileContent != origFileContent:
      filetool.save(fileName, patchedFileContent, options.encoding)




if __name__ == '__main__':
  try:
    main()

  except KeyboardInterrupt:
    print
    print "  * Keyboard Interrupt"
    sys.exit(1)
    
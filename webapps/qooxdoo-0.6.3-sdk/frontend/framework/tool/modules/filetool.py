#!/usr/bin/env python

import os, codecs, cPickle, sys
import textutil

def save(filePath, content="", encoding="utf_8"):
  # Normalize
  filePath = normalize(filePath)

  # Create directory
  directory(os.path.dirname(filePath))

  # Writing file
  try:
    outputFile = codecs.open(filePath, encoding=encoding, mode="w", errors="replace")
    outputFile.write(content)
  except IOError, (errno, strerror):
    print "  * I/O error(%s): %s" % (errno, strerror)
    sys.exit(1)
  except UnicodeDecodeError:
    print "  * Could not decode result to %s" % encoding
    sys.exit(1)
  except:
    print "  * Unexpected error:", sys.exc_info()[0]
    sys.exit(1)

  outputFile.flush()
  outputFile.close()


def directory(dirname):
  # Normalize
  dirname = normalize(dirname)

  # Check/Create directory
  if dirname != "" and not os.path.exists(dirname):
    os.makedirs(dirname)


def normalize(filename):
  return os.path.normcase(os.path.normpath(filename))


def read(filePath, encoding="utf_8"):
  try:
    ref = codecs.open(filePath, encoding=encoding, mode="r")
    content = ref.read()
    ref.close()

    return textutil.any2Unix(unicode(content))

  except IOError, (errno, strerror):
    print "  * I/O error(%s): %s" % (errno, strerror)
    sys.exit(1)

  except ValueError:
    print "  * Invalid Encoding. Required encoding %s in %s" % (encoding, filePath)
    sys.exit(1)

  except:
    print "  * Unexpected error:", sys.exc_info()[0]
    sys.exit(1)


def storeCache(cachePath, data):
  try:
    cPickle.dump(data, open(cachePath, 'w'), 2)

  except EOFError or PickleError or PicklingError:
    print "  * Could not store cache to %s" % cachePath
    sys.exit(1)


def readCache(cachePath):
  try:
    return cPickle.load(open(cachePath))

  except EOFError or PickleError or UnpicklingError:
    print "  * Could not read cache from %s" % cachePath
    sys.exit(1)


def checkCache(filePath, cachePath, internalModTime):
  fileModTime = os.stat(filePath).st_mtime

  try:
    cacheModTime = os.stat(cachePath).st_mtime
  except OSError:
    cacheModTime = 0

  if internalModTime > cacheModTime:
    # print "Invalid cache: %s" % filePath
    # print "%s > %s" % (internalModTime, cacheModTime)
    return True

  return fileModTime > cacheModTime

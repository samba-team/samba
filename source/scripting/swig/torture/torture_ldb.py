#!/usr/bin/python

import Ldb

def fail(msg):
    print 'FAILED:', msg
    sys.exit(1)

l = Ldb.Ldb()

l.connect('tdb:///tmp/foo.ldb')
result = l.search('(dn=*)')

print result

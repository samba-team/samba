#!/usr/bin/python

import Ldb, sys

def test(cond, msg):
    if not cond:
        print 'FAILED:', msg
        sys.exit(1)

# Torture LdbMessage

m = Ldb.LdbMessage()
m['animal'] = 'dog'
m['name'] = 'spotty'

test(m.keys() == ['animal', 'name'], 'keys() test failed')
test(m.values() == [['dog'], ['spotty']], 'values() test failed')
test(m.items() == [('animal', ['dog']), ('name', ['spotty'])], 'items() test failed')

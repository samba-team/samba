#!/usr/bin/python
#
# A torture test for the Python Ldb bindings.  Also a short guide on
# how the API works.
#

from Ldb import *

# Helpers

def t(cond, msg):
    """Test a condition."""
    if not cond:
        raise RuntimeError('FAILED: %s' % msg)

#
# Torture LdbMessage
#

m = LdbMessage()

# Empty message

t(m.keys() == [], 'empty msg')
t(m.dn == None, 'empty dn')

t(m.sanity_check() == LDB_ERR_INVALID_DN_SYNTAX, 'sanity check')

# Test invalid dn

try:
    m.dn = 'invalid dn'
except LdbError, arg:
    if arg[0] != LDB_ERR_INVALID_DN_SYNTAX:
        raise
else:
    t(False, 'LdbError not raised')

# Test valid dn

m.dn = 'name=spotty'
t(m.dn == 'name=spotty', 'specified dn')

t(m.sanity_check() == LDB_SUCCESS, 'sanity check')

# Test some single-valued attributes

m['animal'] = 'dog'
m['name'] = 'spotty'

t(m.keys() == ['animal', 'name'], 'keys() test failed')
t(m.values() == [['dog'], ['spotty']], 'values() test failed')
t(m.items() == [('animal', ['dog']), ('name', ['spotty'])],
  'items() test failed')

t(m.sanity_check() == LDB_SUCCESS, 'sanity check')

m['animal'] = 'canine'
t(m['animal'] == ['canine'], 'replace value failed')

# Test a multi-valued attribute

names = ['spotty', 'foot']
m['name'] = names

t(m['name'] == names, 'multi-valued attr failed')

t(m.sanity_check() == LDB_SUCCESS, 'sanity check')

# Test non-string attributes

try:
    m['foo'] = 42
except TypeError:
    pass
else:
    t(False, 'TypeError not raised')

#
# Torture Ldb
#

l = Ldb('foo.ldb')

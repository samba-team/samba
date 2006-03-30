#!/usr/bin/python

import Tdb, os

t = Tdb.Tdb('foo.tdb')
os.unlink('foo.tdb')

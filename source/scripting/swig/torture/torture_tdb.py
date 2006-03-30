#!/usr/bin/python

import sys, tdb
from os import *

t = tdb.open('foo.tdb', 0, 0, O_RDWR | O_CREAT, 0600)
tdb.close(t)

unlink('foo.tdb')


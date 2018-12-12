#!/usr/bin/env python3
# Trivial reimplementation of tdbdump in Python

from __future__ import print_function
import tdb, sys

if len(sys.argv) < 2:
    print("Usage: tdbdump.py <tdb-file>")
    sys.exit(1)

db = tdb.Tdb(sys.argv[1])
for (k, v) in db.items():
    print("{\nkey(%d) = %r\ndata(%d) = %r\n}" % (len(k), k, len(v), v))

#!/usr/bin/env python3
# Trivial reimplementation of tdbdump in Python

import sys

sys.path.insert(0, "bin/python")

import tdb

if len(sys.argv) < 2:
    print("Usage: tdbdump.py <tdb-file>")
    sys.exit(1)

db = tdb.Tdb(sys.argv[1])
for k in db.keys():
    v = db.get(k)
    print("{\nkey(%d) = %r\ndata(%d) = %r\n}" % (len(k), k, len(v), v))

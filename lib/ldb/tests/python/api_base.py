#!/usr/bin/env python3
# Simple tests for the ldb python bindings.
# Copyright (C) 2007 Jelmer Vernooij <jelmer@samba.org>

import os
from unittest import TestCase
import sys
sys.path.insert(0, "bin/python")
import ldb


TDB_PREFIX = "tdb://"
MDB_PREFIX = "mdb://"

MDB_INDEX_OBJ = {
    "dn": "@INDEXLIST",
    "@IDXONE": [b"1"],
    "@IDXGUID": [b"objectUUID"],
    "@IDX_DN_GUID": [b"GUID"]
}


def tempdir():
    import tempfile
    try:
        dir_prefix = os.path.join(os.environ["SELFTEST_PREFIX"], "tmp")
    except KeyError:
        dir_prefix = None
    return tempfile.mkdtemp(dir=dir_prefix)


class LdbBaseTest(TestCase):
    prefix = TDB_PREFIX

    def url(self):
        return self.prefix + self.filename

    @classmethod
    def flags(cls):
        if cls.prefix == MDB_PREFIX:
            return ldb.FLG_NOSYNC
        else:
            return 0

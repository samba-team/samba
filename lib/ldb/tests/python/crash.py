#!/usr/bin/env python3
#
# Tests for crashing functions

import os
from unittest import TestCase
import os
import sys
import traceback

import ldb


def segfault_detector(f):
    def wrapper(*args, **kwargs):
        pid = os.fork()
        if pid == 0:
            # child, crashing?
            try:
                f(*args, **kwargs)
            except Exception as e:
                traceback.print_exc()
            sys.stderr.flush()
            sys.stdout.flush()
            os._exit(0)

        # parent, waiting
        pid2, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            signal = os.WTERMSIG(status)
            raise AssertionError("Failed with signal %d" % signal)

    return wrapper


class LdbDnCrashTests(TestCase):
    @segfault_detector
    def test_ldb_dn_explode_crash(self):
        for i in range(106, 150):
            dn = ldb.Dn(ldb.Ldb(), "a=b%s,c= " % (' ' * i))
            dn.validate()

if __name__ == '__main__':
    import unittest
    unittest.TestProgram()

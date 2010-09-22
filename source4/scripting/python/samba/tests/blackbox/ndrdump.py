#!/usr/bin/python
# Blackbox tests for masktest
# Copyright (C) 2008 Andrew Tridgell
# Copyright (C) 2008 Andrew Bartlett
# based on test_smbclient.sh

import os
from samba.tests import BlackboxTestCase

data_path_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../../librpc/tests"))

class NdrDumpTests(BlackboxTestCase):
    """Blackbox tests for ndrdump."""

    def data_path(self, name):
        return os.path.join(data_path_dir, name)

    def test_ndrdump_with_in(self):
        self.check_run("ndrdump samr samr_CreateUser in %s" % (self.data_path("samr-CreateUser-in.dat")))

    def test_ndrdump_with_out(self):
        self.check_run("ndrdump samr samr_CreateUser out %s" % (self.data_path("samr-CreateUser-out.dat")))

    def test_ndrdump_context_file(self):
        self.check_run("ndrdump --context-file %s samr samr_CreateUser out %s" % (self.data_path("samr-CreateUser-in.dat"), self.data_path("samr-CreateUser-out.dat")))

    def test_ndrdump_with_validate(self):
        self.check_run("ndrdump --validate samr samr_CreateUser in %s" % (self.data_path("samr-CreateUser-in.dat")))

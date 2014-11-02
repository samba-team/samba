#!/usr/bin/env python

# Simple subunit testrunner for python

# NOTE: DO NOT USE THIS MODULE FOR NEW CODE.
#
# Instead, use the standard subunit runner - e.g. "python -m subunit.run
# YOURMODULE".
#
# This wrapper will be removed once all tests can be run
# without it. At the moment there are various tests which still
# get e.g. credentials passed via command-line options to this
# script.

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2014
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys

# make sure the script dies immediately when hitting control-C,
# rather than raising KeyboardInterrupt. As we do all database
# operations using transactions, this is safe.
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

# Find right directory when running from source tree
sys.path.insert(0, "bin/python")

import samba
samba.ensure_external_module("mimeparse", "mimeparse")
samba.ensure_external_module("extras", "extras")
samba.ensure_external_module("testtools", "testtools")
samba.ensure_external_module("subunit", "subunit/python")
import subunit.run

try:
   from subunit.run import TestProgram
except ImportError:
   from unittest import TestProgram


class TestProgram(TestProgram):

    def __init__(self, module=None, argv=None):
        super(TestProgram, self).__init__(module=module, argv=argv,
            testRunner=subunit.run.SubunitTestRunner())

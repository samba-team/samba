# test_target.py -- The tests for selftest target code
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 3
# of the License or (at your option) any later version of
# the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

"""Tests for selftest.target."""

from selftest.target import (
    EnvironmentManager,
    NoneEnvironment,
    Environment,
    Target,
    )

import os
import unittest


class DummyEnvironment(Environment):

    def __init__(self, name, prefix):
        self.name = name
        self.prefix = prefix
        self.check_ret = True
        self.log_ret = ""

    def check(self):
        return self.check_ret

    def get_log(self):
        return self.log_ret


class DummyTarget(Target):

    def get_target(self, name, prefix):
        return DummyTarget(name, prefix)


class EnvironmentManagerTests(unittest.TestCase):

    def setUp(self):
        self.mgr = EnvironmentManager(DummyTarget())

    def test_none(self):
        self.assertIs(NoneEnvironment, type(self.mgr.setup_env("none", "prefix")))

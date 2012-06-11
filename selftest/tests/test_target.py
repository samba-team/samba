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
    Environment,
    EnvironmentDown,
    EnvironmentManager,
    NoneEnvironment,
    NoneTarget,
    Target,
    UnsupportedEnvironment,
    )

from selftest.tests import TestCase


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

    def setup_env(self, name, prefix):
        return DummyEnvironment(name, prefix)


class NoneEnvironmentTests(TestCase):

    def setUp(self):
        super(NoneEnvironmentTests, self).setUp()
        self.env = NoneEnvironment()

    def test_get_vars(self):
        self.assertEquals({}, self.env.get_vars())

    def test_check(self):
        self.assertEquals(True, self.env.check())

    def test_get_log(self):
        self.assertEquals("", self.env.get_log())


class NoneTargetTests(TestCase):

    def setUp(self):
        super(NoneTargetTests, self).setUp()
        self.target = NoneTarget()

    def test_setup_env(self):
        self.assertRaises(UnsupportedEnvironment, self.target.setup_env,
            "something", "prefx")


class EnvironmentManagerTests(TestCase):

    def setUp(self):
        super(EnvironmentManagerTests, self).setUp()
        self.mgr = EnvironmentManager(DummyTarget())

    def test_none(self):
        self.assertIs(
            NoneEnvironment, type(self.mgr.setup_env("none", "prefix")))

    def test_setup(self):
        env = self.mgr.setup_env("something", "prefix")
        self.assertEquals(env.name, "something")
        self.assertEquals(env.prefix, "prefix")

    def test_setup_reuses(self):
        env1 = self.mgr.setup_env("something", "prefix")
        env2 = self.mgr.setup_env("something", "prefix")
        self.assertIs(env1, env2)

    def test_setup_down(self):
        env1 = self.mgr.setup_env("something", "prefix")
        env1.check_ret = False
        self.assertRaises(EnvironmentDown, self.mgr.setup_env, "something", "")

    def test_check(self):
        env = self.mgr.setup_env("something", "prefix")
        self.assertTrue(env.check())
        self.assertTrue(self.mgr.check_env("something"))
        env.check_ret = False
        self.assertFalse(env.check())
        self.assertFalse(self.mgr.check_env("something"))

    def test_get_log(self):
        env = self.mgr.setup_env("something", "prefix")
        self.assertEquals("", env.get_log())
        self.assertEquals("", self.mgr.getlog_env("something"))
        env.log_ret = 'bla'
        self.assertEquals('bla', env.get_log())
        self.assertEquals('bla', self.mgr.getlog_env("something"))

    def test_get_running_env(self):
        env = self.mgr.setup_env("something", "prefix")
        self.assertIs(env, self.mgr.get_running_env("something"))

    def test_get_running_env_nonexistent(self):
        self.assertIs(None, self.mgr.get_running_env("something"))

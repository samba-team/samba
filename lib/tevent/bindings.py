#!/usr/bin/python
#
#   Python integration for tevent - tests
#
#   Copyright (C) Jelmer Vernooij 2010
#
#     ** NOTE! The following LGPL license applies to the tevent
#     ** library. This does NOT imply that all of Samba is released
#     ** under the LGPL
#
#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 3 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, see <http://www.gnu.org/licenses/>.

import signal
from unittest import TestCase, TestProgram
import gc

import _tevent


class BackendListTests(TestCase):

    def test_backend_list(self):
        self.assertTrue(isinstance(_tevent.backend_list(), list))


class CreateContextTests(TestCase):

    def test_by_name(self):
        ctx = _tevent.Context(_tevent.backend_list()[0])
        self.assertTrue(ctx is not None)

    def test_no_name(self):
        ctx = _tevent.Context()
        self.assertTrue(ctx is not None)


class ContextTests(TestCase):

    def setUp(self):
        super(ContextTests, self).setUp()
        self.ctx = _tevent.Context()

    def test_signal_support(self):
        self.assertTrue(type(self.ctx.signal_support) is bool)

    def test_reinitialise(self):
        self.ctx.reinitialise()

    def test_loop_wait(self):
        self.ctx.loop_wait()

    def test_add_signal(self):
        sig = self.ctx.add_signal(signal.SIGINT, 0, lambda callback: None)
        self.assertTrue(isinstance(sig, _tevent.Signal))

    def test_timer(self):
        """Test a timer is can be scheduled"""
        collecting_list = []
        # time "0" has already passed, callback will be scheduled immediately
        timer = self.ctx.add_timer(0, lambda t: collecting_list.append(True))
        self.assertTrue(timer.active)
        self.assertEqual(collecting_list, [])
        self.ctx.loop_once()
        self.assertFalse(timer.active)
        self.assertEqual(collecting_list, [True])

    def test_timer_deallocate_timer(self):
        """Test timer is scheduled even if reference to it isn't held"""
        collecting_list = []

        def callback(t):
            collecting_list.append(True)
        timer = self.ctx.add_timer(0, lambda t: collecting_list.append(True))
        gc.collect()
        self.assertEqual(collecting_list, [])
        self.ctx.loop_once()
        self.assertEqual(collecting_list, [True])

    def test_timer_deallocate_context(self):
        """Test timer is unscheduled when context is freed"""
        collecting_list = []

        def callback(t):
            collecting_list.append(True)
        timer = self.ctx.add_timer(0, lambda t: collecting_list.append(True))
        self.assertTrue(timer.active)
        del self.ctx
        gc.collect()
        self.assertEqual(collecting_list, [])
        self.assertFalse(timer.active)

    def test_timer_offset(self):
        """Test scheduling timer with an offset"""
        collecting_list = []
        self.ctx.add_timer_offset(0.2, lambda t: collecting_list.append(2))
        self.ctx.add_timer_offset(0.1, lambda t: collecting_list.append(1))
        self.assertEqual(collecting_list, [])
        self.ctx.loop_once()
        self.assertEqual(collecting_list, [1])
        self.ctx.loop_once()
        self.assertEqual(collecting_list, [1, 2])


if __name__ == '__main__':
    TestProgram()

# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright © Jelmer Vernooij <jelmer@samba.org> 2008
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

"""Tests for samba.messaging."""
import samba
from samba.messaging import Messaging
from samba.tests import TestCase
import time
from samba.ndr import ndr_print
from samba.dcerpc import server_id
import random
import os
from samba.compat import integer_types


class MessagingTests(TestCase):

    def get_context(self, *args, **kwargs):
        kwargs['lp_ctx'] = samba.tests.env_loadparm()
        return Messaging(*args, **kwargs)

    def test_register(self):
        x = self.get_context()

        def callback():
            pass
        msg_type = x.register((callback, None))
        self.assertTrue(isinstance(msg_type, integer_types))
        x.deregister(callback, msg_type)

    def test_all_servers(self):
        x = self.get_context()
        self.assertTrue(isinstance(x.irpc_all_servers(), list))

    def test_by_name(self):
        x = self.get_context()
        for name in x.irpc_all_servers():
            self.assertTrue(isinstance(x.irpc_servers_byname(name.name), list))

    def test_unknown_name(self):
        x = self.get_context()
        self.assertRaises(KeyError,
                          x.irpc_servers_byname, "samba.messaging test NONEXISTING")

    def test_assign_server_id(self):
        x = self.get_context()
        self.assertTrue(isinstance(x.server_id, server_id.server_id))

    def test_add_remove_name(self):
        x = self.get_context()
        name = "samba.messaging test-%d" % random.randint(1, 1000000)
        x.irpc_add_name(name)
        name_list = x.irpc_servers_byname(name)
        self.assertEqual(len(name_list), 1)
        self.assertEqual(ndr_print(x.server_id),
                         ndr_print(name_list[0]))
        x.irpc_remove_name(name)
        self.assertRaises(KeyError,
                          x.irpc_servers_byname, name)

    def test_ping_speed(self):
        got_ping = {"count": 0}
        got_pong = {"count": 0}
        timeout = False

        msg_pong = 0
        msg_ping = 0

        server_ctx = self.get_context((0, 1))

        def ping_callback(got_ping, msg_type, src, data):
            got_ping["count"] += 1
            server_ctx.send(src, msg_pong, data)

        msg_ping = server_ctx.register((ping_callback, got_ping))

        def pong_callback(got_pong, msg_type, src, data):
            got_pong["count"] += 1

        client_ctx = self.get_context((0, 2))
        msg_pong = client_ctx.register((pong_callback, got_pong))

        # Try both server_id forms (structure and tuple)
        client_ctx.send((0, 1), msg_ping, "testing")

        client_ctx.send((0, 1), msg_ping, "testing2")

        start_time = time.time()

        # NOTE WELL: If debugging this with GDB, then the timeout will
        # fire while you are trying to understand it.

        while (got_ping["count"] < 2 or got_pong["count"] < 2) and not timeout:
            client_ctx.loop_once(0.1)
            server_ctx.loop_once(0.1)
            if time.time() - start_time > 1:
                timeout = True

        self.assertEqual(got_ping["count"], 2)
        self.assertEqual(got_pong["count"], 2)

    def test_pid_defaulting(self):
        got_ping = {"count": 0}
        got_pong = {"count": 0}
        timeout = False

        msg_pong = 0
        msg_ping = 0

        pid = os.getpid()
        server_ctx = self.get_context((pid, 1))

        def ping_callback(got_ping, msg_type, src, data):
            got_ping["count"] += 1
            server_ctx.send(src, msg_pong, data)

        msg_ping = server_ctx.register((ping_callback, got_ping))

        def pong_callback(got_pong, msg_type, src, data):
            got_pong["count"] += 1

        client_ctx = self.get_context((2,))
        msg_pong = client_ctx.register((pong_callback, got_pong))

        # Try one and two element tuple forms
        client_ctx.send((pid, 1), msg_ping, "testing")

        client_ctx.send((1,), msg_ping, "testing2")

        start_time = time.time()

        # NOTE WELL: If debugging this with GDB, then the timeout will
        # fire while you are trying to understand it.

        while (got_ping["count"] < 2 or got_pong["count"] < 2) and not timeout:
            client_ctx.loop_once(0.1)
            server_ctx.loop_once(0.1)
            if time.time() - start_time > 1:
                timeout = True

        self.assertEqual(got_ping["count"], 2)
        self.assertEqual(got_pong["count"], 2)

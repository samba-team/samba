# test_socket_wraper.py -- The tests for selftest socket wrapper routines
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

"""Tests for selftest/socket_wrapper."""

from selftest.tests import TestCase

from selftest import socket_wrapper

import os

class SocketWrapperTests(TestCase):

    def test_setup_pcap(self):
        socket_wrapper.setup_pcap("somefile")
        self.assertEquals("somefile", os.environ["SOCKET_WRAPPER_PCAP_FILE"])

    def test_set_default_iface(self):
        socket_wrapper.set_default_iface(4)
        self.assertEquals("4", os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"])

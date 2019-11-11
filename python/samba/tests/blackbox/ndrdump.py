# Blackbox tests for ndrdump
# Copyright (C) 2008 Andrew Tridgell <tridge@samba.org>
# Copyright (C) 2008 Andrew Bartlett <abartlet@samba.org>
# Copyright (C) 2010 Jelmer Vernooij <jelmer@samba.org>
# based on test_smbclient.sh

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

from __future__ import print_function
"""Blackbox tests for ndrdump."""

import os
from samba.tests import BlackboxTestCase, BlackboxProcessError

for p in ["../../../../../source4/librpc/tests",
          "../../../../../librpc/tests"]:
    data_path_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), p))
    print(data_path_dir)
    if os.path.exists(data_path_dir):
        break


class NdrDumpTests(BlackboxTestCase):
    """Blackbox tests for ndrdump."""

    def data_path(self, name):
        return os.path.join(data_path_dir, name)

    def test_ndrdump_with_in(self):
        self.check_run(("ndrdump samr samr_CreateUser in %s" %
                       (self.data_path("samr-CreateUser-in.dat"))))

    def test_ndrdump_with_out(self):
        self.check_run(("ndrdump samr samr_CreateUser out %s" %
                       (self.data_path("samr-CreateUser-out.dat"))))

    def test_ndrdump_context_file(self):
        self.check_run(
            ("ndrdump --context-file %s samr samr_CreateUser out %s" %
                (self.data_path("samr-CreateUser-in.dat"),
                self.data_path("samr-CreateUser-out.dat"))))

    def test_ndrdump_with_validate(self):
        self.check_run(("ndrdump --validate samr samr_CreateUser in %s" %
                       (self.data_path("samr-CreateUser-in.dat"))))

    def test_ndrdump_with_hex_decode_function(self):
        self.check_run(
            ("ndrdump dns decode_dns_name_packet in --hex-input %s" %
                self.data_path("dns-decode_dns_name_packet-hex.dat")))

    def test_ndrdump_with_hex_struct_name(self):
        expected = open(self.data_path("dns-decode_dns_name_packet-hex.txt")).read()
        try:
            actual = self.check_output(
                "ndrdump dns dns_name_packet struct --hex-input %s" %
                self.data_path("dns-decode_dns_name_packet-hex.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_with_binary_struct_name(self):
        # Prefix of the expected unparsed PAC data (without times, as
        # these vary by host)
        expected = '''pull returned NT_STATUS_OK
    PAC_DATA: struct PAC_DATA
        num_buffers              : 0x00000005 (5)
        version                  : 0x00000000 (0)
        buffers: ARRAY(5)'''
        try:
            actual = self.check_output(
                "ndrdump krb5pac PAC_DATA struct %s" %
                self.data_path("krb5pac-PAC_DATA.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual[:len(expected)],
                         expected.encode('utf-8'))
        self.assertTrue(actual.endswith(b"dump OK\n"))

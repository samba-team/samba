# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

"""Tests for samba.samba3."""

from samba.samba3 import Registry
from samba.tests import TestCase
import os


for p in ["../../../../../testdata/samba3", "../../../../testdata/samba3"]:
    DATADIR = os.path.join(os.path.dirname(__file__), p)
    if os.path.exists(DATADIR):
        break


class RegistryTestCase(TestCase):

    def setUp(self):
        super(RegistryTestCase, self).setUp()
        self.registry = Registry(os.path.join(DATADIR, "registry"))

    def tearDown(self):
        self.registry.close()
        super(RegistryTestCase, self).tearDown()

    def test_length(self):
        self.assertEqual(28, len(self.registry))

    def test_keys(self):
        self.assertTrue(b"HKLM" in self.registry.keys())

    def test_subkeys(self):
        self.assertEqual([b"SOFTWARE", b"SYSTEM"], self.registry.subkeys(b"HKLM"))

    def test_values(self):
        self.assertEqual({b'DisplayName': (1, b'E\x00v\x00e\x00n\x00t\x00 \x00L\x00o\x00g\x00\x00\x00'),
                           b'ErrorControl': (4, b'\x01\x00\x00\x00')},
                          self.registry.values(b"HKLM/SYSTEM/CURRENTCONTROLSET/SERVICES/EVENTLOG"))

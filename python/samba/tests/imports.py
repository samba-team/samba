# Unix SMB/CIFS implementation. Tests for python imports
# Copyright (C) David Mulder <dmulder@samba.org> 2020
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
from samba.tests import TestCase

class PyImportsTestCase(TestCase):
    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

    def test_samdb_import(self):
        try:
            from samba import dsdb, dsdb_dns
            from samba import samdb
        except ImportError as e:
            self.fail('Failed to import samdb from samba: %s' % str(e))

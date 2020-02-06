# test generated python code from pidl
# Copyright (C) Andrew Tridgell August 2010
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
#
# to run this test, use one of these:
#
#    python -m unittest samba.tests.dcerpc.rpc_talloc
#
# or if you have trial installed (from twisted), use
#
#    trial samba.tests.dcerpc.rpc_talloc

"""Tests for the talloc handling in the generated Python DCE/RPC bindings."""

import sys

sys.path.insert(0, "bin/python")

import samba
import samba.tests
from samba.dcerpc import drsuapi
import talloc

talloc.enable_null_tracking()


class TallocTests(samba.tests.TestCase):
    '''test talloc behaviour of pidl generated python code'''

    def check_blocks(self, object, num_expected):
        '''check that the number of allocated blocks is correct'''
        nblocks = talloc.total_blocks(object)
        if object is None:
            nblocks -= self.initial_blocks
        self.assertEqual(nblocks, num_expected)

    def get_rodc_partial_attribute_set(self):
        '''get a list of attributes for RODC replication'''
        partial_attribute_set = drsuapi.DsPartialAttributeSet()

        # we expect one block for the object
        self.check_blocks(partial_attribute_set, 1)

        attids = [1, 2, 3]
        partial_attribute_set.version = 1
        partial_attribute_set.attids     = attids
        partial_attribute_set.num_attids = len(attids)

        # we expect one block for the object, a structure, and a
        # reference to the array
        self.check_blocks(partial_attribute_set, 2)

        return partial_attribute_set

    def pas_test(self):
        pas = self.get_rodc_partial_attribute_set()
        self.check_blocks(pas, 2)
        req8 = drsuapi.DsGetNCChangesRequest8()
        self.check_blocks(req8, 1)

        # We expect the pas and req8, plus one block for each python object
        self.check_blocks(None, 5)
        req8.partial_attribute_set = pas
        if req8.partial_attribute_set.attids[1] != 2:
            raise Exception("Wrong value in attids[2]")
        # we now get an additional reference
        self.check_blocks(None, 6)

    def test_run(self):
        self.initial_blocks = talloc.total_blocks(None)
        self.check_blocks(None, 0)
        self.pas_test()
        self.check_blocks(None, 0)

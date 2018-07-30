# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2016
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

"""Tests for array handling in PIDL generated bindings samba.dcerpc.*"""

from samba.dcerpc import drsblobs
import samba.tests
from samba.ndr import ndr_unpack, ndr_pack
import talloc
import gc


class ArrayTests(samba.tests.TestCase):

    def setUp(self):
        super(ArrayTests, self).setUp()
        talloc.enable_null_tracking()
        self.startup_blocks = talloc.total_blocks()

    def tearDown(self):
        super(ArrayTests, self).tearDown()
        gc.collect()
        if talloc.total_blocks() != self.startup_blocks:
            talloc.report_full()
            self.fail("it appears we are leaking memory")

    def test_array_from_python(self):
        rmd = drsblobs.replPropertyMetaDataBlob()

        rmd.version = 1
        rmd.ctr = drsblobs.replPropertyMetaDataCtr1()
        rmd.ctr.count = 3

        rmd1 = drsblobs.replPropertyMetaData1()
        rmd1.attid = 1
        rmd1.version = 2

        rmd2 = drsblobs.replPropertyMetaData1()
        rmd2.attid = 2
        rmd2.version = 2

        rmd3 = drsblobs.replPropertyMetaData1()
        rmd3.attid = 3
        rmd3.version = 2

        rmd.ctr.array = [rmd1, rmd2, rmd3]
        gc.collect()

        self.assertIsNotNone(rmd)
        self.assertEqual(rmd.version, 1)
        self.assertIsNotNone(rmd.ctr)
        self.assertEqual(rmd.ctr.count, 3)
        self.assertEqual(len(rmd.ctr.array), rmd.ctr.count)
        self.assertIsNotNone(rmd.ctr.array[0])
        self.assertEqual(rmd.ctr.array[0].attid, 1)

    def test_array_with_exception(self):
        try:
            rmd = drsblobs.replPropertyMetaDataBlob()

            rmd.version = 1
            rmd.ctr = drsblobs.replPropertyMetaDataCtr1()
            rmd.ctr.count = 3

            rmd1 = drsblobs.replPropertyMetaData1()
            rmd1.attid = 1
            rmd1.version = 2

            rmd2 = drsblobs.replPropertyMetaData1()
            rmd2.attid = 2
            rmd2.version = 2

            rmd3 = drsblobs.replPropertyMetaData1()
            rmd3.attid = 3
            rmd3.version = 2

            rmd.ctr.array = [rmd1, rmd2, rmd3]

            gc.collect()

            self.assertIsNotNone(rmd)
            self.assertEqual(rmd.version, 1)
            self.assertIsNotNone(rmd.ctr)
            self.assertEqual(rmd.ctr.count, 3)
            self.assertEqual(len(rmd.ctr.array), rmd.ctr.count)
            self.assertIsNotNone(rmd.ctr.array[0])
            self.assertEqual(rmd.ctr.array[0].attid, 1)

            raise Exception()
        except:
            pass

    def test_array_from_python_function(self):
        def get_rmd():
            rmd = drsblobs.replPropertyMetaDataBlob()

            rmd.version = 1
            rmd.ctr = drsblobs.replPropertyMetaDataCtr1()
            rmd.ctr.count = 3

            rmd1 = drsblobs.replPropertyMetaData1()
            rmd1.attid = 1
            rmd1.version = 2

            rmd2 = drsblobs.replPropertyMetaData1()
            rmd2.attid = 2
            rmd2.version = 2

            rmd3 = drsblobs.replPropertyMetaData1()
            rmd3.attid = 3
            rmd3.version = 2

            rmd.ctr.array = [rmd1, rmd2, rmd3]
            return rmd

        rmd = get_rmd()
        gc.collect()
        self.assertIsNotNone(rmd)
        self.assertEqual(rmd.version, 1)
        self.assertIsNotNone(rmd.ctr)
        self.assertEqual(rmd.ctr.count, 3)
        self.assertEqual(len(rmd.ctr.array), rmd.ctr.count)
        self.assertIsNotNone(rmd.ctr.array[0])
        self.assertEqual(rmd.ctr.array[0].attid, 1)

    def test_array_from_ndr(self):
        rmd = drsblobs.replPropertyMetaDataBlob()

        rmd.version = 1
        rmd.ctr = drsblobs.replPropertyMetaDataCtr1()
        rmd.ctr.count = 3

        rmd1 = drsblobs.replPropertyMetaData1()
        rmd1.attid = 1
        rmd1.version = 2

        rmd2 = drsblobs.replPropertyMetaData1()
        rmd2.attid = 2
        rmd2.version = 2

        rmd3 = drsblobs.replPropertyMetaData1()
        rmd3.attid = 3
        rmd3.version = 2

        rmd.ctr.array = [rmd1, rmd2, rmd3]

        packed = ndr_pack(rmd)
        gc.collect()

        rmd_unpacked = ndr_unpack(drsblobs.replPropertyMetaDataBlob, packed)
        self.assertIsNotNone(rmd_unpacked)
        self.assertEqual(rmd_unpacked.version, 1)
        self.assertIsNotNone(rmd_unpacked.ctr)
        self.assertEqual(rmd_unpacked.ctr.count, 3)
        self.assertEqual(len(rmd_unpacked.ctr.array), rmd_unpacked.ctr.count)
        self.assertIsNotNone(rmd_unpacked.ctr.array[0])
        self.assertEqual(rmd_unpacked.ctr.array[0].attid, 1)

        self.assertEqual(rmd.ctr.array[0].attid,
                         rmd_unpacked.ctr.array[0].attid)

    def test_array_delete(self):
        rmd = drsblobs.replPropertyMetaDataBlob()

        rmd.version = 1
        rmd.ctr = drsblobs.replPropertyMetaDataCtr1()
        rmd.ctr.count = 3

        rmd1 = drsblobs.replPropertyMetaData1()
        rmd1.attid = 1
        rmd1.version = 2

        rmd2 = drsblobs.replPropertyMetaData1()
        rmd2.attid = 2
        rmd2.version = 2

        rmd3 = drsblobs.replPropertyMetaData1()
        rmd3.attid = 3
        rmd3.version = 2

        rmd.ctr.array = [rmd1, rmd2, rmd3]
        try:
            del rmd1.version
            self.fail("succeeded in deleting rmd1.version")
        except AttributeError as e:
            pass

        try:
            del rmd.ctr.array
            self.fail("succeeded in deleting rmd.ctr.array")
        except AttributeError as e:
            pass

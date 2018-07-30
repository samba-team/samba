# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org>
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

from samba.tests import TestCaseInTempDir
from samba import param
import os

# the python bindings for LoadParm objects map (by default) to a single global
# object in the underlying C code. E.g. if we create 2 different LoadParm
# objects in python, really they're just the same object underneath.


class LoadParmTest(TestCaseInTempDir):

    def test_global_loadparm(self):
        # create 2 different Loadparm objects (which are really the same
        # object underneath)
        lp1 = param.LoadParm()
        lp2 = param.LoadParm()

        # we can prove this by setting a value on lp1 and assert that the
        # change is also reflected on lp2
        lp1_realm = "JUST.A.TEST"
        self.assertNotEqual(lp2.get('realm'), lp1_realm)
        lp1.set('realm', lp1_realm)
        self.assertEqual(lp1.get('realm'), lp1_realm)
        self.assertEqual(lp2.get('realm'), lp1_realm)

    def touch_temp_file(self, filename):
        filepath = os.path.join(self.tempdir, filename)
        open(filepath, 'a').close()
        # delete the file once the test completes
        self.addCleanup(os.remove, filepath)
        return filepath

    def test_non_global_loadparm(self):
        # create a empty smb.conf file
        smb_conf = self.touch_temp_file("smb.conf")

        # we can create a non-global Loadparm that overrides the default
        # behaviour and creates a separate underlying object
        lp1 = param.LoadParm()
        lp2 = param.LoadParm(filename_for_non_global_lp=smb_conf)

        # setting a value for the global LP does not affect the non-global LP
        lp1_realm = "JUST.A.TEST"
        self.assertNotEqual(lp2.get('realm'), lp1_realm)
        lp1.set('realm', lp1_realm)
        self.assertEqual(lp1.get('realm'), lp1_realm)
        self.assertNotEqual(lp2.get('realm'), lp1_realm)

        # and vice versa
        lp2_realm = "TEST.REALM.LP2"
        lp2.set('realm', lp2_realm)
        self.assertEqual(lp2.get('realm'), lp2_realm)
        self.assertEqual(lp1.get('realm'), lp1_realm)

    def test_non_global_loadparm_bad_path(self):
        non_existent_file = os.path.join(self.tempdir, 'not-there')

        # we can create a non-global Loadparm that overrides the default
        # behaviour and creates a separate underlying object
        self.assertRaises(ValueError,
                          param.LoadParm,
                          filename_for_non_global_lp=non_existent_file)

        # still shouldn't be there
        self.assertRaises(ValueError,
                          param.LoadParm,
                          non_existent_file)

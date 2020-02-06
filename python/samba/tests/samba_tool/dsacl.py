# Unix SMB/CIFS implementation.
# Copyright (C) Martin Kraemer 2019 <mk.maddin@gmail.com>
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

import os
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
import re

class DSaclSetSddlTestCase(SambaToolCmdTest):
    """Tests for samba-tool dsacl set --sddl subcommand"""
    sddl       = "(OA;CIIO;RPWP;aaaaaaaa-1111-bbbb-2222-dddddddddddd;33333333-eeee-4444-ffff-555555555555;PS)"
    sddl_lc    = "(OA;CIIO;RPWP;aaaaaaaa-1111-bbbb-2222-dddddddddddd;33333333-eeee-4444-ffff-555555555555;PS)"
    sddl_uc    = "(OA;CIIO;RPWP;AAAAAAAA-1111-BBBB-2222-DDDDDDDDDDDD;33333333-EEEE-4444-FFFF-555555555555;PS)"
    sddl_sid   = "(OA;CIIO;RPWP;aaaaaaaa-1111-bbbb-2222-dddddddddddd;33333333-eeee-4444-ffff-555555555555;S-1-5-10)"
    sddl_multi = "(OA;CIIO;RPWP;aaaaaaaa-1111-bbbb-2222-dddddddddddd;33333333-eeee-4444-ffff-555555555555;PS)(OA;CIIO;RPWP;cccccccc-9999-ffff-8888-eeeeeeeeeeee;77777777-dddd-6666-bbbb-555555555555;PS)"

    def setUp(self):
        super(DSaclSetSddlTestCase, self).setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],"-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.dn="OU=DSaclSetSddlTestCase,%s" % self.samdb.domain_dn()
        self.samdb.create_ou(self.dn)

    def tearDown(self):
        super(DSaclSetSddlTestCase, self).tearDown()
        # clean-up the created test ou
        self.samdb.delete(self.dn)

    def test_sddl(self):
        """Tests if a sddl string can be added 'the normal way'"""
        (result, out, err) = self.runsubcmd("dsacl", "set","--objectdn=%s" % self.dn, "--sddl=%s" % self.sddl)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        #extract only the two sddl strings from samba-tool output
        acl_list=re.findall('.*descriptor for.*:\n(.*?)\n',out)
        self.assertNotEqual(acl_list[0], acl_list[1], "new and old SDDL string differ")
        self.assertMatch(acl_list[1], self.sddl, "new SDDL string should be contained within second sddl output")

    def test_sddl_set_get(self):
        """Tests if a sddl string can be added 'the normal way' and the output of 'get' is the same"""
        (result, out, err) = self.runsubcmd("dsacl", "get",
                                            "--objectdn=%s" % self.dn)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        #extract only the two sddl strings from samba-tool output
        acl_list_get=re.findall('^descriptor for.*:\n(.*?)\n', out)

        (result, out, err) = self.runsubcmd("dsacl", "set",
                                            "--objectdn=%s" % self.dn,
                                            "--sddl=%s" % self.sddl)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        #extract only the two sddl strings from samba-tool output
        acl_list_old=re.findall('old descriptor for.*:\n(.*?)\n', out)
        self.assertEqual(acl_list_old, acl_list_get,
                         "output of dsacl get should be the same as before set")

        acl_list=re.findall('new descriptor for.*:\n(.*?)\n', out)

        (result, out, err) = self.runsubcmd("dsacl", "get",
                                            "--objectdn=%s" % self.dn)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        #extract only the two sddl strings from samba-tool output
        acl_list_get2=re.findall('^descriptor for.*:\n(.*?)\n', out)
        self.assertEqual(acl_list, acl_list_get2,
                         "output of dsacl get should be the same as after set")

    def test_multisddl(self):
        """Tests if we can add multiple, different sddl strings at the same time"""
        (result, out, err) = self.runsubcmd("dsacl", "set","--objectdn=%s" % self.dn, "--sddl=%s" % self.sddl_multi)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        #extract only the two sddl strings from samba-tool output
        acl_list=re.findall('.*descriptor for.*:\n(.*?)\n',out)
        for ace in re.findall('\(.*?\)',self.sddl_multi):
            self.assertMatch(acl_list[1], ace, "new SDDL string should be contained within second sddl output")

    def test_duplicatesddl(self):
        """Tests if an already existing sddl string can be added causing duplicate entry"""
        acl_list = self._double_sddl_check(self.sddl,self.sddl)
        self.assertEqual(acl_list[0],acl_list[1])

    def test_casesensitivesddl(self):
        """Tests if an already existing sddl string can be added in different cases causing duplicate entry"""
        acl_list = self._double_sddl_check(self.sddl_lc,self.sddl_uc)
        self.assertEqual(acl_list[0],acl_list[1])

    def test_sidsddl(self):
        """Tests if an already existing sddl string can be added with SID instead of SDDL SIDString causing duplicate entry"""
        acl_list = self._double_sddl_check(self.sddl,self.sddl_sid)
        self.assertEqual(acl_list[0],acl_list[1])

    def test_twosddl(self):
        """Tests if an already existing sddl string can be added by using it twice/in combination with non existing sddl string causing duplicate entry"""
        acl_list = self._double_sddl_check(self.sddl,self.sddl + self.sddl)
        self.assertEqual(acl_list[0],acl_list[1])

    def _double_sddl_check(self,sddl1,sddl2):
        """Adds two sddl strings and checks if there was an ace change after the second adding"""
        (result, out, err) = self.runsubcmd("dsacl", "set","--objectdn=%s" % self.dn, "--sddl=%s" % sddl1)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        acl_list = re.findall('.*descriptor for.*:\n(.*?)\n',out)
        self.assertMatch(acl_list[1], sddl1, "new SDDL string should be contained within second sddl output - is not")
        #add sddl2
        (result, out, err) = self.runsubcmd("dsacl", "set","--objectdn=%s" % self.dn, "--sddl=%s" % sddl2)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        acl_list = re.findall('.*descriptor for.*:\n(.*?)\n',out)
        return acl_list

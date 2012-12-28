# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett 2012
#
# Based on user.py:
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
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
import time
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
import random

class NtACLCmdSysvolTestCase(SambaToolCmdTest):
    """Tests for samba-tool ntacl sysvol* subcommands"""


    def test_ntvfs(self):
        (result, out, err) =  self.runsubcmd("ntacl", "sysvolreset",
                                             "--use-ntvfs")
        self.assertCmdSuccess(result)
        self.assertEquals(out,"","Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been changed, only the stored NT ACL", err)

    def test_s3fs(self):
        (result, out, err) =  self.runsubcmd("ntacl", "sysvolreset",
                                             "--use-s3fs")

        self.assertCmdSuccess(result)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertEquals(out,"","Shouldn't be any output messages")

    def test_ntvfs_check(self):
        (result, out, err) =  self.runsubcmd("ntacl", "sysvolreset",
                                             "--use-ntvfs")
        self.assertCmdSuccess(result)
        self.assertEquals(out,"","Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been changed, only the stored NT ACL", err)
        # Now check they were set correctly
        (result, out, err) =  self.runsubcmd("ntacl", "sysvolcheck")
        self.assertCmdSuccess(result)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertEquals(out,"","Shouldn't be any output messages")

    def test_s3fs_check(self):
        (result, out, err) =  self.runsubcmd("ntacl", "sysvolreset",
                                             "--use-s3fs")

        self.assertCmdSuccess(result)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertEquals(out,"","Shouldn't be any output messages")

        # Now check they were set correctly
        (result, out, err) =  self.runsubcmd("ntacl", "sysvolcheck")
        self.assertCmdSuccess(result)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertEquals(out,"","Shouldn't be any output messages")

class NtACLCmdGetSetTestCase(SambaToolCmdTest):
    """Tests for samba-tool ntacl get/set subcommands"""

    acl = "O:DAG:DUD:P(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;EA)(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;DA)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001200a9;;;ED)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"


    def test_ntvfs(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")

        (result, out, err) =  self.runsubcmd("ntacl", "set", self.acl, tempf,
                                             "--use-ntvfs")
        self.assertCmdSuccess(result)
        self.assertEquals(out,"","Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been changed, only the stored NT ACL", err)

    def test_s3fs(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")

        (result, out, err) =  self.runsubcmd("ntacl", "set", self.acl, tempf,
                                             "--use-s3fs")

        self.assertCmdSuccess(result)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertEquals(out,"","Shouldn't be any output messages")

    def test_ntvfs_check(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")

        (result, out, err) =  self.runsubcmd("ntacl", "set", self.acl, tempf,
                                             "--use-ntvfs")
        self.assertCmdSuccess(result)
        self.assertEquals(out,"","Shouldn't be any output messages")
        self.assertIn("Please note that POSIX permissions have NOT been changed, only the stored NT ACL", err)

        # Now check they were set correctly
        (result, out, err) =  self.runsubcmd("ntacl",  "get", tempf,
                                             "--use-ntvfs", "--as-sddl")
        self.assertCmdSuccess(result)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertEquals(self.acl+"\n", out, "Output should be the ACL")

    def test_s3fs_check(self):
        path = os.environ['SELFTEST_PREFIX']
        tempf = os.path.join(path,"pytests"+str(int(100000*random.random())))
        open(tempf, 'w').write("empty")

        (result, out, err) =  self.runsubcmd("ntacl", "set", self.acl, tempf,
                                             "--use-s3fs")
        self.assertCmdSuccess(result)
        self.assertEquals(out,"","Shouldn't be any output messages")
        self.assertEquals(err,"","Shouldn't be any error messages")

        # Now check they were set correctly
        (result, out, err) =  self.runsubcmd("ntacl",  "get", tempf,
                                             "--use-s3fs", "--as-sddl")
        self.assertCmdSuccess(result)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertEquals(self.acl+"\n", out,"Output should be the ACL")

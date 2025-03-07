# Unix SMB/CIFS implementation. Tests for ntacls manipulation
# Copyright (C) Matthieu Patou <mat@matws.net> 2009-2010
# Copyright (C) Andrew Bartlett 2012
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

"""Tests for samba.ntacls."""

import os

from samba.ntacls import setntacl, getntacl, XattrBackendError, dsacl2fsacl
from samba.param import LoadParm
from samba.dcerpc import security
from samba.tests import TestCaseInTempDir, SkipTest
from samba.auth_util import system_session_unix

NTACL_SDDL = "O:S-1-5-21-2212615479-2695158682-2101375467-512G:S-1-5-21-2212615479-2695158682-2101375467-513D:(A;OICI;FA;;;S-1-5-21-2212615479-2695158682-2101375467-512)"
DOMAIN_SID = "S-1-5-21-2212615479-2695158682-2101375467"


class NtaclsTests(TestCaseInTempDir):

    def setUp(self):
        super().setUp()
        self.tempf = os.path.join(self.tempdir, "test")
        open(self.tempf, 'w').write("empty")
        self.session_info = system_session_unix()

    def tearDown(self):
        os.unlink(self.tempf)
        super().tearDown()

    def test_setntacl(self):
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb", os.path.join(self.tempdir, "eadbtest.tdb"))
        setntacl(lp, self.tempf, NTACL_SDDL, DOMAIN_SID, self.session_info)
        os.unlink(os.path.join(self.tempdir, "eadbtest.tdb"))

    def test_setntacl_getntacl(self):
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb", os.path.join(self.tempdir, "eadbtest.tdb"))
        setntacl(lp, self.tempf, NTACL_SDDL, DOMAIN_SID, self.session_info)
        facl = getntacl(lp, self.tempf, self.session_info)
        anysid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(facl.as_sddl(anysid), NTACL_SDDL)
        os.unlink(os.path.join(self.tempdir, "eadbtest.tdb"))

    def test_setntacl_getntacl_param(self):
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        setntacl(lp, self.tempf, NTACL_SDDL, DOMAIN_SID, self.session_info, "tdb",
                 os.path.join(self.tempdir, "eadbtest.tdb"))
        facl = getntacl(lp, self.tempf, self.session_info, "tdb", os.path.join(
            self.tempdir, "eadbtest.tdb"))
        domsid = security.dom_sid(security.SID_NT_SELF)
        self.assertEqual(facl.as_sddl(domsid), NTACL_SDDL)
        os.unlink(os.path.join(self.tempdir, "eadbtest.tdb"))

    def test_setntacl_invalidbackend(self):
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        self.assertRaises(XattrBackendError, setntacl, lp, self.tempf,
                          NTACL_SDDL, DOMAIN_SID, self.session_info, "ttdb",
                          os.path.join(self.tempdir, "eadbtest.tdb"))

    def test_setntacl_forcenative(self):
        if os.getuid() == 0:
            raise SkipTest("Running test as root, test skipped")
        lp = LoadParm()
        open(self.tempf, 'w').write("empty")
        lp.set("posix:eadb", os.path.join(self.tempdir, "eadbtest.tdb"))
        self.assertRaises(PermissionError, setntacl, lp, self.tempf, NTACL_SDDL,
                          DOMAIN_SID, self.session_info, "native")

    def test_dsacl2fsacl(self):
        for comment, dssddl, sid, as_sddl, expected in (
                ("simple ACE should be unchanged",
                 'O:BAD:(A;OICI;;;;WD)',
                 DOMAIN_SID, True,
                 'O:BAD:(A;OICI;;;;WD)'),
                ("simple ACE, unchanged, without SDDL conversion",
                 'O:BAD:(A;OICI;;;;WD)',
                 DOMAIN_SID, False,
                 'O:BAD:(A;OICI;;;;WD)'),
                ("simple ACE with DS mask",
                 'O:BAD:(A;;CR;;;WD)',
                 DOMAIN_SID, True,
                 'O:BAD:(A;OICI;;;;WD)'),
                ("simple ACE with no mask without SDDL conversion",
                 'O:BAD:(A;;;;;WD)',
                 DOMAIN_SID, False,
                 'O:BAD:(A;OICI;;;;WD)'),

                ("simple deny ACE should be unchanged",
                 'O:BAD:(D;OICI;;;;WD)',
                 DOMAIN_SID, True,
                 'O:BAD:(D;OICI;;;;WD)'),
                ("simple deny ACE, unchanged, without SDDL conversion",
                 'O:BAD:(D;OICI;;;;WD)',
                 DOMAIN_SID, False,
                 'O:BAD:(D;OICI;;;;WD)'),
                ("simple deny ACE with DS mask",
                 'O:BAD:(D;;CR;;;WD)',
                 DOMAIN_SID, True,
                 'O:BAD:(D;OICI;;;;WD)'),
                ("simple deny ACE with no mask without SDDL conversion",
                 'O:BAD:(D;;;;;WD)',
                 DOMAIN_SID, False,
                 'O:BAD:(D;OICI;;;;WD)'),
                ("simple ACE with fancy mask",
                 'O:BAD:(A;NPIOIDSA;;;;WD)',
                 DOMAIN_SID, False,
                 'O:BAD:(A;OICINPIOIDSA;;;;WD)'),
                ("simple ACE with different domain SID and GR mask",
                 'O:BAD:(A;;GR;;;WD)',
                 "S-1-2-3-4-5", False,
                 'O:BAD:(A;OICI;;;;WD)'),
                ("compound ACL, allow only",
                 "O:LAG:BAD:P(A;OICI;FA;;;BA)"
                 "(A;OICI;0x1200a9;;;SO)(A;OICI;FA;;;SY)"
                 "(A;OICI;0x1200a9;;;AU)(A;OICI;0x1301bf;;;PA)",
                 DOMAIN_SID, True,
                 "O:LAG:BAD:P(A;OICI;FA;;;BA)"
                 "(A;OICI;FW;;;SO)(A;OICI;FA;;;SY)"
                 "(A;OICI;FW;;;AU)(A;OICI;0x1301ff;;;PA)"),
                ("compound ACL with object ACES",
                 "D:(OD;;CR;00299570-246d-11d0-a768-00aa006e0529;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDD"
                 "TSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;"
                 "SY)(A;;RPCRLCLORCSDDT;;;CO)(OD;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(O"
                 "A;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5"
                 "-0000f80367c1;;CO)",
                 DOMAIN_SID, True,
                 "D:(A;OICI;FA;;;DA)(A;OICI;FA;;;AO)(A;OICI;FA;;;SY)(A;OICIIO;0x1300a9;;;CO)"),
        ):
            domsid = security.dom_sid(sid)
            result = dsacl2fsacl(dssddl, domsid, as_sddl=as_sddl)
            if as_sddl:
                self.assertIsInstance(result, str,
                                      f"expected sddl in '{comment}' test")
            else:
                self.assertNotIsInstance(result, str,
                                         f"did not expect sddl in '{comment}' test")
                # convert to SDDL to compare the result
                result = result.as_sddl(domsid)

            self.assertEqual(result, expected)

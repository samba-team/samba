# Unix SMB/CIFS implementation.
# Copyright (C) 2026 CTERA Networks
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
# Integration test: SYSTEM_RESOURCE_ATTRIBUTE_ACE round-trip over SMB.
#
# This test sets a SACL containing a SYSTEM_RESOURCE_ATTRIBUTE_ACE on a file
# hosted by a share that uses the acl_xattr VFS module (e.g. the "tmp" share
# in the fileserver test environment), then reads the ACE back via SMB and
# verifies it survives the round-trip intact.
#
# Before Samba 4.19, i.e. when Samba learned about claims and
# conditions, when a client sent an ACE with
# SYSTEM_RESOURCE_ATTRIBUTE_ACE Samba threw away the blob in
# ndr_pull_security_ace():
#
#     pad = r->size - size;
#     NDR_PULL_NEED_BYTES(ndr, pad);
#     ndr->offset += pad;
#
# This test shows that we don't drop the SACL anymore

import os
from samba.dcerpc import security
from samba.samba3 import libsmb_samba_internal as libsmb
from samba import NTSTATUSError
import samba.tests
import samba.tests.libsmb
from samba.tests import BlackboxTestCase


class NtaclResourceAttrAceTests(samba.tests.libsmb.LibsmbTests):
    """Round-trip test for SYSTEM_RESOURCE_ATTRIBUTE_ACE over SMB."""

    def setUp(self):
        super().setUp()
        self.share = samba.tests.env_get_var_value("SHARE",
                                                   allow_missing=True) or "tmp"

        # Use a user with SeSecurityPrivilege, so that we can set a
        # SACL
        self.creds.set_username("systemuser")
        self.creds.set_password("ag67aca0wcbhritu1")

        self.conn = libsmb.Conn(
            self.server_ip,
            self.share,
            self.lp,
            self.creds,
        )
        self.test_file = "ntacl_resource_attr_ace_test.txt"
        # Ensure a clean slate.
        try:
            self.conn.unlink(self.test_file)
        except NTSTATUSError:
            pass
        self.conn.savefile(self.test_file, b"")

    def tearDown(self):
        try:
            self.conn.unlink(self.test_file)
        except NTSTATUSError:
            pass
        super().tearDown()

    def test_resource_attr_ace_round_trip(self):
        """Set a SYSTEM_RESOURCE_ATTRIBUTE_ACE and verify it survives SMB.

        SDDL: S:(RA;;;;;WD;("Secret",TU,0,42))
          - SACL-only security descriptor
          - One SYSTEM_RESOURCE_ATTRIBUTE_ACE (type 0x12)
          - Trustee: World (S-1-1-0)
          - Attribute: name="Secret", value_type=TU (unsigned 64-bit), value=42

        The test requires that the connecting user holds SeSecurityPrivilege
        (typically true for Administrator in the fileserver test environment).
        """
        # Any domain_sid is fine here; SACL RA ACEs use absolute SIDs.
        domain_sid = security.dom_sid("S-1-5-21-0-0-0-0")
        sddl = 'D:(A;;FA;;;SY)S:(RA;;;;;WD;("Secret",TU,0,42))'
        sd_in = security.descriptor.from_sddl(sddl, domain_sid)

        # Set the SACL.  The wrapper computes the required access mask
        # (SEC_FLAG_SYSTEM_SECURITY) automatically from the sinfo flags.
        self.conn.set_acl(self.test_file, sd_in, security.SECINFO_SACL|security.SECINFO_DACL)

        # Assert we don't lose anything
        sd_out = self.conn.get_acl(self.test_file, security.SECINFO_SACL|security.SECINFO_DACL)
        self.assertEqual(sd_out.as_sddl(), 'D:(A;;FA;;;SY)S:(RA;;;;;WD;("Secret",TU,0x0,+42))')

class NtaclCheckBrokenXattr(BlackboxTestCase):
    def test_broken_4_18_sd(self):
        """Test that we can ndr-parse a broken ACL written by Samba before 4.19
        """
        try:
            self.check_run("ndrdump --input=BAAEAAAAAgAEAAIAAQDTUqgmaU3l3XQ" \
                           "iIvhobT/RmQ8qA1P4Ao5OARKbhEkaqQAAAAAAAAAAAAAAAA" \
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAcG9zaXhfYWNsAG6gQRFE7" \
                           "9wBuX0c98dZv+qO/cof92D0EaIkn1cf3JUJ8jckslpjE5IA" \
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAFIC" \
                           "0AAAA0AAAAOwAAAAIAQAAAQUAAAAAAAUVAAAAGzK0UbnSA4" \
                           "sRk/P16AMAAAEFAAAAAAAFFQAAABsytFG50gOLEZPz9QECA" \
                           "AAEABwAAQAAABIAFAAAAAAAAQEAAAAAAAEAAAAABAAcAAEA" \
                           "AAAAABQA/wEfAAEBAAAAAAAFEgAAAA== " \
                           "--base64-input xattr xattr_NTACL struct")
        except:
            self.fail()

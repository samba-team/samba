#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Samuel Cabrero 2021
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

import sys
import os
import pwd
import ctypes

from samba.tests import env_get_var_value
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param
from samba import NTSTATUSError, ntstatus

from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.credentials import MUST_USE_KERBEROS, DONT_USE_KERBEROS

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

class SmbMinDomainUid(KDCBaseTest):
    """Test for SMB authorization without NSS winbind. In such setup domain
       accounts are mapped to local accounts using the 'username map' option.
    """

    def setUp(self):
        super(KDCBaseTest, self).setUp()

        # Create a user account, along with a Kerberos credentials cache file
        # where the service ticket authenticating the user are stored.
        self.samdb = self.get_samdb()

        self.mach_name = env_get_var_value('SERVER')
        self.user_name = "root"
        self.service = "cifs"
        self.share = "tmp"

        # Create the user account.
        (self.user_creds, _) = self.create_account(self.samdb, self.user_name)

        # Build the global inject file path
        server_conf = env_get_var_value('SMB_CONF_PATH')
        server_conf_dir = os.path.dirname(server_conf)
        self.global_inject = os.path.join(server_conf_dir, "global_inject.conf")

    def _test_min_uid(self, creds):
        # Assert unix root uid is less than 'idmap config ADDOMAIN' minimum
        s3_lp = s3param.get_context()
        s3_lp.load(self.get_lp().configfile)

        domain_range = s3_lp.get("idmap config * : range").split('-')
        domain_range_low = int(domain_range[0])
        unix_root_pw = pwd.getpwnam(self.user_name)
        self.assertLess(unix_root_pw.pw_uid, domain_range_low)
        self.assertLess(unix_root_pw.pw_gid, domain_range_low)

        conn = libsmb.Conn(self.mach_name, self.share, lp=s3_lp, creds=creds)
        # Disconnect
        conn = None

        # Restrict access to local root account uid
        with open(self.global_inject, 'w') as f:
            f.write("min domain uid = %s\n" % (unix_root_pw.pw_uid + 1))

        with self.assertRaises(NTSTATUSError) as cm:
            conn = libsmb.Conn(self.mach_name,
                               self.share,
                               lp=s3_lp,
                               creds=creds)
        code = ctypes.c_uint32(cm.exception.args[0]).value
        self.assertEqual(code, ntstatus.NT_STATUS_INVALID_TOKEN)

        # check that the local root account uid is now allowed
        with open(self.global_inject, 'w') as f:
            f.write("min domain uid = %s\n" % unix_root_pw.pw_uid)

        conn = libsmb.Conn(self.mach_name, self.share, lp=s3_lp, creds=creds)
        # Disconnect
        conn = None

        with open(self.global_inject, 'w') as f:
            f.truncate()

    def test_min_domain_uid_krb5(self):
        krb5_state = self.user_creds.get_kerberos_state()
        self.user_creds.set_kerberos_state(MUST_USE_KERBEROS)
        ret = self._test_min_uid(self.user_creds)
        self.user_creds.set_kerberos_state(krb5_state)
        return ret

    def test_min_domain_uid_ntlmssp(self):
        krb5_state = self.user_creds.get_kerberos_state()
        self.user_creds.set_kerberos_state(DONT_USE_KERBEROS)
        ret = self._test_min_uid(self.user_creds)
        self.user_creds.set_kerberos_state(krb5_state)
        return ret

    def tearDown(self):
        # Ensure no leftovers in global inject file
        with open(self.global_inject, 'w') as f:
            f.truncate()

        super(KDCBaseTest, self).tearDown()

if __name__ == "__main__":
    import unittest
    unittest.main()

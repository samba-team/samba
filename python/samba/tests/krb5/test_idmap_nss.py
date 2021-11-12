#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2021 Catalyst.Net Ltd
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

from ldb import SCOPE_SUBTREE
from samba import NTSTATUSError
from samba.credentials import DONT_USE_KERBEROS
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.ntstatus import (
    NT_STATUS_NO_IMPERSONATION_TOKEN,
    NT_STATUS_LOGON_FAILURE
)
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param

from samba.tests.krb5.kdc_base_test import KDCBaseTest

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

global_asn1_print = False
global_hexdump = False


class IdmapNssTests(KDCBaseTest):

    mappeduser_uid = 0xffff - 14
    mappeduser_sid = security.dom_sid(f'S-1-22-1-{mappeduser_uid}')
    unmappeduser_uid = 0xffff - 15
    unmappeduser_sid = security.dom_sid(f'S-1-22-1-{unmappeduser_uid}')

    def get_mapped_creds(self,
                         allow_missing_password=False,
                         allow_missing_keys=True):
        c = self._get_krb5_creds(prefix='MAPPED',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys)
        c.set_workstation('')
        return c

    def get_unmapped_creds(self,
                           allow_missing_password=False,
                           allow_missing_keys=True):
        c = self._get_krb5_creds(prefix='UNMAPPED',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys)
        c.set_workstation('')
        return c

    def get_invalid_creds(self,
                          allow_missing_password=False,
                          allow_missing_keys=True):
        c = self._get_krb5_creds(prefix='INVALID',
                                 allow_missing_password=allow_missing_password,
                                 allow_missing_keys=allow_missing_keys)
        c.set_workstation('')
        return c

    # Expect a mapping to the local user SID.
    def test_mapped_user_kerberos(self):
        user_creds = self.get_mapped_creds()
        self._run_idmap_nss_test(user_creds, use_kerberos=True,
                                 expected_first_sid=self.mappeduser_sid,
                                 expected_uid=self.mappeduser_uid)

    # Expect a mapping to the local user SID.
    def test_mapped_user_ntlm(self):
        user_creds = self.get_mapped_creds()
        self._run_idmap_nss_test(user_creds, use_kerberos=False,
                                 expected_first_sid=self.mappeduser_sid,
                                 expected_uid=self.mappeduser_uid)

    def test_mapped_user_no_pac_kerberos(self):
        user_creds = self.get_mapped_creds()
        self._run_idmap_nss_test(
            user_creds, use_kerberos=True, remove_pac=True,
            expected_error=NT_STATUS_NO_IMPERSONATION_TOKEN)

    def test_unmapped_user_kerberos(self):
        user_creds = self.get_unmapped_creds()
        self._run_idmap_nss_test(user_creds, use_kerberos=True,
                                 expected_additional_sid=self.unmappeduser_sid,
                                 expected_uid=self.unmappeduser_uid)

    def test_unmapped_user_ntlm(self):
        user_creds = self.get_unmapped_creds()
        self._run_idmap_nss_test(user_creds, use_kerberos=False,
                                 expected_additional_sid=self.unmappeduser_sid,
                                 expected_uid=self.unmappeduser_uid)

    def test_unmapped_user_no_pac_kerberos(self):
        user_creds = self.get_unmapped_creds()
        self._run_idmap_nss_test(
            user_creds, use_kerberos=True, remove_pac=True,
            expected_error=NT_STATUS_NO_IMPERSONATION_TOKEN)

    def test_invalid_user_kerberos(self):
        user_creds = self.get_invalid_creds()
        self._run_idmap_nss_test(user_creds, use_kerberos=True,
                                 expected_error=NT_STATUS_LOGON_FAILURE)

    def test_invalid_user_ntlm(self):
        user_creds = self.get_invalid_creds()
        self._run_idmap_nss_test(user_creds, use_kerberos=False,
                                 expected_error=NT_STATUS_LOGON_FAILURE)

    def test_invalid_user_no_pac_kerberos(self):
        user_creds = self.get_invalid_creds()
        self._run_idmap_nss_test(
            user_creds, use_kerberos=True, remove_pac=True,
            expected_error=NT_STATUS_NO_IMPERSONATION_TOKEN)

    def _run_idmap_nss_test(self, user_creds,
                            use_kerberos,
                            remove_pac=False,
                            expected_error=None,
                            expected_first_sid=None,
                            expected_additional_sid=None,
                            expected_uid=None):
        if expected_first_sid is not None:
            self.assertIsNotNone(expected_uid)
        if expected_additional_sid is not None:
            self.assertIsNotNone(expected_uid)
        if expected_uid is not None:
            self.assertIsNone(expected_error)

        if not use_kerberos:
            self.assertFalse(remove_pac)

        samdb = self.get_samdb()

        server_name = self.host
        service = 'cifs'
        share = 'tmp'

        server_creds = self.get_server_creds()

        if expected_first_sid is None:
            # Retrieve the user account's SID.
            user_name = user_creds.get_username()
            res = samdb.search(scope=SCOPE_SUBTREE,
                               expression=f'(sAMAccountName={user_name})',
                               attrs=['objectSid'])
            self.assertEqual(1, len(res))

            expected_first_sid = ndr_unpack(security.dom_sid,
                                      res[0].get('objectSid', idx=0))

        if use_kerberos:
            # Talk to the KDC to obtain the service ticket, which gets placed
            # into the cache. The machine account name has to match the name in
            # the ticket, to ensure that the krbtgt ticket doesn't also need to
            # be stored.
            creds, cachefile = self.create_ccache_with_user(
                user_creds,
                server_creds,
                service,
                server_name,
                pac=not remove_pac)

            # Remove the cached creds file.
            self.addCleanup(os.remove, cachefile.name)

            # Set the Kerberos 5 creds cache environment variable. This is
            # required because the codepath that gets run (gse_krb5) looks for
            # it in here and not in the creds object.
            krb5_ccname = os.environ.get('KRB5CCNAME', '')
            self.addCleanup(os.environ.__setitem__, 'KRB5CCNAME', krb5_ccname)
            os.environ['KRB5CCNAME'] = 'FILE:' + cachefile.name
        else:
            creds = user_creds
            creds.set_kerberos_state(DONT_USE_KERBEROS)

        # Connect to a share and retrieve the user SID.
        s3_lp = s3param.get_context()
        s3_lp.load(self.get_lp().configfile)

        min_protocol = s3_lp.get('client min protocol')
        self.addCleanup(s3_lp.set, 'client min protocol', min_protocol)
        s3_lp.set('client min protocol', 'NT1')

        max_protocol = s3_lp.get('client max protocol')
        self.addCleanup(s3_lp.set, 'client max protocol', max_protocol)
        s3_lp.set('client max protocol', 'NT1')

        try:
            conn = libsmb.Conn(server_name, share, lp=s3_lp, creds=creds)
        except NTSTATUSError as e:
            enum, _ = e.args
            self.assertEqual(expected_error, enum)
            return
        else:
            self.assertIsNone(expected_error)

        uid, gid, gids, sids, guest = conn.posix_whoami()

        # Ensure that they match.
        self.assertEqual(expected_first_sid, sids[0])
        self.assertNotIn(expected_first_sid, sids[1:-1])

        if expected_additional_sid:
            self.assertNotEqual(expected_additional_sid, sids[0])
            self.assertIn(expected_additional_sid, sids)

        self.assertIsNotNone(expected_uid)
        self.assertEqual(expected_uid, uid)


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()

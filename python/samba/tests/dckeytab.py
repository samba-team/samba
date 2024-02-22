# Tests for source4/libnet/py_net_dckeytab.c
#
# Copyright (C) David Mulder <dmulder@suse.com> 2018
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
import sys
import string
from samba.net import Net
from samba import enable_net_export_keytab

from samba import credentials, tests
from samba.dcerpc import krb5ccache, security
from samba.dsdb import UF_WORKSTATION_TRUST_ACCOUNT
from samba.ndr import ndr_unpack, ndr_pack
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.tests import TestCaseInTempDir, delete_force

from ldb import SCOPE_BASE

enable_net_export_keytab()


class DCKeytabTests(TestCaseInTempDir):
    def setUp(self):
        super().setUp()
        self.lp = LoadParm()
        self.lp.load_default()
        self.creds = self.insta_creds(template=self.get_credentials())
        self.samdb = SamDB(url=f"ldap://{os.environ.get('SERVER')}",
                           credentials=self.creds,
                           lp=self.lp)

        self.ktfile = os.path.join(self.tempdir, 'test.keytab')
        self.principal = self.creds.get_principal()

    def tearDown(self):
        super().tearDown()

    def test_export_keytab(self):
        net = Net(None, self.lp)
        net.export_keytab(keytab=self.ktfile, principal=self.principal)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_bytes = bytes_kt.read()

        self.rm_files('test.keytab')

        keytab = ndr_unpack(krb5ccache.KEYTAB, keytab_bytes)

        # Confirm that the principal is as expected

        principal_parts = self.principal.split('@')

        self.assertEqual(keytab.entry.principal.component_count, 1)
        self.assertEqual(keytab.entry.principal.realm, principal_parts[1])
        self.assertEqual(keytab.entry.principal.components[0], principal_parts[0])

    def test_export_keytab_gmsa(self):

        # Create gMSA account
        gmsa_username = "GMSA_K5KeytabTest$"
        gmsa_principal = f"{gmsa_username}@{self.samdb.domain_dns_name().upper()}"
        gmsa_base_dn = f"CN=Managed Service Accounts,{self.samdb.domain_dn()}"
        gmsa_user_dn = f"CN={gmsa_username},{gmsa_base_dn}"

        msg = self.samdb.search(base="", scope=SCOPE_BASE, attrs=["tokenGroups"])[0]
        connecting_user_sid = str(ndr_unpack(security.dom_sid, msg["tokenGroups"][0]))

        domain_sid = security.dom_sid(self.samdb.get_domain_sid())
        allow_sddl = f"O:SYD:(A;;RP;;;{connecting_user_sid})"
        allow_sd = ndr_pack(security.descriptor.from_sddl(allow_sddl, domain_sid))

        details = {
            "dn": str(gmsa_user_dn),
            "objectClass": "msDS-GroupManagedServiceAccount",
            "msDS-ManagedPasswordInterval": "1",
            "msDS-GroupMSAMembership": allow_sd,
            "sAMAccountName": gmsa_username,
            "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT),
        }

        delete_force(self.samdb, gmsa_user_dn)
        self.samdb.add(details)
        self.addCleanup(delete_force, self.samdb, gmsa_user_dn)

        # Export keytab of gMSA account remotely
        net = Net(None, self.lp)
        try:
            net.export_keytab(samdb=self.samdb, keytab=self.ktfile, principal=gmsa_principal)
        except RuntimeError as e:
            self.fail(e)

        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_bytes = bytes_kt.read()

        remote_keytab = ndr_unpack(krb5ccache.KEYTAB, keytab_bytes)

        self.rm_files('test.keytab')

        # Export keytab of gMSA account locally
        try:
            net.export_keytab(keytab=self.ktfile, principal=gmsa_principal)
        except RuntimeError as e:
            self.fail(e)

        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_bytes = bytes_kt.read()

        self.rm_files('test.keytab')

        local_keytab = ndr_unpack(krb5ccache.KEYTAB, keytab_bytes)

        # Confirm that the principal is as expected

        principal_parts = gmsa_principal.split('@')

        self.assertEqual(local_keytab.entry.principal.component_count, 1)
        self.assertEqual(local_keytab.entry.principal.realm, principal_parts[1])
        self.assertEqual(local_keytab.entry.principal.components[0], principal_parts[0])

        self.assertEqual(remote_keytab.entry.principal.component_count, 1)
        self.assertEqual(remote_keytab.entry.principal.realm, principal_parts[1])
        self.assertEqual(remote_keytab.entry.principal.components[0], principal_parts[0])

        # Put all keys from each into a dictionary, and confirm all remote keys are in local keytab

        remote_keys = {}

        while True:
            remote_keys[remote_keytab.entry.enctype] = remote_keytab.entry.key.data
            keytab_bytes = remote_keytab.further_entry
            if not keytab_bytes:
                break

            remote_keytab = ndr_unpack(krb5ccache.MULTIPLE_KEYTAB_ENTRIES, keytab_bytes)

        local_keys = {}

        while True:
            local_keys[local_keytab.entry.enctype] = local_keytab.entry.key.data
            keytab_bytes = local_keytab.further_entry
            if keytab_bytes is None or len(keytab_bytes) == 0:
                break
            local_keytab = ndr_unpack(krb5ccache.MULTIPLE_KEYTAB_ENTRIES, keytab_bytes)

        # Check that the gMSA keys are in the local keys
        remote_enctypes = set(remote_keys.keys())

        # Check that at least the AES keys were generated
        self.assertLessEqual(set(credentials.ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                                 credentials.ENCTYPE_AES128_CTS_HMAC_SHA1_96),
                             remote_enctypes)

        local_enctypes = set(local_keys.keys())

        self.assertLessEqual(remote_enctypes, local_enctypes)

        common_enctypes = remote_enctypes & local_enctypes

        for enctype in common_enctypes:
            self.assertEqual(remote_keys[enctype], local_keys[enctype])

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

from samba import credentials, dsdb, ntstatus, NTSTATUSError, tests
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

    def keytab_as_set(self, keytab_bytes):
        def entry_to_tuple(entry):
            principal = '/'.join(entry.principal.components) + f"@{entry.principal.realm}"
            enctype = entry.enctype
            kvno = entry.key_version
            key = tuple(entry.key.data)
            return (principal, enctype, kvno, key)

        keytab = ndr_unpack(krb5ccache.KEYTAB, keytab_bytes)
        entry = keytab.entry

        keytab_as_set = set()

        entry_as_tuple = entry_to_tuple(entry)
        keytab_as_set.add(entry_as_tuple)

        keytab_bytes = keytab.further_entry
        while True:
            multiple_entry = ndr_unpack(krb5ccache.MULTIPLE_KEYTAB_ENTRIES, keytab_bytes)
            entry = multiple_entry.entry
            entry_as_tuple = entry_to_tuple(entry)
            self.assertNotIn(entry_as_tuple, keytab_as_set)
            keytab_as_set.add(entry_as_tuple)

            keytab_bytes = multiple_entry.further_entry
            if not keytab_bytes:
                break

        return keytab_as_set

    def test_export_keytab(self):
        net = Net(None, self.lp)
        self.addCleanup(self.rm_files, self.ktfile)
        net.export_keytab(keytab=self.ktfile, principal=self.principal)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_bytes = bytes_kt.read()

        # confirm only this principal was exported
        for entry in self.keytab_as_set(keytab_bytes):
            (principal, enctype, kvno, key) = entry
            self.assertEqual(principal, self.principal)

    def test_export_keytab_all(self):
        net = Net(None, self.lp)
        self.addCleanup(self.rm_files, self.ktfile)
        net.export_keytab(keytab=self.ktfile)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_bytes = bytes_kt.read()

        # Parse the keytab
        keytab_as_set = self.keytab_as_set(keytab_bytes)

        # confirm many principals were exported
        self.assertGreater(len(keytab_as_set), 10)

    def test_export_keytab_all_keep_stale(self):
        net = Net(None, self.lp)
        self.addCleanup(self.rm_files, self.ktfile)
        net.export_keytab(keytab=self.ktfile)

        new_principal=f"keytab_testuser@{self.creds.get_realm()}"
        self.samdb.newuser("keytab_testuser", "4rfvBGT%")
        self.addCleanup(self.samdb.deleteuser, "keytab_testuser")

        net.export_keytab(keytab=self.ktfile, keep_stale_entries=True)

        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_bytes = bytes_kt.read()

        # confirm many principals were exported
        # self.keytab_as_set() will also check we only got it
        # each entry once
        keytab_as_set = self.keytab_as_set(keytab_bytes)

        self.assertGreater(len(keytab_as_set), 10)

        # Look for the new principal, showing this was updated
        found = False
        for entry in keytab_as_set:
            (principal, enctype, kvno, key) = entry
            if principal == new_principal:
                found = True

        self.assertTrue(found)

    def test_export_keytab_nochange_update(self):
        new_principal=f"keytab_testuser@{self.creds.get_realm()}"
        self.samdb.newuser("keytab_testuser", "4rfvBGT%")
        self.addCleanup(self.samdb.deleteuser, "keytab_testuser")

        net = Net(None, self.lp)
        self.addCleanup(self.rm_files, self.ktfile)
        net.export_keytab(keytab=self.ktfile, principal=new_principal)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_orig_bytes = bytes_kt.read()

        net.export_keytab(keytab=self.ktfile, principal=new_principal)

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_bytes = bytes_kt.read()

        self.assertEqual(keytab_orig_bytes, keytab_bytes)

        # confirm only this principal was exported.
        # self.keytab_as_set() will also check we only got it
        # once
        for entry in self.keytab_as_set(keytab_bytes):
            (principal, enctype, kvno, key) = entry
            self.assertEqual(principal, new_principal)

    def test_export_keytab_change_update(self):
        new_principal=f"keytab_testuser@{self.creds.get_realm()}"
        self.samdb.newuser("keytab_testuser", "4rfvBGT%")
        self.addCleanup(self.samdb.deleteuser, "keytab_testuser")

        net = Net(None, self.lp)
        self.addCleanup(self.rm_files, self.ktfile)
        net.export_keytab(keytab=self.ktfile, principal=new_principal)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_orig_bytes = bytes_kt.read()

        self.samdb.setpassword(f"(userPrincipalName={new_principal})", "5rfvBGT%")

        net.export_keytab(keytab=self.ktfile, principal=new_principal)

        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_change_bytes = bytes_kt.read()

        self.assertNotEqual(keytab_orig_bytes, keytab_change_bytes)

        # We can't parse it as the parser is simple and doesn't
        # understand holes in the file.

    def test_export_keytab_change2_update(self):
        new_principal=f"keytab_testuser@{self.creds.get_realm()}"
        self.samdb.newuser("keytab_testuser", "4rfvBGT%")
        self.addCleanup(self.samdb.deleteuser, "keytab_testuser")

        net = Net(None, self.lp)
        self.addCleanup(self.rm_files, self.ktfile)
        net.export_keytab(keytab=self.ktfile, principal=new_principal)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_orig_bytes = bytes_kt.read()

        # intended to trigger the pruning code for old keys
        self.samdb.setpassword(f"(userPrincipalName={new_principal})", "5rfvBGT%")
        self.samdb.setpassword(f"(userPrincipalName={new_principal})", "6rfvBGT%")

        net.export_keytab(keytab=self.ktfile, principal=new_principal)

        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_change_bytes = bytes_kt.read()

        self.assertNotEqual(keytab_orig_bytes, keytab_change_bytes)

        # We can't parse it as the parser is simple and doesn't
        # understand holes in the file.

    def test_export_keytab_change3_update_keep(self):
        new_principal=f"keytab_testuser@{self.creds.get_realm()}"
        self.samdb.newuser("keytab_testuser", "4rfvBGT%")
        self.addCleanup(self.samdb.deleteuser, "keytab_testuser")
        net = Net(None, self.lp)
        self.addCleanup(self.rm_files, self.ktfile)
        net.export_keytab(keytab=self.ktfile, principal=new_principal)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_orig_bytes = bytes_kt.read()

        # By changing the password three times, we allow Samba to fill
        # out current, old, older from supplementalCredentials and
        # still have one password that must still be from the original
        # keytab
        self.samdb.setpassword(f"(userPrincipalName={new_principal})", "5rfvBGT%")
        self.samdb.setpassword(f"(userPrincipalName={new_principal})", "6rfvBGT%")
        self.samdb.setpassword(f"(userPrincipalName={new_principal})", "6rfvBGT%")

        net.export_keytab(keytab=self.ktfile, principal=new_principal, keep_stale_entries=True)

        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_change_bytes = bytes_kt.read()

        self.assertNotEqual(keytab_orig_bytes, keytab_change_bytes)

        # self.keytab_as_set() will also check we got each entry
        # exactly once
        keytab_as_set = self.keytab_as_set(keytab_change_bytes)

        # Look for the new principal, showing this was updated but the old kept
        found = 0
        for entry in keytab_as_set:
            (principal, enctype, kvno, key) = entry
            if principal == new_principal and enctype == credentials.ENCTYPE_AES128_CTS_HMAC_SHA1_96:
                found += 1

        # Samba currently does not export the previous keys into the keytab, but could.
        self.assertEqual(found, 4)

        # confirm at least 12 keys (4 changes, 1 in orig export and 3
        # history in 2nd export, 3 enctypes) were exported
        self.assertGreaterEqual(len(keytab_as_set), 12)

    def test_export_keytab_change2_export2_update_keep(self):
        new_principal=f"keytab_testuser@{self.creds.get_realm()}"
        self.samdb.newuser("keytab_testuser", "4rfvBGT%")
        self.addCleanup(self.samdb.deleteuser, "keytab_testuser")
        net = Net(None, self.lp)
        self.addCleanup(self.rm_files, self.ktfile)
        net.export_keytab(keytab=self.ktfile, principal=new_principal)
        self.assertTrue(os.path.exists(self.ktfile), 'keytab was not created')

        # Parse the first entry in the keytab
        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_orig_bytes = bytes_kt.read()

        self.samdb.setpassword(f"(userPrincipalName={new_principal})", "5rfvBGT%")

        net.export_keytab(keytab=self.ktfile, principal=new_principal, keep_stale_entries=True)

        self.samdb.setpassword(f"(userPrincipalName={new_principal})", "6rfvBGT%")

        net.export_keytab(keytab=self.ktfile, principal=new_principal, keep_stale_entries=True)

        with open(self.ktfile, 'rb') as bytes_kt:
            keytab_change_bytes = bytes_kt.read()

        self.assertNotEqual(keytab_orig_bytes, keytab_change_bytes)

        # self.keytab_as_set() will also check we got each entry
        # exactly once
        keytab_as_set = self.keytab_as_set(keytab_change_bytes)

        # Look for the new principal, showing this was updated but the old kept
        found = 0
        for entry in keytab_as_set:
            (principal, enctype, kvno, key) = entry
            if principal == new_principal and enctype == credentials.ENCTYPE_AES128_CTS_HMAC_SHA1_96:
                found += 1

        # This covers the simple case, one export per password change
        self.assertEqual(found, 3)

        # confirm at least 9 keys (3 exports, 3 enctypes) were exported
        self.assertGreaterEqual(len(keytab_as_set), 9)

    def test_export_keytab_not_a_dir(self):
        net = Net(None, self.lp)
        with open(self.ktfile, mode='w') as f:
            f.write("NOT A KEYTAB")
        self.addCleanup(self.rm_files, self.ktfile)

        try:
            net.export_keytab(keytab=self.ktfile + "/f")
            self.fail("Expected failure to write to an existing file")
        except NTSTATUSError as err:
            num, _ = err.args
            self.assertEqual(num, ntstatus.NT_STATUS_NOT_A_DIRECTORY)

    def test_export_keytab_existing(self):
        net = Net(None, self.lp)
        with open(self.ktfile, mode='w') as f:
            f.write("NOT A KEYTAB")
        self.addCleanup(self.rm_files, self.ktfile)

        try:
            net.export_keytab(keytab=self.ktfile)
            self.fail(f"Expected failure to write to an existing file {self.ktfile}")
        except NTSTATUSError as err:
            num, _ = err.args
            self.assertEqual(num, ntstatus.NT_STATUS_OBJECT_NAME_EXISTS)

    def test_export_keytab_gmsa(self):

        # Create gMSA account
        gmsa_username = "GMSA_K5KeytabTest$"
        gmsa_principal = f"{gmsa_username}@{self.samdb.domain_dns_name().upper()}"
        gmsa_base_dn = self.samdb.get_wellknown_dn(
            self.samdb.get_default_basedn(),
            dsdb.DS_GUID_MANAGED_SERVICE_ACCOUNTS_CONTAINER,
        )
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
            if not keytab_bytes:
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

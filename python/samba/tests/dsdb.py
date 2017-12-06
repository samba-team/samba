# Unix SMB/CIFS implementation. Tests for dsdb
# Copyright (C) Matthieu Patou <mat@matws.net> 2010
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

"""Tests for samba.dsdb."""

from samba.credentials import Credentials
from samba.samdb import SamDB
from samba.auth import system_session
from samba.tests import TestCase
from samba.tests import delete_force
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import drsblobs
from samba import dsdb
import ldb
import samba

class DsdbTests(TestCase):

    def setUp(self):
        super(DsdbTests, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.session = system_session()
        self.samdb = SamDB(session_info=self.session,
                           credentials=self.creds,
                           lp=self.lp)

        # Create a test user
        user_name = "samdb-testuser"
        user_pass = samba.generate_random_password(32, 32)
        user_description = "Test user for dsdb test"

        base_dn = self.samdb.domain_dn()

        self.account_dn = "cn=" + user_name + ",cn=Users," + base_dn
        delete_force(self.samdb, self.account_dn)
        self.samdb.newuser(username=user_name,
                           password=user_pass,
                           description=user_description)

    def test_get_oid_from_attrid(self):
        oid = self.samdb.get_oid_from_attid(591614)
        self.assertEquals(oid, "1.2.840.113556.1.4.1790")

    def test_error_replpropertymetadata(self):
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=self.account_dn,
                                attrs=["replPropertyMetaData"])
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                            str(res[0]["replPropertyMetaData"]))
        ctr = repl.ctr
        for o in ctr.array:
            # Search for Description
            if o.attid == 13:
                old_version = o.version
                o.version = o.version + 1
        replBlob = ndr_pack(repl)
        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["replPropertyMetaData"] = ldb.MessageElement(replBlob, ldb.FLAG_MOD_REPLACE, "replPropertyMetaData")
        self.assertRaises(ldb.LdbError, self.samdb.modify, msg, ["local_oid:1.3.6.1.4.1.7165.4.3.14:0"])

    def test_error_replpropertymetadata_nochange(self):
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=self.account_dn,
                                attrs=["replPropertyMetaData"])
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                            str(res[0]["replPropertyMetaData"]))
        replBlob = ndr_pack(repl)
        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["replPropertyMetaData"] = ldb.MessageElement(replBlob, ldb.FLAG_MOD_REPLACE, "replPropertyMetaData")
        self.assertRaises(ldb.LdbError, self.samdb.modify, msg, ["local_oid:1.3.6.1.4.1.7165.4.3.14:0"])

    def test_error_replpropertymetadata_allow_sort(self):
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=self.account_dn,
                                attrs=["replPropertyMetaData"])
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                            str(res[0]["replPropertyMetaData"]))
        replBlob = ndr_pack(repl)
        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["replPropertyMetaData"] = ldb.MessageElement(replBlob, ldb.FLAG_MOD_REPLACE, "replPropertyMetaData")
        self.samdb.modify(msg, ["local_oid:1.3.6.1.4.1.7165.4.3.14:0", "local_oid:1.3.6.1.4.1.7165.4.3.25:0"])

    def test_twoatt_replpropertymetadata(self):
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=self.account_dn,
                                attrs=["replPropertyMetaData", "uSNChanged"])
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                            str(res[0]["replPropertyMetaData"]))
        ctr = repl.ctr
        for o in ctr.array:
            # Search for Description
            if o.attid == 13:
                old_version = o.version
                o.version = o.version + 1
                o.local_usn = long(str(res[0]["uSNChanged"])) + 1
        replBlob = ndr_pack(repl)
        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["replPropertyMetaData"] = ldb.MessageElement(replBlob, ldb.FLAG_MOD_REPLACE, "replPropertyMetaData")
        msg["description"] = ldb.MessageElement("new val", ldb.FLAG_MOD_REPLACE, "description")
        self.assertRaises(ldb.LdbError, self.samdb.modify, msg, ["local_oid:1.3.6.1.4.1.7165.4.3.14:0"])

    def test_set_replpropertymetadata(self):
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=self.account_dn,
                                attrs=["replPropertyMetaData", "uSNChanged"])
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                            str(res[0]["replPropertyMetaData"]))
        ctr = repl.ctr
        for o in ctr.array:
            # Search for Description
            if o.attid == 13:
                old_version = o.version
                o.version = o.version + 1
                o.local_usn = long(str(res[0]["uSNChanged"])) + 1
                o.originating_usn = long(str(res[0]["uSNChanged"])) + 1
        replBlob = ndr_pack(repl)
        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["replPropertyMetaData"] = ldb.MessageElement(replBlob, ldb.FLAG_MOD_REPLACE, "replPropertyMetaData")
        self.samdb.modify(msg, ["local_oid:1.3.6.1.4.1.7165.4.3.14:0"])

    def test_ok_get_attribute_from_attid(self):
        self.assertEquals(self.samdb.get_attribute_from_attid(13), "description")

    def test_ko_get_attribute_from_attid(self):
        self.assertEquals(self.samdb.get_attribute_from_attid(11979), None)

    def test_get_attribute_replmetadata_version(self):
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=self.account_dn,
                                attrs=["dn"])
        self.assertEquals(len(res), 1)
        dn = str(res[0].dn)
        self.assertEqual(self.samdb.get_attribute_replmetadata_version(dn, "unicodePwd"), 2)

    def test_set_attribute_replmetadata_version(self):
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=self.account_dn,
                                attrs=["dn"])
        self.assertEquals(len(res), 1)
        dn = str(res[0].dn)
        version = self.samdb.get_attribute_replmetadata_version(dn, "description")
        self.samdb.set_attribute_replmetadata_version(dn, "description", version + 2)
        self.assertEqual(self.samdb.get_attribute_replmetadata_version(dn, "description"), version + 2)

    def test_no_error_on_invalid_control(self):
        try:
            res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                    base=self.account_dn,
                                    attrs=["replPropertyMetaData"],
                                    controls=["local_oid:%s:0"
                                              % dsdb.DSDB_CONTROL_INVALID_NOT_IMPLEMENTED])
        except ldb.LdbError as e:
            self.fail("Should have not raised an exception")

    def test_error_on_invalid_critical_control(self):
        try:
            res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                    base=self.account_dn,
                                    attrs=["replPropertyMetaData"],
                                    controls=["local_oid:%s:1"
                                              % dsdb.DSDB_CONTROL_INVALID_NOT_IMPLEMENTED])
        except ldb.LdbError as e:
            if e[0] != ldb.ERR_UNSUPPORTED_CRITICAL_EXTENSION:
                self.fail("Got %s should have got ERR_UNSUPPORTED_CRITICAL_EXTENSION"
                          % e[1])

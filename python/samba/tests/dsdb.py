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
from samba.dcerpc import drsblobs, security, misc
from samba import dsdb
from samba import werror
import ldb
import samba
import uuid


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
        user_name = "dsdb-user-" + str(uuid.uuid4().hex[0:6])
        user_pass = samba.generate_random_password(32, 32)
        user_description = "Test user for dsdb test"

        base_dn = self.samdb.domain_dn()

        self.account_dn = "cn=" + user_name + ",cn=Users," + base_dn
        self.samdb.newuser(username=user_name,
                           password=user_pass,
                           description=user_description)
        # Cleanup (teardown)
        self.addCleanup(delete_force, self.samdb, self.account_dn)

    def test_get_oid_from_attrid(self):
        oid = self.samdb.get_oid_from_attid(591614)
        self.assertEquals(oid, "1.2.840.113556.1.4.1790")

    def test_error_replpropertymetadata(self):
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=self.account_dn,
                                attrs=["replPropertyMetaData"])
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          res[0]["replPropertyMetaData"][0])
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
                          res[0]["replPropertyMetaData"][0])
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
                          res[0]["replPropertyMetaData"][0])
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
                          res[0]["replPropertyMetaData"][0])
        ctr = repl.ctr
        for o in ctr.array:
            # Search for Description
            if o.attid == 13:
                old_version = o.version
                o.version = o.version + 1
                o.local_usn = int(str(res[0]["uSNChanged"])) + 1
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
                          res[0]["replPropertyMetaData"][0])
        ctr = repl.ctr
        for o in ctr.array:
            # Search for Description
            if o.attid == 13:
                old_version = o.version
                o.version = o.version + 1
                o.local_usn = int(str(res[0]["uSNChanged"])) + 1
                o.originating_usn = int(str(res[0]["uSNChanged"])) + 1
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
            (errno, estr) = e.args
            if errno != ldb.ERR_UNSUPPORTED_CRITICAL_EXTENSION:
                self.fail("Got %s should have got ERR_UNSUPPORTED_CRITICAL_EXTENSION"
                          % e[1])

    # Allocate a unique RID for use in the objectSID tests.
    #
    def allocate_rid(self):
        self.samdb.transaction_start()
        try:
            rid = self.samdb.allocate_rid()
        except:
            self.samdb.transaction_cancel()
            raise
        self.samdb.transaction_commit()
        return str(rid)

    # Ensure that duplicate objectSID's are permitted for foreign security
    # principals.
    #
    def test_duplicate_objectSIDs_allowed_on_foreign_security_principals(self):

        #
        # We need to build a foreign security principal SID
        # i.e a  SID not in the current domain.
        #
        dom_sid = self.samdb.get_domain_sid()
        if str(dom_sid).endswith("0"):
            c = "9"
        else:
            c = "0"
        sid_str = str(dom_sid)[:-1] + c + "-1000"
        sid     = ndr_pack(security.dom_sid(sid_str))
        basedn  = self.samdb.get_default_basedn()
        dn      = "CN=%s,CN=ForeignSecurityPrincipals,%s" % (sid_str, basedn)

        #
        # First without control
        #

        try:
            self.samdb.add({
                "dn": dn,
                "objectClass": "foreignSecurityPrincipal"})
            self.fail("No exception should get ERR_OBJECT_CLASS_VIOLATION")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_OBJECT_CLASS_VIOLATION, str(e))
            werr = "%08X" % werror.WERR_DS_MISSING_REQUIRED_ATT
            self.assertTrue(werr in msg, msg)

        try:
            self.samdb.add({
                "dn": dn,
                "objectClass": "foreignSecurityPrincipal",
                "objectSid": sid})
            self.fail("No exception should get ERR_UNWILLING_TO_PERFORM")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_UNWILLING_TO_PERFORM, str(e))
            werr = "%08X" % werror.WERR_DS_ILLEGAL_MOD_OPERATION
            self.assertTrue(werr in msg, msg)

        #
        # We need to use the provision control
        # in order to add foreignSecurityPrincipal
        # objects
        #

        controls = ["provision:0"]
        self.samdb.add({
            "dn": dn,
            "objectClass": "foreignSecurityPrincipal"},
            controls=controls)

        self.samdb.delete(dn)

        try:
            self.samdb.add({
                "dn": dn,
                "objectClass": "foreignSecurityPrincipal"},
                controls=controls)
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.fail("Got unexpected exception %d - %s "
                      % (code, msg))

        # cleanup
        self.samdb.delete(dn)

    def _test_foreignSecurityPrincipal(self, obj_class, fpo_attr):

        dom_sid = self.samdb.get_domain_sid()
        lsid_str = str(dom_sid) + "-4294967294"
        bsid_str = "S-1-5-32-4294967294"
        fsid_str = "S-1-5-4294967294"
        basedn   = self.samdb.get_default_basedn()
        cn       = "dsdb_test_fpo"
        dn_str   = "cn=%s,cn=Users,%s" % (cn, basedn)
        dn = ldb.Dn(self.samdb, dn_str)

        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=basedn,
                                expression="(objectSid=%s)" % lsid_str,
                                attrs=[])
        self.assertEqual(len(res), 0)
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=basedn,
                                expression="(objectSid=%s)" % bsid_str,
                                attrs=[])
        self.assertEqual(len(res), 0)
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=basedn,
                                expression="(objectSid=%s)" % fsid_str,
                                attrs=[])
        self.assertEqual(len(res), 0)

        self.addCleanup(delete_force, self.samdb, dn_str)

        self.samdb.add({
            "dn": dn_str,
            "objectClass": obj_class})

        msg = ldb.Message()
        msg.dn = dn
        msg[fpo_attr] = ldb.MessageElement("<SID=%s>" % lsid_str,
                                           ldb.FLAG_MOD_ADD,
                                           fpo_attr)
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get LDB_ERR_UNWILLING_TO_PERFORM")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_UNWILLING_TO_PERFORM, str(e))
            werr = "%08X" % werror.WERR_DS_INVALID_GROUP_TYPE
            self.assertTrue(werr in msg, msg)

        msg = ldb.Message()
        msg.dn = dn
        msg[fpo_attr] = ldb.MessageElement("<SID=%s>" % bsid_str,
                                           ldb.FLAG_MOD_ADD,
                                           fpo_attr)
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get LDB_ERR_NO_SUCH_OBJECT")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_NO_SUCH_OBJECT, str(e))
            werr = "%08X" % werror.WERR_NO_SUCH_MEMBER
            self.assertTrue(werr in msg, msg)

        msg = ldb.Message()
        msg.dn = dn
        msg[fpo_attr] = ldb.MessageElement("<SID=%s>" % fsid_str,
                                           ldb.FLAG_MOD_ADD,
                                           fpo_attr)
        try:
            self.samdb.modify(msg)
        except ldb.LdbError as e:
            self.fail("Should have not raised an exception")

        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=basedn,
                                expression="(objectSid=%s)" % fsid_str,
                                attrs=[])
        self.assertEqual(len(res), 1)
        self.samdb.delete(res[0].dn)
        self.samdb.delete(dn)
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=basedn,
                                expression="(objectSid=%s)" % fsid_str,
                                attrs=[])
        self.assertEqual(len(res), 0)

    def test_foreignSecurityPrincipal_member(self):
        return self._test_foreignSecurityPrincipal(
                "group", "member")

    def test_foreignSecurityPrincipal_MembersForAzRole(self):
        return self._test_foreignSecurityPrincipal(
                "msDS-AzRole", "msDS-MembersForAzRole")

    def test_foreignSecurityPrincipal_NeverRevealGroup(self):
        return self._test_foreignSecurityPrincipal(
                "computer", "msDS-NeverRevealGroup")

    def test_foreignSecurityPrincipal_RevealOnDemandGroup(self):
        return self._test_foreignSecurityPrincipal(
                "computer", "msDS-RevealOnDemandGroup")

    def _test_fail_foreignSecurityPrincipal(self, obj_class, fpo_attr,
                                            msg_exp, lerr_exp, werr_exp,
                                            allow_reference=True):

        dom_sid = self.samdb.get_domain_sid()
        lsid_str = str(dom_sid) + "-4294967294"
        bsid_str = "S-1-5-32-4294967294"
        fsid_str = "S-1-5-4294967294"
        basedn   = self.samdb.get_default_basedn()
        cn1       = "dsdb_test_fpo1"
        dn1_str   = "cn=%s,cn=Users,%s" % (cn1, basedn)
        dn1 = ldb.Dn(self.samdb, dn1_str)
        cn2       = "dsdb_test_fpo2"
        dn2_str   = "cn=%s,cn=Users,%s" % (cn2, basedn)
        dn2 = ldb.Dn(self.samdb, dn2_str)

        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=basedn,
                                expression="(objectSid=%s)" % lsid_str,
                                attrs=[])
        self.assertEqual(len(res), 0)
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=basedn,
                                expression="(objectSid=%s)" % bsid_str,
                                attrs=[])
        self.assertEqual(len(res), 0)
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=basedn,
                                expression="(objectSid=%s)" % fsid_str,
                                attrs=[])
        self.assertEqual(len(res), 0)

        self.addCleanup(delete_force, self.samdb, dn1_str)
        self.addCleanup(delete_force, self.samdb, dn2_str)

        self.samdb.add({
            "dn": dn1_str,
            "objectClass": obj_class})

        self.samdb.add({
            "dn": dn2_str,
            "objectClass": obj_class})

        msg = ldb.Message()
        msg.dn = dn1
        msg[fpo_attr] = ldb.MessageElement("<SID=%s>" % lsid_str,
                                           ldb.FLAG_MOD_ADD,
                                           fpo_attr)
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get %s" % msg_exp)
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, lerr_exp, str(e))
            werr = "%08X" % werr_exp
            self.assertTrue(werr in msg, msg)

        msg = ldb.Message()
        msg.dn = dn1
        msg[fpo_attr] = ldb.MessageElement("<SID=%s>" % bsid_str,
                                           ldb.FLAG_MOD_ADD,
                                           fpo_attr)
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get %s" % msg_exp)
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, lerr_exp, str(e))
            werr = "%08X" % werr_exp
            self.assertTrue(werr in msg, msg)

        msg = ldb.Message()
        msg.dn = dn1
        msg[fpo_attr] = ldb.MessageElement("<SID=%s>" % fsid_str,
                                           ldb.FLAG_MOD_ADD,
                                           fpo_attr)
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get %s" % msg)
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, lerr_exp, str(e))
            werr = "%08X" % werr_exp
            self.assertTrue(werr in msg, msg)

        msg = ldb.Message()
        msg.dn = dn1
        msg[fpo_attr] = ldb.MessageElement("%s" % dn2,
                                           ldb.FLAG_MOD_ADD,
                                           fpo_attr)
        try:
            self.samdb.modify(msg)
            if not allow_reference:
                self.fail("No exception should get %s" % msg_exp)
        except ldb.LdbError as e:
            if allow_reference:
                self.fail("Should have not raised an exception: %s" % e)
            (code, msg) = e.args
            self.assertEqual(code, lerr_exp, str(e))
            werr = "%08X" % werr_exp
            self.assertTrue(werr in msg, msg)

        self.samdb.delete(dn2)
        self.samdb.delete(dn1)

    def test_foreignSecurityPrincipal_NonMembers(self):
        return self._test_fail_foreignSecurityPrincipal(
                "group", "msDS-NonMembers",
                "LDB_ERR_UNWILLING_TO_PERFORM/WERR_NOT_SUPPORTED",
                ldb.ERR_UNWILLING_TO_PERFORM, werror.WERR_NOT_SUPPORTED,
                allow_reference=False)

    def test_foreignSecurityPrincipal_HostServiceAccount(self):
        return self._test_fail_foreignSecurityPrincipal(
                "computer", "msDS-HostServiceAccount",
                "LDB_ERR_CONSTRAINT_VIOLATION/WERR_DS_NAME_REFERENCE_INVALID",
                ldb.ERR_CONSTRAINT_VIOLATION,
                werror.WERR_DS_NAME_REFERENCE_INVALID)

    def test_foreignSecurityPrincipal_manager(self):
        return self._test_fail_foreignSecurityPrincipal(
                "user", "manager",
                "LDB_ERR_CONSTRAINT_VIOLATION/WERR_DS_NAME_REFERENCE_INVALID",
                ldb.ERR_CONSTRAINT_VIOLATION,
                werror.WERR_DS_NAME_REFERENCE_INVALID)

    #
    # Duplicate objectSID's should not be permitted for sids in the local
    # domain. The test sequence is add an object, delete it, then attempt to
    # re-add it, this should fail with a constraint violation
    #
    def test_duplicate_objectSIDs_not_allowed_on_local_objects(self):

        dom_sid = self.samdb.get_domain_sid()
        rid     = self.allocate_rid()
        sid_str = str(dom_sid) + "-" + rid
        sid     = ndr_pack(security.dom_sid(sid_str))
        basedn  = self.samdb.get_default_basedn()
        cn       = "dsdb_test_01"
        dn      = "cn=%s,cn=Users,%s" % (cn, basedn)

        self.samdb.add({
            "dn": dn,
            "objectClass": "user",
            "objectSID": sid})
        self.samdb.delete(dn)

        try:
            self.samdb.add({
                "dn": dn,
                "objectClass": "user",
                "objectSID": sid})
            self.fail("No exception should get LDB_ERR_CONSTRAINT_VIOLATION")
        except ldb.LdbError as e:
            (code, msg) = e.args
            if code != ldb.ERR_CONSTRAINT_VIOLATION:
                self.fail("Got %d - %s should have got "
                          "LDB_ERR_CONSTRAINT_VIOLATION"
                          % (code, msg))

    def test_linked_vs_non_linked_reference(self):
        basedn   = self.samdb.get_default_basedn()
        kept_dn_str   = "cn=reference_kept,cn=Users,%s" % (basedn)
        removed_dn_str   = "cn=reference_removed,cn=Users,%s" % (basedn)
        dom_sid = self.samdb.get_domain_sid()
        none_sid_str = str(dom_sid) + "-4294967294"
        none_guid_str = "afafafaf-fafa-afaf-fafa-afafafafafaf"

        self.addCleanup(delete_force, self.samdb, kept_dn_str)
        self.addCleanup(delete_force, self.samdb, removed_dn_str)

        self.samdb.add({
            "dn": kept_dn_str,
            "objectClass": "user"})
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=kept_dn_str,
                                attrs=["objectGUID", "objectSID"])
        self.assertEqual(len(res), 1)
        kept_guid = ndr_unpack(misc.GUID, res[0]["objectGUID"][0])
        kept_sid = ndr_unpack(security.dom_sid, res[0]["objectSid"][0])
        kept_dn = res[0].dn

        self.samdb.add({
            "dn": removed_dn_str,
            "objectClass": "user"})
        res = self.samdb.search(scope=ldb.SCOPE_SUBTREE,
                                base=removed_dn_str,
                                attrs=["objectGUID", "objectSID"])
        self.assertEqual(len(res), 1)
        removed_guid = ndr_unpack(misc.GUID, res[0]["objectGUID"][0])
        removed_sid = ndr_unpack(security.dom_sid, res[0]["objectSid"][0])
        self.samdb.delete(removed_dn_str)

        #
        # First try the linked attribute 'manager'
        # by GUID and SID
        #

        msg = ldb.Message()
        msg.dn = kept_dn
        msg["manager"] = ldb.MessageElement("<SID=%s>" % removed_sid,
                                            ldb.FLAG_MOD_ADD,
                                            "manager")
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get LDB_ERR_CONSTRAINT_VIOLATION")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_CONSTRAINT_VIOLATION, str(e))
            werr = "%08X" % werror.WERR_DS_NAME_REFERENCE_INVALID
            self.assertTrue(werr in msg, msg)

        msg = ldb.Message()
        msg.dn = kept_dn
        msg["manager"] = ldb.MessageElement("<GUID=%s>" % removed_guid,
                                            ldb.FLAG_MOD_ADD,
                                            "manager")
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get LDB_ERR_CONSTRAINT_VIOLATION")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_CONSTRAINT_VIOLATION, str(e))
            werr = "%08X" % werror.WERR_DS_NAME_REFERENCE_INVALID
            self.assertTrue(werr in msg, msg)

        #
        # Try the non-linked attribute 'assistant'
        # by GUID and SID, which should work.
        #
        msg = ldb.Message()
        msg.dn = kept_dn
        msg["assistant"] = ldb.MessageElement("<SID=%s>" % removed_sid,
                                              ldb.FLAG_MOD_ADD,
                                              "assistant")
        self.samdb.modify(msg)
        msg = ldb.Message()
        msg.dn = kept_dn
        msg["assistant"] = ldb.MessageElement("<SID=%s>" % removed_sid,
                                              ldb.FLAG_MOD_DELETE,
                                              "assistant")
        self.samdb.modify(msg)

        msg = ldb.Message()
        msg.dn = kept_dn
        msg["assistant"] = ldb.MessageElement("<GUID=%s>" % removed_guid,
                                              ldb.FLAG_MOD_ADD,
                                              "assistant")
        self.samdb.modify(msg)
        msg = ldb.Message()
        msg.dn = kept_dn
        msg["assistant"] = ldb.MessageElement("<GUID=%s>" % removed_guid,
                                              ldb.FLAG_MOD_DELETE,
                                              "assistant")
        self.samdb.modify(msg)

        #
        # Finally ry the non-linked attribute 'assistant'
        # but with non existing GUID, SID, DN
        #
        msg = ldb.Message()
        msg.dn = kept_dn
        msg["assistant"] = ldb.MessageElement("CN=NoneNone,%s" % (basedn),
                                              ldb.FLAG_MOD_ADD,
                                              "assistant")
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get LDB_ERR_CONSTRAINT_VIOLATION")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_CONSTRAINT_VIOLATION, str(e))
            werr = "%08X" % werror.WERR_DS_NAME_REFERENCE_INVALID
            self.assertTrue(werr in msg, msg)

        msg = ldb.Message()
        msg.dn = kept_dn
        msg["assistant"] = ldb.MessageElement("<SID=%s>" % none_sid_str,
                                              ldb.FLAG_MOD_ADD,
                                              "assistant")
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get LDB_ERR_CONSTRAINT_VIOLATION")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_CONSTRAINT_VIOLATION, str(e))
            werr = "%08X" % werror.WERR_DS_NAME_REFERENCE_INVALID
            self.assertTrue(werr in msg, msg)

        msg = ldb.Message()
        msg.dn = kept_dn
        msg["assistant"] = ldb.MessageElement("<GUID=%s>" % none_guid_str,
                                              ldb.FLAG_MOD_ADD,
                                              "assistant")
        try:
            self.samdb.modify(msg)
            self.fail("No exception should get LDB_ERR_CONSTRAINT_VIOLATION")
        except ldb.LdbError as e:
            (code, msg) = e.args
            self.assertEqual(code, ldb.ERR_CONSTRAINT_VIOLATION, str(e))
            werr = "%08X" % werror.WERR_DS_NAME_REFERENCE_INVALID
            self.assertTrue(werr in msg, msg)

        self.samdb.delete(kept_dn)

    def test_normalize_dn_in_domain_full(self):
        domain_dn = self.samdb.domain_dn()

        part_dn = ldb.Dn(self.samdb, "CN=Users")

        full_dn = part_dn
        full_dn.add_base(domain_dn)

        full_str = str(full_dn)

        # That is, no change
        self.assertEqual(full_dn,
                         self.samdb.normalize_dn_in_domain(full_str))

    def test_normalize_dn_in_domain_part(self):
        domain_dn = self.samdb.domain_dn()

        part_str = "CN=Users"

        full_dn = ldb.Dn(self.samdb, part_str)
        full_dn.add_base(domain_dn)

        # That is, the domain DN appended
        self.assertEqual(full_dn,
                         self.samdb.normalize_dn_in_domain(part_str))

    def test_normalize_dn_in_domain_full_dn(self):
        domain_dn = self.samdb.domain_dn()

        part_dn = ldb.Dn(self.samdb, "CN=Users")

        full_dn = part_dn
        full_dn.add_base(domain_dn)

        # That is, no change
        self.assertEqual(full_dn,
                         self.samdb.normalize_dn_in_domain(full_dn))

    def test_normalize_dn_in_domain_part_dn(self):
        domain_dn = self.samdb.domain_dn()

        part_dn = ldb.Dn(self.samdb, "CN=Users")

        # That is, the domain DN appended
        self.assertEqual(ldb.Dn(self.samdb,
                                str(part_dn) + "," + str(domain_dn)),
                         self.samdb.normalize_dn_in_domain(part_dn))


class DsdbFullScanTests(TestCase):

    def setUp(self):
        super(DsdbFullScanTests, self).setUp()
        self.lp = samba.tests.env_loadparm()
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.session = system_session()

    def test_sam_ldb_open_no_full_scan(self):
        try:
            self.samdb = SamDB(session_info=self.session,
                               credentials=self.creds,
                               lp=self.lp,
                               options=["disable_full_db_scan_for_self_test:1"])
        except ldb.LdbError as err:
            estr = err.args[1]
            self.fail("sam.ldb required a full scan to start up")

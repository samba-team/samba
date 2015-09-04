#!/usr/bin/env python
#
# Tombstone reanimation tests
#
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2014
# Copyright (C) Nadezhda Ivanova <nivanova@symas.com> 2014
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

import sys
import unittest

sys.path.insert(0, "bin/python")
import samba

import samba.tests
from ldb import (SCOPE_BASE, FLAG_MOD_ADD, FLAG_MOD_DELETE, FLAG_MOD_REPLACE, Dn, Message,
                 MessageElement, LdbError,
                 ERR_ATTRIBUTE_OR_VALUE_EXISTS, ERR_NO_SUCH_OBJECT, ERR_ENTRY_ALREADY_EXISTS,
                 ERR_OPERATIONS_ERROR, ERR_UNWILLING_TO_PERFORM)


class RestoredObjectAttributesBaseTestCase(samba.tests.TestCase):
    """ verify Samba restores required attributes when
        user restores a Deleted object
    """

    def setUp(self):
        super(RestoredObjectAttributesBaseTestCase, self).setUp()
        self.samdb = samba.tests.connect_samdb_env("TEST_SERVER", "TEST_USERNAME", "TEST_PASSWORD")
        self.base_dn = self.samdb.domain_dn()
        self.schema_dn = self.samdb.get_schema_basedn().get_linearized()
        self.configuration_dn = self.samdb.get_config_basedn().get_linearized()
        # Get the old "dSHeuristics" if it was set
        self.dsheuristics = self.samdb.get_dsheuristics()
        # Set the "dSHeuristics" to activate the correct "userPassword" behaviour
        self.samdb.set_dsheuristics("000000001")
        # Get the old "minPwdAge"
        self.minPwdAge = self.samdb.get_minPwdAge()
        # Set it temporary to "0"
        self.samdb.set_minPwdAge("0")

    def tearDown(self):
        super(RestoredObjectAttributesBaseTestCase, self).tearDown()
        # Reset the "dSHeuristics" as they were before
        self.samdb.set_dsheuristics(self.dsheuristics)
        # Reset the "minPwdAge" as it was before
        self.samdb.set_minPwdAge(self.minPwdAge)

    def GUID_string(self, guid):
        return self.samdb.schema_format_value("objectGUID", guid)

    def search_guid(self, guid):
        res = self.samdb.search(base="<GUID=%s>" % self.GUID_string(guid),
                                scope=SCOPE_BASE, controls=["show_deleted:1"])
        self.assertEquals(len(res), 1)
        return res[0]

    def search_dn(self, dn):
        res = self.samdb.search(expression="(objectClass=*)",
                                base=dn,
                                scope=SCOPE_BASE,
                                controls=["show_recycled:1"])
        self.assertEquals(len(res), 1)
        return res[0]

    def _create_object(self, msg):
        """:param msg: dict with dn and attributes to create an object from"""
        # delete an object if leftover from previous test
        samba.tests.delete_force(self.samdb, msg['dn'])
        self.samdb.add(msg)
        return self.search_dn(msg['dn'])

    def assertAttributesEqual(self, obj_orig, attrs_orig, obj_restored, attrs_rest):
        self.assertEqual(attrs_orig, attrs_rest,
                         "Actual object does not have expected attributes, missing from expected (%s), extra (%s)"
                         % (str(attrs_orig.difference(attrs_rest)), str(attrs_rest.difference(attrs_orig))))
        # remove volatile attributes, they can't be equal
        attrs_orig -= set(["uSNChanged", "dSCorePropagationData", "whenChanged"])
        for attr in attrs_orig:
            # convert original attr value to ldif
            orig_val = obj_orig.get(attr)
            if orig_val is None:
                continue
            if not isinstance(orig_val, MessageElement):
                orig_val = MessageElement(str(orig_val), 0, attr    )
            m = Message()
            m.add(orig_val)
            orig_ldif = self.samdb.write_ldif(m, 0)
            # convert restored attr value to ldif
            rest_val = obj_restored.get(attr)
            self.assertFalse(rest_val is None)
            m = Message()
            if not isinstance(rest_val, MessageElement):
                rest_val = MessageElement(str(rest_val), 0, attr)
            m.add(rest_val)
            rest_ldif = self.samdb.write_ldif(m, 0)
            # compare generated ldif's
            self.assertEqual(orig_ldif.lower(), rest_ldif.lower())

    def assertAttributesExists(self, attr_expected, obj_msg):
        """Check object contains at least expected attrbigutes
        :param attr_expected: dict of expected attributes with values. ** is any value
        :param obj_msg: Ldb.Message for the object under test
        """
        actual_names = set(obj_msg.keys())
        # Samba does not use 'dSCorePropagationData', so skip it
        actual_names -= set(['dSCorePropagationData'])
        self.assertEqual(set(attr_expected.keys()), actual_names, "Actual object does not have expected attributes")
        for name in attr_expected.keys():
            expected_val = attr_expected[name]
            actual_val = obj_msg.get(name)
            self.assertFalse(actual_val is None, "No value for attribute '%s'" % name)
            if expected_val == "**":
                # "**" values means "any"
                continue
            self.assertEqual(expected_val.lower(), str(actual_val).lower(),
                             "Unexpected value for '%s'" % name)

    @staticmethod
    def restore_deleted_object(samdb, del_dn, new_dn, new_attrs=None):
        """Restores a deleted object
        :param samdb: SamDB connection to SAM
        :param del_dn: str Deleted object DN
        :param new_dn: str Where to restore the object
        :param new_attrs: dict Additional attributes to set
        """
        msg = Message()
        msg.dn = Dn(samdb, str(del_dn))
        msg["isDeleted"] = MessageElement([], FLAG_MOD_DELETE, "isDeleted")
        msg["distinguishedName"] = MessageElement([str(new_dn)], FLAG_MOD_REPLACE, "distinguishedName")
        if new_attrs is not None:
            assert isinstance(new_attrs, dict)
            for attr in new_attrs:
                msg[attr] = MessageElement(new_attrs[attr], FLAG_MOD_REPLACE, attr)
        samdb.modify(msg, ["show_deleted:1"])


class BaseRestoreObjectTestCase(RestoredObjectAttributesBaseTestCase):
    def setUp(self):
        super(BaseRestoreObjectTestCase, self).setUp()

    def enable_recycle_bin(self):
        msg = Message()
        msg.dn = Dn(self.samdb, "")
        msg["enableOptionalFeature"] = MessageElement(
            "CN=Partitions," + self.configuration_dn + ":766ddcd8-acd0-445e-f3b9-a7f9b6744f2a",
            FLAG_MOD_ADD, "enableOptionalFeature")
        try:
            self.samdb.modify(msg)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

    def test_undelete(self):
        print "Testing standard undelete operation"
        usr1 = "cn=testuser,cn=users," + self.base_dn
        samba.tests.delete_force(self.samdb, usr1)
        self.samdb.add({
            "dn": usr1,
            "objectclass": "user",
            "description": "test user description",
            "samaccountname": "testuser"})
        objLive1 = self.search_dn(usr1)
        guid1 = objLive1["objectGUID"][0]
        self.samdb.delete(usr1)
        objDeleted1 = self.search_guid(guid1)
        self.restore_deleted_object(self.samdb, objDeleted1.dn, usr1)
        objLive2 = self.search_dn(usr1)
        self.assertEqual(str(objLive2.dn).lower(), str(objLive1.dn).lower())
        samba.tests.delete_force(self.samdb, usr1)

    def test_rename(self):
        print "Testing attempt to rename deleted object"
        usr1 = "cn=testuser,cn=users," + self.base_dn
        self.samdb.add({
            "dn": usr1,
            "objectclass": "user",
            "description": "test user description",
            "samaccountname": "testuser"})
        objLive1 = self.search_dn(usr1)
        guid1 = objLive1["objectGUID"][0]
        self.samdb.delete(usr1)
        objDeleted1 = self.search_guid(guid1)
        # just to make sure we get the correct error if the show deleted is missing
        try:
            self.samdb.rename(str(objDeleted1.dn), usr1)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        try:
            self.samdb.rename(str(objDeleted1.dn), usr1, ["show_deleted:1"])
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

    def test_undelete_with_mod(self):
        print "Testing standard undelete operation with modification of additional attributes"
        usr1 = "cn=testuser,cn=users," + self.base_dn
        self.samdb.add({
            "dn": usr1,
            "objectclass": "user",
            "description": "test user description",
            "samaccountname": "testuser"})
        objLive1 = self.search_dn(usr1)
        guid1 = objLive1["objectGUID"][0]
        self.samdb.delete(usr1)
        objDeleted1 = self.search_guid(guid1)
        self.restore_deleted_object(self.samdb, objDeleted1.dn, usr1, {"url": "www.samba.org"})
        objLive2 = self.search_dn(usr1)
        self.assertEqual(objLive2["url"][0], "www.samba.org")
        samba.tests.delete_force(self.samdb, usr1)

    def test_undelete_newuser(self):
        print "Testing undelete user with a different dn"
        usr1 = "cn=testuser,cn=users," + self.base_dn
        usr2 = "cn=testuser2,cn=users," + self.base_dn
        samba.tests.delete_force(self.samdb, usr1)
        self.samdb.add({
            "dn": usr1,
            "objectclass": "user",
            "description": "test user description",
            "samaccountname": "testuser"})
        objLive1 = self.search_dn(usr1)
        guid1 = objLive1["objectGUID"][0]
        self.samdb.delete(usr1)
        objDeleted1 = self.search_guid(guid1)
        self.restore_deleted_object(self.samdb, objDeleted1.dn, usr2)
        objLive2 = self.search_dn(usr2)
        samba.tests.delete_force(self.samdb, usr1)
        samba.tests.delete_force(self.samdb, usr2)

    def test_undelete_existing(self):
        print "Testing undelete user after a user with the same dn has been created"
        usr1 = "cn=testuser,cn=users," + self.base_dn
        self.samdb.add({
            "dn": usr1,
            "objectclass": "user",
            "description": "test user description",
            "samaccountname": "testuser"})
        objLive1 = self.search_dn(usr1)
        guid1 = objLive1["objectGUID"][0]
        self.samdb.delete(usr1)
        self.samdb.add({
            "dn": usr1,
            "objectclass": "user",
            "description": "test user description",
            "samaccountname": "testuser"})
        objDeleted1 = self.search_guid(guid1)
        try:
            self.restore_deleted_object(self.samdb, objDeleted1.dn, usr1)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ENTRY_ALREADY_EXISTS)

    def test_undelete_cross_nc(self):
        print "Cross NC undelete"
        c1 = "cn=ldaptestcontainer," + self.base_dn
        c2 = "cn=ldaptestcontainer2," + self.configuration_dn
        c3 = "cn=ldaptestcontainer," + self.configuration_dn
        c4 = "cn=ldaptestcontainer2," + self.base_dn
        samba.tests.delete_force(self.samdb, c1)
        samba.tests.delete_force(self.samdb, c2)
        samba.tests.delete_force(self.samdb, c3)
        samba.tests.delete_force(self.samdb, c4)
        self.samdb.add({
            "dn": c1,
            "objectclass": "container"})
        self.samdb.add({
            "dn": c2,
            "objectclass": "container"})
        objLive1 = self.search_dn(c1)
        objLive2 = self.search_dn(c2)
        guid1 = objLive1["objectGUID"][0]
        guid2 = objLive2["objectGUID"][0]
        self.samdb.delete(c1)
        self.samdb.delete(c2)
        objDeleted1 = self.search_guid(guid1)
        objDeleted2 = self.search_guid(guid2)
        # try to undelete from base dn to config
        try:
            self.restore_deleted_object(self.samdb, objDeleted1.dn, c3)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OPERATIONS_ERROR)
        #try to undelete from config to base dn
        try:
            self.restore_deleted_object(self.samdb, objDeleted2.dn, c4)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OPERATIONS_ERROR)
        #assert undeletion will work in same nc
        self.restore_deleted_object(self.samdb, objDeleted1.dn, c4)
        self.restore_deleted_object(self.samdb, objDeleted2.dn, c3)


class RestoreUserObjectTestCase(RestoredObjectAttributesBaseTestCase):
    """Test cases for delete/reanimate user objects"""

    def _expected_user_attributes(self, username, user_dn, category):
        return {'dn': user_dn,
                'objectClass': '**',
                'cn': username,
                'distinguishedName': user_dn,
                'instanceType': '4',
                'whenCreated': '**',
                'whenChanged': '**',
                'uSNCreated': '**',
                'uSNChanged': '**',
                'name': username,
                'objectGUID': '**',
                'userAccountControl': '546',
                'badPwdCount': '0',
                'badPasswordTime': '0',
                'codePage': '0',
                'countryCode': '0',
                'lastLogon': '0',
                'lastLogoff': '0',
                'pwdLastSet': '0',
                'primaryGroupID': '513',
                'operatorCount': '0',
                'objectSid': '**',
                'adminCount': '0',
                'accountExpires': '9223372036854775807',
                'logonCount': '0',
                'sAMAccountName': username,
                'sAMAccountType': '805306368',
                'lastKnownParent': 'CN=Users,%s' % self.base_dn,
                'objectCategory': 'CN=%s,%s' % (category, self.schema_dn)
                }

    def test_restore_user(self):
        print "Test restored user attributes"
        username = "restore_user"
        usr_dn = "cn=%s,cn=users,%s" % (username, self.base_dn)
        samba.tests.delete_force(self.samdb, usr_dn)
        self.samdb.add({
            "dn": usr_dn,
            "objectClass": "user",
            "sAMAccountName": username})
        obj = self.search_dn(usr_dn)
        guid = obj["objectGUID"][0]
        self.samdb.delete(usr_dn)
        obj_del = self.search_guid(guid)
        # restore the user and fetch what's restored
        self.restore_deleted_object(self.samdb, obj_del.dn, usr_dn)
        obj_restore = self.search_guid(guid)
        # check original attributes and restored one are same
        orig_attrs = set(obj.keys())
        # windows restore more attributes that originally we have
        orig_attrs.update(['adminCount', 'operatorCount', 'lastKnownParent'])
        rest_attrs = set(obj_restore.keys())
        self.assertEqual(orig_attrs, rest_attrs, "Actual object does not have expected attributes")
        self.assertAttributesExists(self._expected_user_attributes(username, usr_dn, "Person"), obj_restore)


class RestoreGroupObjectTestCase(RestoredObjectAttributesBaseTestCase):
    """Test different scenarios for delete/reanimate group objects"""

    def _make_object_dn(self, name):
        return "cn=%s,cn=users,%s" % (name, self.base_dn)

    def _create_test_user(self, user_name):
        user_dn = self._make_object_dn(user_name)
        ldif = {
            "dn": user_dn,
            "objectClass": "user",
            "sAMAccountName": user_name,
        }
        # delete an object if leftover from previous test
        samba.tests.delete_force(self.samdb, user_dn)
        # finally, create the group
        self.samdb.add(ldif)
        return self.search_dn(user_dn)

    def _create_test_group(self, group_name, members=None):
        group_dn = self._make_object_dn(group_name)
        ldif = {
            "dn": group_dn,
            "objectClass": "group",
            "sAMAccountName": group_name,
        }
        try:
            ldif["member"] = [str(usr_dn) for usr_dn in members]
        except TypeError:
            pass
        # delete an object if leftover from previous test
        samba.tests.delete_force(self.samdb, group_dn)
        # finally, create the group
        self.samdb.add(ldif)
        return self.search_dn(group_dn)

    def _expected_group_attributes(self, groupname, group_dn, category):
        return {'dn': group_dn,
                'groupType': '-2147483646',
                'distinguishedName': group_dn,
                'sAMAccountName': groupname,
                'name': groupname,
                'objectCategory': 'CN=%s,%s' % (category, self.schema_dn),
                'objectClass': '**',
                'objectGUID': '**',
                'lastKnownParent': 'CN=Users,%s' % self.base_dn,
                'whenChanged': '**',
                'sAMAccountType': '268435456',
                'objectSid': '**',
                'whenCreated': '**',
                'uSNCreated': '**',
                'operatorCount': '0',
                'uSNChanged': '**',
                'instanceType': '4',
                'adminCount': '0',
                'cn': groupname }

    def test_plain_group(self):
        print "Test restored Group attributes"
        # create test group
        obj = self._create_test_group("r_group")
        guid = obj["objectGUID"][0]
        # delete the group
        self.samdb.delete(str(obj.dn))
        obj_del = self.search_guid(guid)
        # restore the Group and fetch what's restored
        self.restore_deleted_object(self.samdb, obj_del.dn, obj.dn)
        obj_restore = self.search_guid(guid)
        # check original attributes and restored one are same
        attr_orig = set(obj.keys())
        # windows restore more attributes that originally we have
        attr_orig.update(['adminCount', 'operatorCount', 'lastKnownParent'])
        attr_rest = set(obj_restore.keys())
        self.assertAttributesEqual(obj, attr_orig, obj_restore, attr_rest)
        self.assertAttributesExists(self._expected_group_attributes("r_group", str(obj.dn), "Group"), obj_restore)

    def test_group_with_members(self):
        print "Test restored Group with members attributes"
        # create test group
        usr1 = self._create_test_user("r_user_1")
        usr2 = self._create_test_user("r_user_2")
        obj = self._create_test_group("r_group", [usr1.dn, usr2.dn])
        guid = obj["objectGUID"][0]
        # delete the group
        self.samdb.delete(str(obj.dn))
        obj_del = self.search_guid(guid)
        # restore the Group and fetch what's restored
        self.restore_deleted_object(self.samdb, obj_del.dn, obj.dn)
        obj_restore = self.search_guid(guid)
        # check original attributes and restored one are same
        attr_orig = set(obj.keys())
        # windows restore more attributes that originally we have
        attr_orig.update(['adminCount', 'operatorCount', 'lastKnownParent'])
        # and does not restore following attributes
        attr_orig.remove("member")
        attr_rest = set(obj_restore.keys())
        self.assertAttributesEqual(obj, attr_orig, obj_restore, attr_rest)
        self.assertAttributesExists(self._expected_group_attributes("r_group", str(obj.dn), "Group"), obj_restore)


class RestoreContainerObjectTestCase(RestoredObjectAttributesBaseTestCase):
    """Test different scenarios for delete/reanimate OU/container objects"""

    def _expected_container_attributes(self, rdn, name, dn, category):
        if rdn == 'ou':
            lastKnownParent = '%s' % self.base_dn
        else:
            lastKnownParent = 'CN=Users,%s' % self.base_dn
        return {'dn': dn,
                'distinguishedName': dn,
                'name': name,
                'objectCategory': 'CN=%s,%s' % (category, self.schema_dn),
                'objectClass': '**',
                'objectGUID': '**',
                'lastKnownParent': lastKnownParent,
                'whenChanged': '**',
                'whenCreated': '**',
                'uSNCreated': '**',
                'uSNChanged': '**',
                'instanceType': '4',
                rdn: name }

    def _create_test_ou(self, rdn, name=None, description=None):
        ou_dn = "OU=%s,%s" % (rdn, self.base_dn)
        # delete an object if leftover from previous test
        samba.tests.delete_force(self.samdb, ou_dn)
        # create ou and return created object
        self.samdb.create_ou(ou_dn, name=name, description=description)
        return self.search_dn(ou_dn)

    def test_ou_with_name_description(self):
        print "Test OU reanimation"
        # create OU to test with
        obj = self._create_test_ou(rdn="r_ou",
                                   name="r_ou name",
                                   description="r_ou description")
        guid = obj["objectGUID"][0]
        # delete the object
        self.samdb.delete(str(obj.dn))
        obj_del = self.search_guid(guid)
        # restore the Object and fetch what's restored
        self.restore_deleted_object(self.samdb, obj_del.dn, obj.dn)
        obj_restore = self.search_guid(guid)
        # check original attributes and restored one are same
        attr_orig = set(obj.keys())
        attr_rest = set(obj_restore.keys())
        # windows restore more attributes that originally we have
        attr_orig.update(["lastKnownParent"])
        # and does not restore following attributes
        attr_orig -= set(["description"])
        self.assertAttributesEqual(obj, attr_orig, obj_restore, attr_rest)
        expected_attrs = self._expected_container_attributes("ou", "r_ou", str(obj.dn), "Organizational-Unit")
        self.assertAttributesExists(expected_attrs, obj_restore)

    def test_container(self):
        print "Test Container reanimation"
        # create test Container
        obj = self._create_object({
            "dn": "CN=r_container,CN=Users,%s" % self.base_dn,
            "objectClass": "container"
        })
        guid = obj["objectGUID"][0]
        # delete the object
        self.samdb.delete(str(obj.dn))
        obj_del = self.search_guid(guid)
        # restore the Object and fetch what's restored
        self.restore_deleted_object(self.samdb, obj_del.dn, obj.dn)
        obj_restore = self.search_guid(guid)
        # check original attributes and restored one are same
        attr_orig = set(obj.keys())
        attr_rest = set(obj_restore.keys())
        # windows restore more attributes that originally we have
        attr_orig.update(["lastKnownParent"])
        # and does not restore following attributes
        attr_orig -= set(["showInAdvancedViewOnly"])
        self.assertAttributesEqual(obj, attr_orig, obj_restore, attr_rest)
        expected_attrs = self._expected_container_attributes("cn", "r_container",
                                                             str(obj.dn), "container")
        self.assertAttributesExists(expected_attrs, obj_restore)


if __name__ == '__main__':
    unittest.main()

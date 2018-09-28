# -*- coding: utf-8 -*-
#
# Tests a corner-case involving the fromServer attribute, which is slightly
# unique: it's an Object(DS-DN) (like a one-way link), but it is also a
# mandatory attribute (for nTDSConnection). The corner-case is that the
# fromServer can potentially end up pointing to a non-existent object.
# This can happen with other one-way links, but these other one-way links
# are not mandatory attributes.
#
# Copyright (C) Andrew Bartlett 2018
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
from __future__ import print_function
import optparse
import sys
sys.path.insert(0, "bin/python")
import samba
import os
import time
import ldb
import samba.tests
from samba.tests.subunitrun import TestProgram, SubunitOptions
from samba.dcerpc import misc
from samba.provision import DEFAULTSITE

# note we must connect to the local ldb file on disk, in order to
# add system-only nTDSDSA objects
parser = optparse.OptionParser("attr_from_server.py <LDB-filepath>")
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

ldb_path = args[0]


class FromServerAttrTest(samba.tests.TestCase):
    def setUp(self):
        super(FromServerAttrTest, self).setUp()
        self.ldb = samba.tests.connect_samdb(ldb_path)

    def tearDown(self):
        super(FromServerAttrTest, self).tearDown()

    def set_attribute(self, dn, attr, value, operation=ldb.FLAG_MOD_ADD):
        """Modifies an attribute for an object"""
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, dn)
        m[attr] = ldb.MessageElement(value, operation, attr)
        self.ldb.modify(m)

    def get_object_guid(self, dn):
        res = self.ldb.search(base=dn, attrs=["objectGUID"],
                              scope=ldb.SCOPE_BASE)
        self.assertTrue(len(res) == 1)
        return str(misc.GUID(res[0]['objectGUID'][0]))

    def test_dangling_server_attr(self):
        """
        Tests a scenario where an object has a fromServer attribute that points
        to an object that no longer exists.
        """

        # add a temporary server and its associated NTDS Settings object
        config_dn = self.ldb.get_config_basedn()
        sites_dn = "CN=Sites,{0}".format(config_dn)
        servers_dn = "CN=Servers,CN={0},{1}".format(DEFAULTSITE, sites_dn)
        tmp_server = "CN=TMPSERVER,{0}".format(servers_dn)
        self.ldb.add({"dn": tmp_server, "objectclass": "server"})
        server_guid = self.get_object_guid(tmp_server)
        tmp_ntds_settings = "CN=NTDS Settings,{0}".format(tmp_server)
        self.ldb.add({"dn": tmp_ntds_settings, "objectClass": "nTDSDSA"},
                     ["relax:0"])

        # add an NTDS connection under the testenv DC that points to the tmp DC
        testenv_dc = "CN={0},{1}".format(os.environ["SERVER"], servers_dn)
        ntds_conn = "CN=Test-NTDS-Conn,CN=NTDS Settings,{0}".format(testenv_dc)
        ldif = """
dn: {dn}
objectClass: nTDSConnection
fromServer: CN=NTDS Settings,{fromServer}
options: 1
enabledConnection: TRUE
""".format(dn=ntds_conn, fromServer=tmp_server)
        self.ldb.add_ldif(ldif)
        self.addCleanup(self.ldb.delete, ntds_conn)

        # sanity-check we can modify the NTDS Connection object
        self.set_attribute(ntds_conn, 'description', 'Test-value')

        # sanity-check we can't modify the fromServer to point to a bad DN
        try:
            bad_dn = "CN=NTDS Settings,CN=BAD-DC,{0}".format(servers_dn)
            self.set_attribute(ntds_conn, 'fromServer', bad_dn,
                               operation=ldb.FLAG_MOD_REPLACE)
            self.fail("Successfully set fromServer to bad DN")
        except ldb.LdbError as err:
            enum = err.args[0]
            self.assertEqual(enum, ldb.ERR_CONSTRAINT_VIOLATION)

        # delete the tmp server, i.e. pretend we demoted it
        self.ldb.delete(tmp_server, ["tree_delete:1"])

        # check we can still see the deleted server object
        search_expr = '(objectGUID={0})'.format(server_guid)
        res = self.ldb.search(config_dn, scope=ldb.SCOPE_SUBTREE,
                              expression=search_expr,
                              controls=["show_deleted:1"])
        self.assertTrue(len(res) == 1, "Could not find deleted server entry")

        # now pretend some time has passed and the deleted server object
        # has been tombstone-expunged from the DB
        time.sleep(1)
        current_time = int(time.time())
        self.ldb.garbage_collect_tombstones([str(config_dn)], current_time,
                                            tombstone_lifetime=0)

        # repeat the search to sanity-check the deleted object is really gone
        res = self.ldb.search(config_dn, scope=ldb.SCOPE_SUBTREE,
                              expression=search_expr,
                              controls=["show_deleted:1"])
        self.assertTrue(len(res) == 0, "Did not expunge deleted server")

        # the nTDSConnection now has a (mandatory) fromServer attribute that
        # points to an object that no longer exists. Now try to modify an
        # unrelated attribute on the nTDSConnection
        try:
            self.set_attribute(ntds_conn, 'description', 'Test-value-2',
                               operation=ldb.FLAG_MOD_REPLACE)
        except ldb.LdbError as err:
            print(err)
            self.fail("Could not modify NTDS connection")


TestProgram(module=__name__, opts=subunitopts)

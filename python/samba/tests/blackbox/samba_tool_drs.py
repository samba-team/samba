# Blackbox tests for "samba-tool drs" command
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
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

"""Blackbox tests for samba-tool drs."""

import samba.tests
import shutil
import os
import ldb

class SambaToolDrsTests(samba.tests.BlackboxTestCase):
    """Blackbox test case for samba-tool drs."""

    def setUp(self):
        super(SambaToolDrsTests, self).setUp()

        self.dc1 = samba.tests.env_get_var_value("DC1")
        self.dc2 = samba.tests.env_get_var_value("DC2")

        creds = self.get_credentials()
        self.cmdline_creds = "-U%s/%s%%%s" % (creds.get_domain(),
                                              creds.get_username(), creds.get_password())

    def _get_rootDSE(self, dc, ldap_only=True):
        samdb = samba.tests.connect_samdb(dc, lp=self.get_loadparm(),
                                          credentials=self.get_credentials(),
                                          ldap_only=ldap_only)
        return samdb.search(base="", scope=samba.tests.ldb.SCOPE_BASE)[0]

    def test_samba_tool_bind(self):
        """Tests 'samba-tool drs bind' command."""

        # Output should be like:
        #      Extensions supported:
        #        <list-of-supported-extensions>
        #      Site GUID: <GUID>
        #      Repl epoch: 0
        out = self.check_output("samba-tool drs bind %s %s" % (self.dc1,
                                                               self.cmdline_creds))
        self.assertTrue("Site GUID:" in out)
        self.assertTrue("Repl epoch:" in out)

    def test_samba_tool_kcc(self):
        """Tests 'samba-tool drs kcc' command."""

        # Output should be like 'Consistency check on <DC> successful.'
        out = self.check_output("samba-tool drs kcc %s %s" % (self.dc1,
                                                              self.cmdline_creds))
        self.assertTrue("Consistency check on" in out)
        self.assertTrue("successful" in out)

    def test_samba_tool_showrepl(self):
        """Tests 'samba-tool drs showrepl' command.
        """
        # Output should be like:
        #      <site-name>/<domain-name>
        #      DSA Options: <hex-options>
        #      DSA object GUID: <DSA-object-GUID>
        #      DSA invocationId: <DSA-invocationId>
        #      <Inbound-connections-list>
        #      <Outbound-connections-list>
        #      <KCC-objects>
        #      ...
        #   TODO: Perhaps we should check at least for
        #         DSA's objectGUDI and invocationId
        out = self.check_output("samba-tool drs showrepl %s %s" % (self.dc1,
                                                                   self.cmdline_creds))
        self.assertTrue("DSA Options:" in out)
        self.assertTrue("DSA object GUID:" in out)
        self.assertTrue("DSA invocationId:" in out)

    def test_samba_tool_options(self):
        """Tests 'samba-tool drs options' command
        """
        # Output should be like 'Current DSA options: IS_GC <OTHER_FLAGS>'
        out = self.check_output("samba-tool drs options %s %s" % (self.dc1,
                                                                  self.cmdline_creds))
        self.assertTrue("Current DSA options:" in out)

    def test_samba_tool_replicate(self):
        """Tests 'samba-tool drs replicate' command."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was successful.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]
        out = self.check_output("samba-tool drs replicate %s %s %s %s" % (self.dc1,
                                                                          self.dc2,
                                                                          nc_name,
                                                                          self.cmdline_creds))
        self.assertTrue("Replicate from" in out)
        self.assertTrue("was successful" in out)

    def test_samba_tool_drs_clone_dc(self):
        """Tests 'samba-tool drs clone-dc-database' command."""
        server_rootdse = self._get_rootDSE(self.dc1)
        server_nc_name = server_rootdse["defaultNamingContext"]
        server_ds_name = server_rootdse["dsServiceName"]
        server_ldap_service_name = str(server_rootdse["ldapServiceName"][0])
        server_realm = server_ldap_service_name.split(":")[0]
        creds = self.get_credentials()
        out = self.check_output("samba-tool drs clone-dc-database %s --server=%s %s --targetdir=%s"
                                % (server_realm,
                                   self.dc1,
                                   self.cmdline_creds,
                                   self.tempdir))
        ldb_rootdse = self._get_rootDSE("tdb://" + os.path.join(self.tempdir, "private", "sam.ldb"), ldap_only=False)
        nc_name = ldb_rootdse["defaultNamingContext"]
        ds_name = ldb_rootdse["dsServiceName"]
        ldap_service_name = str(server_rootdse["ldapServiceName"][0])
        self.assertEqual(nc_name, server_nc_name)
        # The clone should pretend to be the source server
        self.assertEqual(ds_name, server_ds_name)
        self.assertEqual(ldap_service_name, server_ldap_service_name)

        samdb = samba.tests.connect_samdb("tdb://" + os.path.join(self.tempdir, "private", "sam.ldb"),
                                          ldap_only=False, lp=self.get_loadparm())
        def get_krbtgt_pw():
            krbtgt_pw = samdb.searchone("unicodePwd", "cn=krbtgt,CN=users,%s" % nc_name)
        self.assertRaises(KeyError, get_krbtgt_pw)

        server_dn = samdb.searchone("serverReferenceBL", "cn=%s,ou=domain controllers,%s" % (self.dc2, server_nc_name))
        ntds_guid = samdb.searchone("objectGUID", "cn=ntds settings,%s" % server_dn)

        res = samdb.search(base=str(server_nc_name),
                           expression="(&(objectclass=user)(cn=dns-%s))" % (self.dc2),
                           attrs=[], scope=ldb.SCOPE_SUBTREE)
        if len(res) == 1:
            dns_obj = res[0]
        else:
            dns_obj = None

        # While we have this cloned, try demoting the other server on the clone, by GUID
        out = self.check_output("samba-tool domain demote --remove-other-dead-server=%s -H %s/private/sam.ldb"
                                % (ntds_guid,
                                   self.tempdir))

        # Check some of the objects that should have been removed
        def check_machine_obj():
            samdb.searchone("CN", "cn=%s,ou=domain controllers,%s" % (self.dc2, server_nc_name))
        self.assertRaises(ldb.LdbError, check_machine_obj)

        def check_server_obj():
            samdb.searchone("CN", server_dn)
        self.assertRaises(ldb.LdbError, check_server_obj)

        def check_ntds_guid():
            samdb.searchone("CN", "<GUID=%s>" % ntds_guid)
        self.assertRaises(ldb.LdbError, check_ntds_guid)

        if dns_obj is not None:
            # Check some of the objects that should have been removed
            def check_dns_account_obj():
                samdb.search(base=dns_obj.dn, scope=ldb.SCOPE_BASE,
                             attrs=[])
            self.assertRaises(ldb.LdbError, check_dns_account_obj)

        shutil.rmtree(os.path.join(self.tempdir, "private"))
        shutil.rmtree(os.path.join(self.tempdir, "etc"))
        shutil.rmtree(os.path.join(self.tempdir, "msg.lock"))
        os.remove(os.path.join(self.tempdir, "names.tdb"))
        shutil.rmtree(os.path.join(self.tempdir, "state"))

    def test_samba_tool_drs_clone_dc_secrets(self):
        """Tests 'samba-tool drs clone-dc-database --include-secrets' command ."""
        server_rootdse = self._get_rootDSE(self.dc1)
        server_nc_name = server_rootdse["defaultNamingContext"]
        server_ds_name = server_rootdse["dsServiceName"]
        server_ldap_service_name = str(server_rootdse["ldapServiceName"][0])
        server_realm = server_ldap_service_name.split(":")[0]
        creds = self.get_credentials()
        out = self.check_output("samba-tool drs clone-dc-database %s --server=%s %s --targetdir=%s --include-secrets"
                                % (server_realm,
                                   self.dc1,
                                   self.cmdline_creds,
                                   self.tempdir))
        ldb_rootdse = self._get_rootDSE("tdb://" + os.path.join(self.tempdir, "private", "sam.ldb"), ldap_only=False)
        nc_name = ldb_rootdse["defaultNamingContext"]
        config_nc_name = ldb_rootdse["configurationNamingContext"]
        ds_name = ldb_rootdse["dsServiceName"]
        ldap_service_name = str(server_rootdse["ldapServiceName"][0])

        samdb = samba.tests.connect_samdb("tdb://" + os.path.join(self.tempdir, "private", "sam.ldb"),
                                          ldap_only=False, lp=self.get_loadparm())
        krbtgt_pw = samdb.searchone("unicodePwd", "cn=krbtgt,CN=users,%s" % nc_name)
        self.assertIsNotNone(krbtgt_pw)

        self.assertEqual(nc_name, server_nc_name)
        # The clone should pretend to be the source server
        self.assertEqual(ds_name, server_ds_name)
        self.assertEqual(ldap_service_name, server_ldap_service_name)

        server_dn = samdb.searchone("serverReferenceBL", "cn=%s,ou=domain controllers,%s" % (self.dc2, server_nc_name))
        ntds_guid = samdb.searchone("objectGUID", "cn=ntds settings,%s" % server_dn)

        res = samdb.search(base=str(server_nc_name),
                           expression="(&(objectclass=user)(cn=dns-%s))" % (self.dc2),
                           attrs=[], scope=ldb.SCOPE_SUBTREE)
        if len(res) == 1:
            dns_obj = res[0]
        else:
            dns_obj = None

        def demote_self():
            # While we have this cloned, try demoting the other server on the clone
            out = self.check_output("samba-tool domain demote --remove-other-dead-server=%s -H %s/private/sam.ldb"
                                % (self.dc1,
                                   self.tempdir))
        self.assertRaises(samba.tests.BlackboxProcessError, demote_self)

        # While we have this cloned, try demoting the other server on the clone
        out = self.check_output("samba-tool domain demote --remove-other-dead-server=%s -H %s/private/sam.ldb"
                                % (self.dc2,
                                   self.tempdir))

        # Check some of the objects that should have been removed
        def check_machine_obj():
            samdb.searchone("CN", "cn=%s,ou=domain controllers,%s" % (self.dc2, server_nc_name))
        self.assertRaises(ldb.LdbError, check_machine_obj)

        def check_server_obj():
            samdb.searchone("CN", server_dn)
        self.assertRaises(ldb.LdbError, check_server_obj)

        def check_ntds_guid():
            samdb.searchone("CN", "<GUID=%s>" % ntds_guid)
        self.assertRaises(ldb.LdbError, check_ntds_guid)

        if dns_obj is not None:
            # Check some of the objects that should have been removed
            def check_dns_account_obj():
                samdb.search(base=dns_obj.dn, scope=ldb.SCOPE_BASE,
                             attrs=[])
            self.assertRaises(ldb.LdbError, check_dns_account_obj)

        shutil.rmtree(os.path.join(self.tempdir, "private"))
        shutil.rmtree(os.path.join(self.tempdir, "etc"))
        shutil.rmtree(os.path.join(self.tempdir, "msg.lock"))
        os.remove(os.path.join(self.tempdir, "names.tdb"))
        shutil.rmtree(os.path.join(self.tempdir, "state"))

    def test_samba_tool_drs_clone_dc_secrets_without_targetdir(self):
        """Tests 'samba-tool drs clone-dc-database' command without --targetdir."""
        server_rootdse = self._get_rootDSE(self.dc1)
        server_ldap_service_name = str(server_rootdse["ldapServiceName"][0])
        server_realm = server_ldap_service_name.split(":")[0]
        creds = self.get_credentials()
        def attempt_clone():
            out = self.check_output("samba-tool drs clone-dc-database %s --server=%s %s"
                                    % (server_realm,
                                       self.dc1,
                                       self.cmdline_creds))
        self.assertRaises(samba.tests.BlackboxProcessError, attempt_clone)

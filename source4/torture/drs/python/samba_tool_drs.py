# Blackbox tests for "samba-tool drs" command
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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
import drs_base


class SambaToolDrsTests(drs_base.DrsBaseTestCase):
    """Blackbox test case for samba-tool drs."""

    def setUp(self):
        super(SambaToolDrsTests, self).setUp()

        self.dc1 = samba.tests.env_get_var_value("DC1")
        self.dc2 = samba.tests.env_get_var_value("DC2")

        creds = self.get_credentials()
        self.cmdline_creds = "-U%s/%s%%%s" % (creds.get_domain(),
                                              creds.get_username(), creds.get_password())

    def tearDown(self):
        self._enable_inbound_repl(self.dnsname_dc1)
        self._enable_inbound_repl(self.dnsname_dc2)

        try:
            shutil.rmtree(os.path.join(self.tempdir, "private"))
            shutil.rmtree(os.path.join(self.tempdir, "etc"))
            shutil.rmtree(os.path.join(self.tempdir, "msg.lock"))
            os.remove(os.path.join(self.tempdir, "names.tdb"))
            shutil.rmtree(os.path.join(self.tempdir, "state"))
            shutil.rmtree(os.path.join(self.tempdir, "bind-dns"))
        except Exception:
            pass

        super(SambaToolDrsTests, self).tearDown()

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
        self.assertTrue("Site GUID:" in out.decode('utf8'))
        self.assertTrue("Repl epoch:" in out.decode('utf8'))

    def test_samba_tool_kcc(self):
        """Tests 'samba-tool drs kcc' command."""

        # Output should be like 'Consistency check on <DC> successful.'
        out = self.check_output("samba-tool drs kcc %s %s" % (self.dc1,
                                                              self.cmdline_creds))
        self.assertTrue(b"Consistency check on" in out)
        self.assertTrue(b"successful" in out)

    def test_samba_tool_options(self):
        """Tests 'samba-tool drs options' command
        """
        # Output should be like 'Current DSA options: IS_GC <OTHER_FLAGS>'
        out = self.check_output("samba-tool drs options %s %s" % (self.dc1,
                                                                  self.cmdline_creds))
        self.assertTrue(b"Current DSA options:" in out)

    def test_samba_tool_replicate(self):
        """Tests 'samba-tool drs replicate' command."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was successful.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]
        out = self.check_output("samba-tool drs replicate %s %s %s %s" % (self.dc1,
                                                                          self.dc2,
                                                                          nc_name,
                                                                          self.cmdline_creds))
        self.assertTrue(b"Replicate from" in out)
        self.assertTrue(b"was successful" in out)

    def test_samba_tool_replicate_async(self):
        """Tests 'samba-tool drs replicate --async-op' command."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was started.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]
        out = self.check_output("samba-tool drs replicate --async-op %s %s %s %s" % (self.dc1,
                                                                                     self.dc2,
                                                                                     nc_name,
                                                                                     self.cmdline_creds))
        self.assertTrue(b"Replicate from" in out)
        self.assertTrue(b"was started" in out)

    def test_samba_tool_replicate_local_online(self):
        """Tests 'samba-tool drs replicate --local-online' command."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was successful.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]
        out = self.check_output("samba-tool drs replicate --local-online %s %s %s" % (self.dc1,
                                                                                      self.dc2,
                                                                                      nc_name))
        self.assertTrue(b"Replicate from" in out)
        self.assertTrue(b"was successful" in out)

    def test_samba_tool_replicate_local_online_async(self):
        """Tests 'samba-tool drs replicate --local-online --async-op' command."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was started.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]
        out = self.check_output("samba-tool drs replicate --local-online --async-op %s %s %s" % (self.dc1,
                                                                                                 self.dc2,
                                                                                                 nc_name))
        self.assertTrue(b"Replicate from" in out)
        self.assertTrue(b"was started" in out)

    def test_samba_tool_replicate_local_machine_creds(self):
        """Tests 'samba-tool drs replicate --local -P' command (uses machine creds)."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was successful.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]
        out = self.check_output("samba-tool drs replicate -P --local %s %s %s" % (self.dc1,
                                                                                  self.dc2,
                                                                                  nc_name))
        self.assertTrue(b"Incremental" in out)
        self.assertTrue(b"was successful" in out)

    def test_samba_tool_replicate_local(self):
        """Tests 'samba-tool drs replicate --local' command (uses machine creds)."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was successful.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]

        def get_num_obj_links(output):
            num_objs = None
            num_links = None
            for word in output.decode('utf8').split(" "):
                try:
                    int(word)
                    if num_objs is None:
                        num_objs = int(word)
                    elif num_links is None:
                        num_links = int(word)
                except ValueError:
                    pass

            return (num_objs, num_links)

        out = self.check_output("samba-tool drs replicate --local --full-sync %s %s %s %s"
                                % (self.dc1, self.dc2, nc_name, self.cmdline_creds))
        self.assertTrue(b"was successful" in out)
        self.assertTrue(b"Full" in out)

        (first_obj, _) = get_num_obj_links(out)

        out = self.check_output("samba-tool drs replicate --local %s %s %s %s"
                                % (self.dc1, self.dc2, nc_name, self.cmdline_creds))
        self.assertTrue(b"was successful" in out)
        self.assertTrue(b"Incremental" in out)

        (second_obj, _) = get_num_obj_links(out)

        self.assertTrue(first_obj > second_obj)

        server_rootdse = self._get_rootDSE(self.dc1)
        server_nc_name = server_rootdse["defaultNamingContext"]
        server_ds_name = server_rootdse["dsServiceName"]
        server_ldap_service_name = str(server_rootdse["ldapServiceName"][0])
        server_realm = server_ldap_service_name.split(":")[0]
        creds = self.get_credentials()

        # We have to give it a different netbiosname every time
        # it runs, otherwise the collision causes strange issues
        # to happen. This should be different on different environments.
        netbiosname = "test" + self.dc2
        if len(netbiosname) > 15:
            netbiosname = netbiosname[:15]

        out = self.check_output("samba-tool domain join %s dc --server=%s %s --targetdir=%s --option=netbiosname=%s"
                                % (server_realm, self.dc1, self.cmdline_creds, self.tempdir, netbiosname))

        new_dc_config_file = "%s/etc/smb.conf" % self.tempdir

        self.check_output("samba-tool drs replicate --local %s %s %s %s -s %s"
                          % ("invalid", self.dc1, nc_name,
                             self.cmdline_creds, new_dc_config_file))

        self._disable_inbound_repl(self.dnsname_dc1)
        self._disable_inbound_repl(self.dnsname_dc2)

        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2)

        # add an object with link on dc1
        group_name = "group-repl-local-%s" % self.dc2
        user_name = "user-repl-local-%s" % self.dc2

        self.check_output("samba-tool group add %s %s -H ldap://%s"
                          % (group_name, self.cmdline_creds, self.dc1))
        self.check_output("samba-tool user add %s %s --random-password -H ldap://%s"
                          % (user_name, self.cmdline_creds, self.dc1))
        self.check_output("samba-tool group addmembers %s %s %s -H ldap://%s"
                          % (group_name, user_name, self.cmdline_creds, self.dc1))

        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1)

        # pull that change with --local into local db from dc1: should send link and some objects
        out = self.check_output("samba-tool drs replicate --local %s %s %s %s -s %s"
                                % ("invalid", self.dc1, nc_name,
                                   self.cmdline_creds, new_dc_config_file))

        (obj_1, link_1) = get_num_obj_links(out)

        self.assertGreaterEqual(obj_1, 2)
        self.assertEqual(link_1, 1)

        # pull that change with --local into local db from dc2: shouldn't send link or object
        # as we sent an up-to-dateness vector showing that we had already synced with DC1
        out = self.check_output("samba-tool drs replicate --local %s %s %s %s -s %s"
                                % ("invalid", self.dc2, nc_name,
                                   self.cmdline_creds, new_dc_config_file))

        (obj_2, link_2) = get_num_obj_links(out)

        self.assertEqual(obj_2, 0)
        self.assertEqual(link_2, 0)

        self.check_output("samba-tool domain demote --remove-other-dead-server=%s -H ldap://%s %s -s %s"
                          % (netbiosname, self.dc1, self.cmdline_creds, new_dc_config_file))

    def test_samba_tool_replicate_machine_creds_P(self):
        """Tests 'samba-tool drs replicate -P' command with machine creds."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was successful.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]
        out = self.check_output("samba-tool drs replicate -P %s %s %s" % (self.dc1,
                                                                          self.dc2,
                                                                          nc_name))
        self.assertTrue(b"Replicate from" in out)
        self.assertTrue(b"was successful" in out)

    def test_samba_tool_replicate_machine_creds(self):
        """Tests 'samba-tool drs replicate' command with implicit machine creds."""

        # Output should be like 'Replicate from <DC-SRC> to <DC-DEST> was successful.'
        nc_name = self._get_rootDSE(self.dc1)["defaultNamingContext"]
        out = self.check_output("samba-tool drs replicate %s %s %s" % (self.dc1,
                                                                       self.dc2,
                                                                       nc_name))
        self.assertTrue(b"Replicate from" in out)
        self.assertTrue(b"was successful" in out)

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
        ldb_rootdse = self._get_rootDSE("ldb://" + os.path.join(self.tempdir, "private", "sam.ldb"), ldap_only=False)
        nc_name = ldb_rootdse["defaultNamingContext"]
        ds_name = ldb_rootdse["dsServiceName"]
        ldap_service_name = str(server_rootdse["ldapServiceName"][0])
        self.assertEqual(nc_name, server_nc_name)
        # The clone should pretend to be the source server
        self.assertEqual(ds_name, server_ds_name)
        self.assertEqual(ldap_service_name, server_ldap_service_name)

        samdb = samba.tests.connect_samdb("ldb://" + os.path.join(self.tempdir, "private", "sam.ldb"),
                                          ldap_only=False, lp=self.get_loadparm())

        def get_krbtgt_pw():
            krbtgt_pw = samdb.searchone("unicodePwd", "cn=krbtgt,CN=users,%s" % nc_name)
        self.assertRaises(KeyError, get_krbtgt_pw)

        server_dn = samdb.searchone("serverReferenceBL", "cn=%s,ou=domain controllers,%s" % (self.dc2, server_nc_name)).decode('utf8')
        ntds_guid = samdb.searchone("objectGUID", "cn=ntds settings,%s" % server_dn).decode('utf8')

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
        ldb_rootdse = self._get_rootDSE("ldb://" + os.path.join(self.tempdir, "private", "sam.ldb"), ldap_only=False)
        nc_name = ldb_rootdse["defaultNamingContext"]
        config_nc_name = ldb_rootdse["configurationNamingContext"]
        ds_name = ldb_rootdse["dsServiceName"]
        ldap_service_name = str(server_rootdse["ldapServiceName"][0])

        samdb = samba.tests.connect_samdb("ldb://" + os.path.join(self.tempdir, "private", "sam.ldb"),
                                          ldap_only=False, lp=self.get_loadparm())
        krbtgt_pw = samdb.searchone("unicodePwd", "cn=krbtgt,CN=users,%s" % nc_name)
        self.assertIsNotNone(krbtgt_pw)

        self.assertEqual(nc_name, server_nc_name)
        # The clone should pretend to be the source server
        self.assertEqual(ds_name, server_ds_name)
        self.assertEqual(ldap_service_name, server_ldap_service_name)

        server_dn = samdb.searchone("serverReferenceBL", "cn=%s,ou=domain controllers,%s" % (self.dc2, server_nc_name)).decode('utf8')
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
        out = self.check_output("samba-tool domain demote --remove-other-dead-server=%s -H ldb://%s/private/sam.ldb"
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

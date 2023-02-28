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
import os
import ldb
import drs_base
import random

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

        self.rm_files('names.tdb', allow_missing=True)
        self.rm_dirs('etc', 'msg.lock', 'private', 'state', 'bind-dns',
                     allow_missing=True)

        super(SambaToolDrsTests, self).tearDown()

    # This test is for the Samba 4.5 emulation servers (but runs
    # against a normal server as well) that fail to correctly
    # implement DRSUAPI_DRS_GET_ANC when DRSUAPI_DRS_CRITICAL_ONLY is
    # set.
    def test_samba_tool_drs_clone_dc_critical_object_chain(self):
        """Tests 'samba-tool drs clone-dc-database' command with a Critical/non-critical/critical object chain."""

        samdb = samba.tests.connect_samdb(self.dc1, lp=self.get_loadparm(),
                                          credentials=self.get_credentials(),
                                          ldap_only=True)
        server_rootdse = samdb.search(base="",
                                      scope=samba.tests.ldb.SCOPE_BASE)[0]
        nc_name = server_rootdse["defaultNamingContext"][0]
        server_ldap_service_name = str(server_rootdse["ldapServiceName"][0])
        server_realm = server_ldap_service_name.split(":")[0]

        not_critical_dn = f"OU=not-critical{random.randint(1, 10000000)},{nc_name}"
        samdb.create_ou(not_critical_dn)
        self.addCleanup(samdb.delete,
                        not_critical_dn)
        domain_sid = samdb.get_domain_sid()
        admin_sid = f"{domain_sid}-500"
        samdb.rename(f"<SID={admin_sid}>",
                     f"cn=administrator,{not_critical_dn}")
        self.addCleanup(samdb.rename,
                        f"<SID={admin_sid}>",
                        f"cn=administrator,cn=users,{nc_name}")

        try:
            self.check_output("samba-tool drs clone-dc-database %s --server=%s %s --targetdir=%s"
                              % (server_realm,
                                 self.dc1,
                                 self.cmdline_creds,
                                 self.tempdir))
        except samba.tests.BlackboxProcessError as e:
            self.fail("Error calling samba-tool: %s" % e)

        local_samdb = samba.tests.connect_samdb("ldb://" + os.path.join(self.tempdir, "private", "sam.ldb"),
                                          ldap_only=False, lp=self.get_loadparm())

        # Check administrator was replicated and is in the right place
        res = local_samdb.search(base=str(nc_name),
                                 expression="(&(objectclass=user)(cn=administrator))",
                                 attrs=[], scope=ldb.SCOPE_SUBTREE)
        self.assertEquals(len(res), 1)

        admin_obj = res[0]

        self.assertEquals(admin_obj.dn, ldb.Dn(samdb, f"cn=administrator,{not_critical_dn}"))

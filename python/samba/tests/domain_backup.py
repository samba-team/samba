# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org>
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
from samba import provision, param
import tarfile
import os
import shutil
from samba.tests import (env_loadparm, create_test_ou, BlackboxProcessError,
                         BlackboxTestCase, connect_samdb)
import ldb
from samba.samdb import SamDB
from samba.auth import system_session
from samba import Ldb, dn_from_dns_name
from samba.netcmd.fsmo import get_fsmo_roleowner
import re
from samba import sites
from samba.dsdb import _dsdb_load_udv_v2


def get_prim_dom(secrets_path, lp):
    secrets_ldb = Ldb(secrets_path, session_info=system_session(), lp=lp)
    return secrets_ldb.search(base="CN=Primary Domains",
                              attrs=['objectClass', 'samAccountName',
                                     'secret', 'msDS-KeyVersionNumber'],
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(objectClass=kerberosSecret)")

# The backup tests require that a completely clean LoadParm object gets used
# for the restore. Otherwise the same global LP gets re-used, and the LP
# settings can bleed from one test case to another.
# To do this, these tests should use check_output(), which executes the command
# in a separate process (as opposed to runcmd(), runsubcmd()).
# So although this is a samba-tool test, we don't inherit from SambaToolCmdTest
# so that we never inadvertently use .runcmd() by accident.
class DomainBackupBase(BlackboxTestCase):

    def setUp(self):
        super(DomainBackupBase, self).setUp()

        server = os.environ["DC_SERVER"]
        self.user_auth = "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                       os.environ["DC_PASSWORD"])

        # LDB connection to the original server being backed up
        self.ldb = connect_samdb("ldap://%s" % server)
        self.new_server = "BACKUPSERV"
        self.server = server.upper()
        self.base_cmd = None
        self.backup_markers = ['sidForRestore', 'backupDate']
        self.restore_domain = os.environ["DOMAIN"]
        self.restore_realm = os.environ["REALM"]
        self.backend = None

    def use_backend(self, backend):
        """Explicitly set the DB backend that the backup should use"""
        self.backend = backend
        self.base_cmd += ["--backend-store=" + backend]

    def get_expected_partitions(self, samdb):
        basedn = str(samdb.get_default_basedn())
        config_dn = "CN=Configuration,%s" % basedn
        return [basedn, config_dn, "CN=Schema,%s" % config_dn,
                "DC=DomainDnsZones,%s" % basedn,
                "DC=ForestDnsZones,%s" % basedn]

    def assert_partitions_present(self, samdb):
        """Asserts all expected partitions are present in the backup samdb"""
        res = samdb.search(base="", scope=ldb.SCOPE_BASE,
                           attrs=['namingContexts'])
        actual_ncs = [str(r) for r in res[0].get('namingContexts')]

        expected_ncs = self.get_expected_partitions(samdb)

        for nc in expected_ncs:
            self.assertTrue(nc in actual_ncs,
                            "%s not in %s" % (nc, str(actual_ncs)))

    def assert_repl_uptodate_vector(self, samdb):
        """Asserts an replUpToDateVector entry exists for the original DC"""
        orig_invoc_id = self.ldb.get_invocation_id()
        expected_ncs = self.get_expected_partitions(samdb)

        # loop through the partitions and check the upToDateness vector
        for nc in expected_ncs:
            found = False
            for cursor in _dsdb_load_udv_v2(samdb, nc):
                if orig_invoc_id == str(cursor.source_dsa_invocation_id):
                    found = True
                    break
            self.assertTrue(found, "Couldn't find UDTV for original DC")

    def assert_dcs_present(self, samdb, expected_server, expected_count=None):
        """Checks that the expected server is present in the restored DB"""
        search_expr = "(&(objectClass=Server)(serverReference=*))"
        res = samdb.search(samdb.get_config_basedn(),
                           scope=ldb.SCOPE_SUBTREE,
                           expression=search_expr)
        server_found = False
        for msg in res:
            if expected_server in str(msg.dn):
                server_found = True

        self.assertTrue(server_found,
                        "Could not find %s server" % expected_server)

        if expected_count:
            self.assertTrue(len(res) == expected_count)

    def restore_dir(self):
        extract_dir = os.path.join(self.tempdir, 'tree')
        if not os.path.exists(extract_dir):
            os.mkdir(extract_dir)
            self.addCleanup(shutil.rmtree, extract_dir)
        return extract_dir

    def untar_backup(self, backup_file):
        """Untar the backup file's raw contents (i.e. not a proper restore)"""
        extract_dir = self.restore_dir()
        with tarfile.open(backup_file) as tf:
            tf.extractall(extract_dir)

    def _test_backup_untar(self, primary_domain_secrets=0):
        """Creates a backup, untars the raw files, and sanity-checks the DB"""
        backup_file = self.create_backup()
        self.untar_backup(backup_file)

        private_dir = os.path.join(self.restore_dir(), "private")
        samdb_path = os.path.join(private_dir, "sam.ldb")
        lp = env_loadparm()
        samdb = SamDB(url=samdb_path, session_info=system_session(), lp=lp)

        # check that backup markers were added to the DB
        res = samdb.search(base=ldb.Dn(samdb, "@SAMBA_DSDB"),
                           scope=ldb.SCOPE_BASE,
                           attrs=self.backup_markers)
        self.assertEqual(len(res), 1)
        for marker in self.backup_markers:
            self.assertIsNotNone(res[0].get(marker),
                                 "%s backup marker missing" % marker)

        # check the secrets.ldb entry for the primary domain. (Online/clone
        # backups shouldn't have this, as they never got it during the backup)
        secrets_path = os.path.join(private_dir, "secrets.ldb")
        res = get_prim_dom(secrets_path, lp)
        self.assertEqual(len(res), primary_domain_secrets)

        # sanity-check that all the partitions got backed up
        self.assert_partitions_present(samdb)

    def _test_backup_restore(self):
        """Does a backup/restore, with specific checks of the resulting DB"""
        backup_file = self.create_backup()
        self.restore_backup(backup_file)
        lp = self.check_restored_smbconf()
        self.check_restored_database(lp)

    def _test_backup_restore_no_secrets(self):
        """Does a backup/restore with secrets excluded from the resulting DB"""

        # exclude secrets when we create the backup
        backup_file = self.create_backup(extra_args=["--no-secrets"])
        self.restore_backup(backup_file)
        lp = self.check_restored_smbconf()

        # assert that we don't find user secrets in the DB
        self.check_restored_database(lp, expect_secrets=False)

    def _test_backup_restore_into_site(self):
        """Does a backup and restores into a non-default site"""

        # create a new non-default site
        sitename = "Test-Site-For-Backups"
        sites.create_site(self.ldb, self.ldb.get_config_basedn(), sitename)
        self.addCleanup(sites.delete_site, self.ldb,
                        self.ldb.get_config_basedn(), sitename)

        # restore the backup DC into the site we just created
        backup_file = self.create_backup()
        self.restore_backup(backup_file, ["--site=" + sitename])

        lp = self.check_restored_smbconf()
        restored_ldb = self.check_restored_database(lp)

        # check the restored DC was added to the site we created, i.e. there's
        # an entry matching the new DC sitting underneath the site DN
        site_dn = "CN={0},CN=Sites,{1}".format(sitename,
                                               restored_ldb.get_config_basedn())
        match_server = "(&(objectClass=server)(cn={0}))".format(self.new_server)
        res = restored_ldb.search(site_dn, scope=ldb.SCOPE_SUBTREE,
                                  expression=match_server)
        self.assertTrue(len(res) == 1,
                        "Failed to find new DC under site")

    def create_smbconf(self, settings):
        """Creates a very basic smb.conf to pass to the restore tool"""

        # without the testenv config's settings, the NTACL backup_restore()
        # operation will fail (because we're not root). So first suck in all
        # testenv's settings, so we retain these in the new config. Note we
        # use a non-global LP so that these settings don't leak into other
        # places we use LoadParms
        testenv_conf = os.environ["SMB_CONF_PATH"]
        local_lp = param.LoadParm(filename_for_non_global_lp=testenv_conf)

        # add the new settings to the LP, then write the settings to file
        for key, val in settings.items():
            local_lp.set(key, val)

        new_smbconf = os.path.join(self.tempdir, "smb.conf")
        local_lp.dump(False, new_smbconf)

        self.addCleanup(os.remove, new_smbconf)
        return new_smbconf

    def _test_backup_restore_with_conf(self):
        """Checks smb.conf values passed to the restore are retained"""
        backup_file = self.create_backup()

        # create an smb.conf that we pass to the restore. The netbios/state
        # dir should get overridden by the restore, the other settings should
        # trickle through into the restored dir's smb.conf
        settings = {'state directory': '/var/run',
                    'netbios name': 'FOOBAR',
                    'workgroup': 'NOTMYDOMAIN',
                    'realm': 'NOT.MY.REALM'}
        assert_settings = {'drs: max link sync': '275',
                           'prefork children': '7'}
        settings.update(assert_settings)
        smbconf = self.create_smbconf(settings)

        self.restore_backup(backup_file, ["--configfile=" + smbconf])

        # this will check netbios name/state dir
        lp = self.check_restored_smbconf()
        self.check_restored_database(lp)

        # check the remaining settings are still intact
        for key, val in assert_settings.items():
            self.assertEqual(str(lp.get(key)), val,
                             "'%s' was '%s' in smb.conf" % (key, lp.get(key)))

    def check_restored_smbconf(self):
        """Sanity-check important smb.conf values are restored correctly"""
        smbconf = os.path.join(self.restore_dir(), "etc", "smb.conf")
        bkp_lp = param.LoadParm(filename_for_non_global_lp=smbconf)
        self.assertEqual(bkp_lp.get('netbios name'), self.new_server)
        self.assertEqual(bkp_lp.get('workgroup'), self.restore_domain)
        self.assertEqual(bkp_lp.get('realm'), self.restore_realm.upper())

        # we restore with a fixed directory structure, so we can sanity-check
        # that the core filepaths settings are what we expect them to be
        private_dir = os.path.join(self.restore_dir(), "private")
        self.assertEqual(bkp_lp.get('private dir'), private_dir)
        state_dir = os.path.join(self.restore_dir(), "state")
        self.assertEqual(bkp_lp.get('state directory'), state_dir)
        return bkp_lp

    def check_restored_database(self, bkp_lp, expect_secrets=True):
        paths = provision.provision_paths_from_lp(bkp_lp, bkp_lp.get("realm"))

        bkp_pd = get_prim_dom(paths.secrets, bkp_lp)
        self.assertEqual(len(bkp_pd), 1)
        acn = bkp_pd[0].get('samAccountName')
        self.assertIsNotNone(acn)
        self.assertEqual(str(acn[0]), self.new_server + '$')
        self.assertIsNotNone(bkp_pd[0].get('secret'))

        samdb = SamDB(url=paths.samdb, session_info=system_session(),
                      lp=bkp_lp, credentials=self.get_credentials())

        # check that the backup markers have been removed from the restored DB
        res = samdb.search(base=ldb.Dn(samdb, "@SAMBA_DSDB"),
                           scope=ldb.SCOPE_BASE,
                           attrs=self.backup_markers)
        self.assertEqual(len(res), 1)
        for marker in self.backup_markers:
            self.assertIsNone(res[0].get(marker),
                              "%s backup-marker left behind" % marker)

        # check that the repsFrom and repsTo values have been removed
        # from the restored DB
        res = samdb.search(base=samdb.get_default_basedn(),
                           scope=ldb.SCOPE_BASE,
                           attrs=['repsFrom', 'repsTo'])
        self.assertEqual(len(res), 1)
        self.assertIsNone(res[0].get('repsFrom'))
        self.assertIsNone(res[0].get('repsTo'))

        res = samdb.search(base=samdb.get_config_basedn(),
                           scope=ldb.SCOPE_BASE,
                           attrs=['repsFrom', 'repsTo'])
        self.assertEqual(len(res), 1)
        self.assertIsNone(res[0].get('repsFrom'))
        self.assertIsNone(res[0].get('repsTo'))

        # check the DB is using the backend we supplied
        if self.backend:
            res = samdb.search(base="@PARTITION", scope=ldb.SCOPE_BASE,
                               attrs=["backendStore"])
            backend = str(res[0].get("backendStore"))
            self.assertEqual(backend, self.backend)

        # check the restored DB has the expected partitions/DC/FSMO roles
        self.assert_partitions_present(samdb)
        self.assert_dcs_present(samdb, self.new_server, expected_count=1)
        self.assert_fsmo_roles(samdb, self.new_server, self.server)
        self.assert_secrets(samdb, expect_secrets=expect_secrets)

        # check we still have an uptodateness vector for the original DC
        self.assert_repl_uptodate_vector(samdb)
        return samdb

    def assert_user_secrets(self, samdb, username, expect_secrets):
        """Asserts that a user has/doesn't have secrets as expected"""
        basedn = str(samdb.get_default_basedn())
        user_dn = "CN=%s,CN=users,%s" % (username, basedn)

        if expect_secrets:
            self.assertIsNotNone(samdb.searchone("unicodePwd", user_dn))
        else:
            # the search should throw an exception because the secrets
            # attribute isn't actually there
            self.assertRaises(KeyError, samdb.searchone, "unicodePwd", user_dn)

    def assert_secrets(self, samdb, expect_secrets):
        """Check the user secrets in the restored DB match what's expected"""

        # check secrets for the built-in testenv users match what's expected
        test_users = ["alice", "bob", "jane"]
        for user in test_users:
            self.assert_user_secrets(samdb, user, expect_secrets)

    def assert_fsmo_roles(self, samdb, server, exclude_server):
        """Asserts the expected server is the FSMO role owner"""
        domain_dn = samdb.domain_dn()
        forest_dn = dn_from_dns_name(samdb.forest_dns_name())
        fsmos = {'infrastructure': "CN=Infrastructure," + domain_dn,
                 'naming': "CN=Partitions,%s" % samdb.get_config_basedn(),
                 'schema': str(samdb.get_schema_basedn()),
                 'rid': "CN=RID Manager$,CN=System," + domain_dn,
                 'pdc': domain_dn,
                 'domaindns':
                     "CN=Infrastructure,DC=DomainDnsZones," + domain_dn,
                 'forestdns':
                     "CN=Infrastructure,DC=ForestDnsZones," + forest_dn}
        for role, dn in fsmos.items():
            owner = get_fsmo_roleowner(samdb, ldb.Dn(samdb, dn), role)
            self.assertTrue("CN={0},".format(server) in owner.extended_str(),
                            "Expected %s to own FSMO role %s" % (server, role))
            self.assertTrue("CN={0},".format(exclude_server)
                            not in owner.extended_str(),
                            "%s found as FSMO %s role owner" % (server, role))

    def cleanup_tempdir(self):
        for filename in os.listdir(self.tempdir):
            filepath = os.path.join(self.tempdir, filename)
            shutil.rmtree(filepath)

    def run_cmd(self, args):
        """Executes a samba-tool backup/restore command"""

        cmd = " ".join(args)
        print("Executing: samba-tool %s" % cmd)
        try:
            # note: it's important we run the cmd in a separate process here
            out = self.check_output("samba-tool " + cmd)
        except BlackboxProcessError as e:
            # if the command failed, it may have left behind temporary files.
            # We're going to fail the test, but first cleanup any temp files so
            # that we skip the TestCaseInTempDir._remove_tempdir() assertions
            self.cleanup_tempdir()
            self.fail("Error calling samba-tool: %s" % e)
        print(out)

    def create_backup(self, extra_args=None):
        """Runs the backup cmd to produce a backup file for the testenv DC"""
        # Run the backup command and check we got one backup tar file
        args = self.base_cmd + ["--targetdir=" + self.tempdir]
        if extra_args:
            args += extra_args

        self.run_cmd(args)

        # find the filename of the backup-file generated
        tar_files = []
        for fn in os.listdir(self.tempdir):
            if (fn.startswith("samba-backup-") and fn.endswith(".tar.bz2")):
                tar_files.append(fn)

        self.assertTrue(len(tar_files) == 1,
                        "Domain backup created %u tar files" % len(tar_files))

        # clean up the backup file once the test finishes
        backup_file = os.path.join(self.tempdir, tar_files[0])
        self.addCleanup(os.remove, backup_file)
        return backup_file

    def restore_backup(self, backup_file, extra_args=None):
        """Restores the samba directory files from a given backup"""
        # Run the restore command
        extract_dir = self.restore_dir()
        args = ["domain", "backup", "restore", "--backup-file=" + backup_file,
                "--targetdir=" + extract_dir,
                "--newservername=" + self.new_server]
        if extra_args:
            args += extra_args

        self.run_cmd(args)

        # sanity-check the restore doesn't modify the original DC by mistake
        self.assert_partitions_present(self.ldb)
        self.assert_dcs_present(self.ldb, self.server)
        self.assert_fsmo_roles(self.ldb, self.server, self.new_server)


class DomainBackupOnline(DomainBackupBase):

    def setUp(self):
        super(DomainBackupOnline, self).setUp()
        self.base_cmd = ["domain", "backup", "online",
                         "--server=" + self.server, self.user_auth]

    # run the common test cases above using online backups
    def test_backup_untar(self):
        self._test_backup_untar()

    def test_backup_restore(self):
        self.use_backend("tdb")
        self._test_backup_restore()

    def test_backup_restore_with_conf(self):
        self.use_backend("mdb")
        self._test_backup_restore_with_conf()

    def test_backup_restore_no_secrets(self):
        self.use_backend("tdb")
        self._test_backup_restore_no_secrets()

    def test_backup_restore_into_site(self):
        self.use_backend("mdb")
        self._test_backup_restore_into_site()


class DomainBackupRename(DomainBackupBase):

    # run the above test cases using a rename backup
    def setUp(self):
        super(DomainBackupRename, self).setUp()
        self.new_server = "RENAMESERV"
        self.restore_domain = "NEWDOMAIN"
        self.restore_realm = "rename.test.net"
        self.new_basedn = "DC=rename,DC=test,DC=net"
        self.base_cmd = ["domain", "backup", "rename", self.restore_domain,
                         self.restore_realm, "--server=" + self.server,
                         self.user_auth]
        self.backup_markers += ['backupRename']

    # run the common test case code for backup-renames
    def test_backup_untar(self):
        self._test_backup_untar()

    def test_backup_restore(self):
        self.use_backend("mdb")
        self._test_backup_restore()

    def test_backup_restore_with_conf(self):
        self.use_backend("tdb")
        self._test_backup_restore_with_conf()

    def test_backup_restore_no_secrets(self):
        self.use_backend("mdb")
        self._test_backup_restore_no_secrets()

    def test_backup_restore_into_site(self):
        self.use_backend("tdb")
        self._test_backup_restore_into_site()

    def test_backup_invalid_args(self):
        """Checks that rename commands with invalid args are rejected"""

        # try a "rename" using the same realm as the DC currently has
        rename_cmd = "samba-tool domain backup rename "
        bad_cmd = "{cmd} {domain} {realm}".format(cmd=rename_cmd,
                                                  domain=self.restore_domain,
                                                  realm=os.environ["REALM"])
        self.assertRaises(BlackboxProcessError, self.check_output, bad_cmd)

        # try a "rename" using the same domain as the DC currently has
        bad_cmd = "{cmd} {domain} {realm}".format(cmd=rename_cmd,
                                                  domain=os.environ["DOMAIN"],
                                                  realm=self.restore_realm)
        self.assertRaises(BlackboxProcessError, self.check_output, bad_cmd)

    def add_link(self, attr, source, target):
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, source)
        m[attr] = ldb.MessageElement(target, ldb.FLAG_MOD_ADD, attr)
        self.ldb.modify(m)

    def test_one_way_links(self):
        """Sanity-check that a rename handles one-way links correctly"""

        # Do some initial setup on the DC before back it up:
        # create an OU to hold the test objects we'll create
        test_ou = create_test_ou(self.ldb, "rename_test")
        self.addCleanup(self.ldb.delete, test_ou, ["tree_delete:1"])

        # create the source and target objects and link them together.
        # We use addressBookRoots2 here because it's a one-way link
        src_dn = "CN=link_src,%s" % test_ou
        self.ldb.add({"dn": src_dn,
                      "objectclass": "msExchConfigurationContainer"})
        target_dn = "OU=link_tgt,%s" % test_ou
        self.ldb.add({"dn": target_dn, "objectclass": "organizationalunit"})
        link_attr = "addressBookRoots2"
        self.add_link(link_attr, src_dn, target_dn)

        # add a second link target that's in a different partition
        server_dn = ("CN=testrename,CN=Servers,CN=Default-First-Site-Name,"
                     "CN=Sites,%s" % str(self.ldb.get_config_basedn()))
        self.ldb.add({"dn": server_dn, "objectclass": "server"})
        self.addCleanup(self.ldb.delete, server_dn)
        self.add_link(link_attr, src_dn, server_dn)

        # do the backup/restore
        backup_file = self.create_backup()
        self.restore_backup(backup_file)
        lp = self.check_restored_smbconf()
        restored_ldb = self.check_restored_database(lp)

        # work out what the new DNs should be
        old_basedn = str(self.ldb.get_default_basedn())
        new_target_dn = re.sub(old_basedn + '$', self.new_basedn, target_dn)
        new_src_dn = re.sub(old_basedn + '$', self.new_basedn, src_dn)
        new_server_dn = re.sub(old_basedn + '$', self.new_basedn, server_dn)

        # check the links exist in the renamed DB with the correct DNs
        res = restored_ldb.search(base=new_src_dn, scope=ldb.SCOPE_BASE,
                                  attrs=[link_attr])
        self.assertEqual(len(res), 1,
                         "Failed to find renamed link source object")
        self.assertTrue(link_attr in res[0], "Missing link attribute")
        link_values = [str(x) for x in res[0][link_attr]]
        self.assertTrue(new_target_dn in link_values)
        self.assertTrue(new_server_dn in link_values)

    # extra checks we run on the restored DB in the rename case
    def check_restored_database(self, lp, expect_secrets=True):
        # run the common checks over the restored DB
        common_test = super(DomainBackupRename, self)
        samdb = common_test.check_restored_database(lp, expect_secrets)

        # check we have actually renamed the DNs
        basedn = str(samdb.get_default_basedn())
        self.assertEqual(basedn, self.new_basedn)

        # check the partition and netBIOS name match the new domain
        partitions_dn = samdb.get_partitions_dn()
        nc_name = ldb.binary_encode(str(basedn))
        res = samdb.search(base=partitions_dn, scope=ldb.SCOPE_ONELEVEL,
                           attrs=["nETBIOSName", "cn"],
                           expression='ncName=%s' % nc_name)
        self.assertEqual(len(res), 1,
                         "Looking up partition's NetBIOS name failed")
        self.assertEqual(str(res[0].get("nETBIOSName")), self.restore_domain)
        self.assertEqual(str(res[0].get("cn")), self.restore_domain)

        # check the DC has the correct dnsHostname
        realm = self.restore_realm
        dn = "CN=%s,OU=Domain Controllers,%s" % (self.new_server,
                                                 self.new_basedn)
        res = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                           attrs=["dNSHostName"])
        self.assertEqual(len(res), 1,
                         "Looking up new DC's dnsHostname failed")
        expected_val = "%s.%s" % (self.new_server.lower(), realm)
        self.assertEqual(str(res[0].get("dNSHostName")), expected_val)

        # check the DNS zones for the new realm are present
        dn = "DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones,%s" % (realm, basedn)
        res = samdb.search(base=dn, scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 1, "Lookup of new domain's DNS zone failed")

        forestdn = samdb.get_root_basedn().get_linearized()
        dn = "DC=_msdcs.%s,CN=MicrosoftDNS,DC=ForestDnsZones,%s" % (realm,
                                                                    forestdn)
        res = samdb.search(base=dn, scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 1, "Lookup of new domain's DNS zone failed")
        return samdb


class DomainBackupOffline(DomainBackupBase):

    def setUp(self):
        super(DomainBackupOffline, self).setUp()
        self.base_cmd = ["domain", "backup", "offline"]

    def test_backup_untar(self):
        self._test_backup_untar(primary_domain_secrets=1)

    def test_backup_restore_with_conf(self):
        self._test_backup_restore_with_conf()

    def test_backup_restore(self):
        self._test_backup_restore()

    def test_backup_restore_into_site(self):
        self._test_backup_restore_into_site()

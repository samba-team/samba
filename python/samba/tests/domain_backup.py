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
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.tests import TestCaseInTempDir, env_loadparm
import ldb
from samba.samdb import SamDB
from samba.auth import system_session
from samba import Ldb, dn_from_dns_name
from samba.netcmd.fsmo import get_fsmo_roleowner


def get_prim_dom(secrets_path, lp):
    secrets_ldb = Ldb(secrets_path, session_info=system_session(), lp=lp)
    return secrets_ldb.search(base="CN=Primary Domains",
                              attrs=['objectClass', 'samAccountName',
                                     'secret', 'msDS-KeyVersionNumber'],
                              scope=ldb.SCOPE_SUBTREE,
                              expression="(objectClass=kerberosSecret)")


class DomainBackupBase(SambaToolCmdTest, TestCaseInTempDir):

    def setUp(self):
        super(DomainBackupBase, self).setUp()

        server = os.environ["DC_SERVER"]
        self.user_auth = "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                       os.environ["DC_PASSWORD"])

        # LDB connection to the original server being backed up
        self.ldb = self.getSamDB("-H", "ldap://%s" % server,
                                 self.user_auth)
        self.new_server = "BACKUPSERV"
        self.server = server.upper()
        self.base_cmd = None
        self.backup_markers = ['sidForRestore', 'backupDate']
        self.restore_domain = os.environ["DOMAIN"]
        self.restore_realm = os.environ["REALM"]

    def assert_partitions_present(self, samdb):
        """Asserts all expected partitions are present in the backup samdb"""
        res = samdb.search(base="", scope=ldb.SCOPE_BASE,
                           attrs=['namingContexts'])
        actual_ncs = [str(r) for r in res[0].get('namingContexts')]

        basedn = str(samdb.get_default_basedn())
        config_dn = "CN=Configuration,%s" % basedn
        expected_ncs = [basedn, config_dn, "CN=Schema,%s" % config_dn,
                        "DC=DomainDnsZones,%s" % basedn,
                        "DC=ForestDnsZones,%s" % basedn]

        for nc in expected_ncs:
            self.assertTrue(nc in actual_ncs,
                            "%s not in %s" % (nc, str(actual_ncs)))

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

    def _test_backup_untar(self):
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

        # We have no secrets.ldb entry as we never got that during the backup.
        secrets_path = os.path.join(private_dir, "secrets.ldb")
        res = get_prim_dom(secrets_path, lp)
        self.assertEqual(len(res), 0)

        # sanity-check that all the partitions got backed up
        self.assert_partitions_present(samdb)

    def _test_backup_restore(self):
        """Does a backup/restore, with specific checks of the resulting DB"""
        backup_file = self.create_backup()
        self.restore_backup(backup_file)
        lp = self.check_restored_smbconf()
        self.check_restored_database(lp)

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

    def check_restored_database(self, bkp_lp):
        paths = provision.provision_paths_from_lp(bkp_lp, bkp_lp.get("realm"))

        bkp_pd = get_prim_dom(paths.secrets, bkp_lp)
        self.assertEqual(len(bkp_pd), 1)
        acn = bkp_pd[0].get('samAccountName')
        self.assertIsNotNone(acn)
        self.assertEqual(acn[0].replace('$', ''), self.new_server)
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

        # check the restored DB has the expected partitions/DC/FSMO roles
        self.assert_partitions_present(samdb)
        self.assert_dcs_present(samdb, self.new_server, expected_count=1)
        self.assert_fsmo_roles(samdb, self.new_server, self.server)
        return samdb

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
            self.assertTrue("CN={},".format(server) in owner.extended_str(),
                            "Expected %s to own FSMO role %s" % (server, role))
            self.assertTrue("CN={},".format(exclude_server)
                            not in owner.extended_str(),
                            "%s found as FSMO %s role owner" % (server, role))

    def run_cmd(self, args):
        """Executes a samba-tool backup/restore command"""

        # we use check_output() here to execute the command because we want the
        # command run in a separate process. This means a completely clean
        # LoadParm object gets used for the restore (otherwise the global LP
        # settings can bleed from one test case to another).
        cmd = " ".join(args)
        print("Executing: samba-tool %s" % cmd)
        out = self.check_output("samba-tool " + cmd)
        print(out)

    def create_backup(self):
        """Runs the backup cmd to produce a backup file for the testenv DC"""
        # Run the backup command and check we got one backup tar file
        args = self.base_cmd + ["--server=" + self.server, self.user_auth,
                                "--targetdir=" + self.tempdir]

        self.run_cmd(args)

        # find the filename of the backup-file generated
        tar_files = []
        for filename in os.listdir(self.tempdir):
            if (filename.startswith("samba-backup-") and
                filename.endswith(".tar.bz2")):
                tar_files.append(filename)

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
        self.base_cmd = ["domain", "backup", "online"]

    # run the common test cases above using online backups
    def test_backup_untar(self):
        self._test_backup_untar()

    def test_backup_restore(self):
        self._test_backup_restore()

    def test_backup_restore_with_conf(self):
        self._test_backup_restore_with_conf()

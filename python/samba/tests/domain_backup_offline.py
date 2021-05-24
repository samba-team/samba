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

import tarfile
import os
import shutil
import tempfile
from samba.tests import BlackboxTestCase, BlackboxProcessError
from samba.netcmd import CommandError
from samba.param import LoadParm
from samba.join import join_DC
from samba.credentials import Credentials
from samba.logger import get_samba_logger

# The backup tests require that a completely clean LoadParm object gets used
# for the restore. Otherwise the same global LP gets re-used, and the LP
# settings can bleed from one test case to another.
# To do this, these tests should use check_output(), which executes the command
# in a separate process (as opposed to runcmd(), runsubcmd()).
# So although this is a samba-tool test, we don't inherit from SambaToolCmdTest
# so that we never inadvertently use .runcmd() by accident.
class DomainBackupOfflineCmp(BlackboxTestCase):

    def test_domain_backup_offline_nested_tdb(self):
        self.nested_testcase('tdb')

    def test_domain_backup_offline_nested_mdb(self):
        self.nested_testcase('mdb')

    def nested_testcase(self, backend):
        self.prov_dir = self.provision(backend)
        self.extract_dir = None

        src = os.path.join(self.prov_dir, "private")
        dst = os.path.join(self.prov_dir, "state", "private")

        # Move private directory inside state directory
        shutil.move(src, dst)

        smbconf = os.path.join(self.prov_dir, "etc", "smb.conf")

        # Update the conf file
        lp = LoadParm(filename_for_non_global_lp=smbconf)
        lp.set("private dir", dst)
        lp.dump(False, smbconf)

        backup_file = self.backup(self.prov_dir)

        # Ensure each file is only present once in the tar file
        tf = tarfile.open(backup_file)
        names = tf.getnames()
        self.assertEqual(len(names), len(set(names)))

    def test_domain_backup_offline_join_restore_tdb(self):
        self.join_restore_testcase('tdb')

    def test_domain_backup_offline_join_restore_mdb(self):
        self.join_restore_testcase('mdb')

    def join_restore_testcase(self, backend):
        self.prov_dir = self.join(backend)
        self.extract_dir = None

        try:
            backup_file = self.backup(self.prov_dir)
        except BlackboxProcessError as e:
            self.fail(e)

        self.extract_dir = self.restore(backup_file)

    def test_domain_backup_offline_hard_link_tdb(self):
        self.hard_link_testcase('tdb')

    def test_domain_backup_offline_hard_link_mdb(self):
        self.hard_link_testcase('mdb')

    def hard_link_testcase(self, backend):
        self.prov_dir = self.provision(backend)
        self.extract_dir = None

        # Create hard links in the private and state directories
        os.link(os.path.join(self.prov_dir, "private", "krb5.conf"),
                os.path.join(self.prov_dir, "state", "krb5.conf"))

        backup_file = self.backup(self.prov_dir)

        # Extract the backup
        self.extract_dir = tempfile.mkdtemp(dir=self.tempdir)
        tf = tarfile.open(backup_file)
        tf.extractall(self.extract_dir)

        # Ensure that the hard link in the private directory was backed up,
        # while the one in the state directory was not.
        self.assertTrue(os.path.exists(os.path.join(self.extract_dir,
                                                    "private", "krb5.conf")))
        self.assertFalse(os.path.exists(os.path.join(self.extract_dir,
                                                    "statedir", "krb5.conf")))

    def test_domain_backup_offline_untar_tdb(self):
        self.untar_testcase('tdb')

    def test_domain_backup_offline_untar_mbd(self):
        self.untar_testcase('mdb')

    def test_domain_backup_offline_restore_tdb(self):
        self.restore_testcase('tdb')

    def test_domain_backup_offline_restore_mbd(self):
        self.restore_testcase('mdb')

    def restore_testcase(self, backend):
        self.prov_dir = self.provision(backend)
        self.extract_dir = None
        backup_file = self.backup(self.prov_dir)

        self.extract_dir = self.restore(backup_file)

        # attrs that are altered by the restore process
        ignore_attrs = ["servicePrincipalName", "lastLogonTimestamp",
                        "rIDAllocationPool", "rIDAvailablePool", "rIDUsedPool",
                        "localPolicyFlags", "operatingSystem", "displayName",
                        "dnsRecord", "dNSTombstoned",
                        "msDS-NC-Replica-Locations", "msDS-HasInstantiatedNCs",
                        "interSiteTopologyGenerator"]
        filter_arg = "--filter=" + ",".join(ignore_attrs)
        args = ["--two", filter_arg]
        self.ldapcmp(self.prov_dir, self.extract_dir, args)

    def untar_testcase(self, backend):
        self.prov_dir = self.provision(backend)
        self.extract_dir = None
        backup_file = self.backup(self.prov_dir)

        self.extract_dir = tempfile.mkdtemp(dir=self.tempdir)
        tf = tarfile.open(backup_file)
        tf.extractall(self.extract_dir)

        self.ldapcmp(self.prov_dir, self.extract_dir)

    def ldapcmp(self, prov_dir, ex_dir, args=[]):
        sam_fn = os.path.join("private", "sam.ldb")
        url1 = "tdb://" + os.path.join(os.path.realpath(prov_dir), sam_fn)
        url2 = "tdb://" + os.path.join(os.path.realpath(ex_dir), sam_fn)

        # Compare the restored sam.ldb with the old one
        for partition in ["domain", "configuration", "schema",
                          "dnsdomain", "dnsforest"]:
            cmd = "samba-tool ldapcmp " + " ".join([url1, url2, partition] + args)
            self.check_output(cmd)

    # Test the "samba-tool domain backup" command with ldapcmp
    def provision(self, backend):
        target = tempfile.mkdtemp(dir=self.tempdir)

        # Provision domain.  Use fake ACLs and store xattrs in tdbs so that
        # NTACL backup will work inside the testenv.
        # host-name option must be given because if this test runs on a
        # system with a very long hostname, it will be shortened in certain
        # circumstances, causing the ldapcmp to fail.
        prov_cmd = "samba-tool domain provision " +\
                   "--domain FOO --realm foo.example.com " +\
                   "--targetdir {target} " +\
                   "--backend-store {backend} " +\
                   "--host-name OLDSERVER "+\
                   "--option=\"vfs objects=fake_acls xattr_tdb\""
        prov_cmd = prov_cmd.format(target=target, backend=backend)
        self.check_output(prov_cmd)

        return target

    def join(self, backend):
        target = tempfile.mkdtemp(dir=self.tempdir)

        join_cmd = "samba-tool domain join {domain} DC " +\
                   "--server {server} " +\
                   "--realm {realm} " +\
                   "--username {username}%{password} " +\
                   "--targetdir {target} " +\
                   "--backend-store {backend} " +\
                   "--option=\"vfs objects=dfs_samba4 acl_xattr fake_acls xattr_tdb\""
        join_cmd = join_cmd.format(server=os.environ["DC_SERVER"],
                                   domain=os.environ["DOMAIN"],
                                   realm=os.environ["REALM"],
                                   username=os.environ["USERNAME"],
                                   password=os.environ["PASSWORD"],
                                   target=target,
                                   backend=backend)
        self.check_output(join_cmd)

        return target

    def backup(self, prov_dir):
        # Run the backup and check we got one backup tar file
        cmd = ("samba-tool domain backup offline --targetdir={prov_dir} "
               "-s {prov_dir}/etc/smb.conf").format(prov_dir=prov_dir)
        self.check_output(cmd)

        tar_files = [fn for fn in os.listdir(prov_dir)
                     if fn.startswith("samba-backup-") and
                     fn.endswith(".tar.bz2")]
        if len(tar_files) != 1:
            raise CommandError("expected domain backup to create one tar" +
                               " file but got {0}".format(len(tar_files)))

        backup_file = os.path.join(prov_dir, tar_files[0])
        return backup_file

    def restore(self, backup_file):
        # Restore from a backup file
        extract_dir = tempfile.mkdtemp(dir=self.tempdir)
        cmd = ("samba-tool domain backup restore --backup-file={f}"
               " --targetdir={d} "
               "--newservername=NEWSERVER").format(f=backup_file,
                                                   d=extract_dir)
        self.check_output(cmd)

        return extract_dir

    def tearDown(self):
        # Remove temporary directories
        shutil.rmtree(self.prov_dir)
        if self.extract_dir:
            shutil.rmtree(self.extract_dir)

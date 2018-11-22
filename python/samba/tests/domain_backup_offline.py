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
from samba.tests import BlackboxTestCase
from samba.netcmd import CommandError

# The backup tests require that a completely clean LoadParm object gets used
# for the restore. Otherwise the same global LP gets re-used, and the LP
# settings can bleed from one test case to another.
# To do this, these tests should use check_output(), which executes the command
# in a separate process (as opposed to runcmd(), runsubcmd()).
# So although this is a samba-tool test, we don't inherit from SambaToolCmdTest
# so that we never inadvertently use .runcmd() by accident.
class DomainBackupOfflineCmp(BlackboxTestCase):

    def test_domain_backup_offline_untar_tdb(self):
        self.untar_testcase('tdb')

    def test_domain_backup_offline_untar_mbd(self):
        self.untar_testcase('mdb')

    def test_domain_backup_offline_restore_tdb(self):
        self.restore_testcase('tdb')

    def test_domain_backup_offline_restore_mbd(self):
        self.restore_testcase('mdb')

    def restore_testcase(self, backend):
        prov_dir, backup_file = self.provision_and_backup(backend)

        extract_dir = tempfile.mkdtemp(dir=self.tempdir)
        cmd = ("samba-tool domain backup restore --backup-file={f}"
               " --targetdir={d} "
               "--newservername=NEWSERVER").format(f=backup_file, d=extract_dir)
        self.check_output(cmd)

        # attrs that are altered by the restore process
        ignore_attrs = ["servicePrincipalName", "lastLogonTimestamp",
                        "rIDAllocationPool", "rIDAvailablePool",
                        "localPolicyFlags", "operatingSystem", "displayName",
                        "dnsRecord", "dNSTombstoned",
                        "msDS-NC-Replica-Locations", "msDS-HasInstantiatedNCs",
                        "interSiteTopologyGenerator"]
        filter_arg = "--filter=" + ",".join(ignore_attrs)
        args = ["--two", filter_arg]
        self.ldapcmp(prov_dir, extract_dir, args)

        shutil.rmtree(prov_dir)
        shutil.rmtree(extract_dir)

    def untar_testcase(self, backend):
        prov_dir, backup_file = self.provision_and_backup(backend)

        extract_dir = tempfile.mkdtemp(dir=self.tempdir)
        tf = tarfile.open(backup_file)
        tf.extractall(extract_dir)

        self.ldapcmp(prov_dir, extract_dir)

        shutil.rmtree(prov_dir)
        shutil.rmtree(extract_dir)

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
    def provision_and_backup(self, backend):
        prov_dir = tempfile.mkdtemp(dir=self.tempdir)

        # Provision domain.  Use fake ACLs and store xattrs in tdbs so that
        # NTACL backup will work inside the testenv.
        # host-name option must be given because if this test runs on a
        # system with a very long hostname, it will be shortened in certain
        # circumstances, causing the ldapcmp to fail.
        prov_cmd = "samba-tool domain provision " +\
                   "--domain FOO --realm foo.example.com " +\
                   "--targetdir {prov_dir} " +\
                   "--backend-store {backend} " +\
                   "--host-name OLDSERVER "+\
                   "--option=\"vfs objects=fake_acls xattr_tdb\""
        prov_cmd = prov_cmd.format(prov_dir=prov_dir, backend=backend)
        self.check_output(prov_cmd)

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
        return prov_dir, backup_file

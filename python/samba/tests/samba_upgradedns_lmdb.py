# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst IT Ltd. 2019
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

from samba.tests.samba_tool.base import SambaToolCmdTest
import os
import shutil


class UpgradeDnsLmdbTestCase(SambaToolCmdTest):
    """
        Tests for dns upgrade on a lmdb backend
    """

    def setUp(self):
        super(UpgradeDnsLmdbTestCase, self).setUp()
        self.tempsambadir = os.path.join(self.tempdir, "samba")
        os.mkdir(self.tempsambadir)

    # provision a domain
    #
    # returns the tuple (ret, stdout, stderr)
    def provision(self):
        command = (
            "samba-tool "
            "domain provision "
            "--realm=foo.example.com "
            "--domain=FOO "
            "--targetdir=%s "
            "--backend-store=mdb "
            "--use-ntvfs " % self.tempsambadir)
        return self.run_command(command)

    # upgrade a domains dns to BIND9
    #
    # returns the tuple (ret, stdout, stderr)
    def upgrade_dns(self):
        command = (
            "samba_upgradedns "
            "--dns-backend=BIND9_DLZ "
            "--configfile %s/etc/smb.conf" % self.tempsambadir)
        return self.run_command(command)

    def tearDown(self):
        super(UpgradeDnsLmdbTestCase, self).tearDown()
        shutil.rmtree(self.tempsambadir)

    def test_lmdb_lock_files_linked_on_upgrade_to_bind9_dlz(self):
        """
            Ensure that links are created for the lock files as well as the
            data files
        """
        self.provision()
        self.upgrade_dns()
        directory = ("%s/bind-dns/dns/sam.ldb.d" % self.tempsambadir)
        for filename in os.listdir(directory):
            if filename.endswith(".ldb") and "DNSZONES" in filename:
                lock_file = ("%s/%s-lock" % (directory, filename))
                self.assertTrue(
                    os.path.isfile(lock_file),
                    msg=("Lock file %s/%s-lock for %s, does not exist" %
                         (directory, filename, filename)))

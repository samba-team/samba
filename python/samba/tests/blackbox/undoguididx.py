# Blackbox tests for sambaundoguididx
#
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
from __future__ import print_function
from samba.tests import BlackboxTestCase
import os
import ldb
import shutil
from subprocess import check_output
from samba.samdb import SamDB

COMMAND = os.path.join(os.path.dirname(__file__),
               "../../../../../source4/scripting/bin/sambaundoguididx")


class DowngradeTest(BlackboxTestCase):
    """Test that sambaundoguididx downgrades the samba database"""
    backend = 'tdb'

    def setUp(self):
        super(DowngradeTest, self).setUp()

        prov_cmd = "samba-tool domain provision " +\
                   "--domain FOO --realm foo.example.com " +\
                   "--targetdir {self.tempdir} " +\
                   "--backend-store {self.backend} " +\
                   "--host-name downgradetest " +\
                   "--option=\"vfs objects=fake_acls xattr_tdb\""
        prov_cmd = prov_cmd.format(self=self)
        self.check_run(prov_cmd, "Provisioning for downgrade")

        private_dir = os.path.join(self.tempdir, "private")
        self.sam_path = os.path.join(private_dir, "sam.ldb")
        self.ldb = ldb.Ldb(self.sam_path, options=["modules:"])

        partitions = self.ldb.search(base="@PARTITION",
                                       scope=ldb.SCOPE_BASE,
                                       attrs=["partition"])
        partitions = partitions[0]['partition']
        partitions = [str(p).split(":")[1] for p in partitions]
        self.dbs = [os.path.join(private_dir, p)
                    for p in partitions]
        self.dbs.append(self.sam_path)

    def tearDown(self):
        shutil.rmtree(os.path.join(self.tempdir, "private"))
        shutil.rmtree(os.path.join(self.tempdir, "etc"))
        shutil.rmtree(os.path.join(self.tempdir, "state"))
        shutil.rmtree(os.path.join(self.tempdir, "bind-dns"))
        shutil.rmtree(os.path.join(self.tempdir, "msg.lock"))
        os.unlink(os.path.join(self.tempdir, "names.tdb"))
        os.unlink(os.path.join(self.tempdir, "gencache.tdb"))
        super(DowngradeTest, self).tearDown()

    # Parse out the comments above each record that ldbdump produces
    # containing pack format version and KV level key for each record.
    # Return all GUID keys and DN keys (without @attrs)
    def ldbdump_keys_pack_formats(self):
        # Get all comments from all partition dbs
        comments = []
        for db in self.dbs:
            dump = check_output(["bin/ldbdump", "-i", db])
            dump = dump.decode("utf-8")
            dump = dump.split("\n")
            comments += [s for s in dump if s.startswith("#")]

        guid_key_tag = "# key: GUID="
        guid_keys = {c[len(guid_key_tag):] for c in comments
                     if c.startswith(guid_key_tag)}

        dn_key_tag = "# key: DN="
        dn_keys = {c[len(dn_key_tag):] for c in comments
                   if c.startswith(dn_key_tag)}

        # Ignore @ attributes, they are always DN keyed
        dn_keys_no_at_attrs = {d for d in dn_keys if not d.startswith("@")}

        return dn_keys_no_at_attrs, guid_keys

    # Check that sambaundoguididx replaces all GUID keys with DN keys
    def test_undo_guid_idx(self):
        dn_keys, guid_keys = self.ldbdump_keys_pack_formats()
        self.assertGreater(len(guid_keys), 20)
        self.assertEqual(len(dn_keys), 0)

        num_guid_keys_before_downgrade = len(guid_keys)

        self.check_run("%s -H %s" % (COMMAND, self.sam_path),
                       msg="Running sambaundoguididx")

        dn_keys, guid_keys = self.ldbdump_keys_pack_formats()
        self.assertEqual(len(guid_keys), 0)
        self.assertEqual(len(dn_keys), num_guid_keys_before_downgrade)

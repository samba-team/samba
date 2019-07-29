# Blackbox tests for sambadowngradedatabase
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

COMMAND = os.path.join(os.environ.get("SRCDIR_ABS"),
               "source4/scripting/bin/samba_downgrade_db")


class DowngradeTestBase(BlackboxTestCase):
    """Test that sambadowngradedatabase downgrades the samba database"""

    def setUp(self):
        super(DowngradeTestBase, self).setUp()
        if not hasattr(self, "backend"):
            self.fail("Subclass this class and set 'backend'")

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
        super(DowngradeTestBase, self).tearDown()

    # Parse out the comments above each record that ldbdump produces
    # containing pack format version and KV level key for each record.
    # Return all GUID keys and DN keys (without @attrs), and the set
    # of all unique pack formats.
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

        pack_format_tag = "# pack format: "
        pack_formats = {c[len(pack_format_tag):] for c in comments
                        if c.startswith(pack_format_tag)}
        pack_formats = [int(s, 16) for s in pack_formats]

        return dn_keys_no_at_attrs, guid_keys, pack_formats

    # Get a set of all distinct types in @ATTRIBUTES
    def attribute_types(self):
        at_attributes = self.ldb.search(base="@ATTRIBUTES",
                                          scope=ldb.SCOPE_BASE,
                                          attrs=["*"])
        self.assertEqual(len(at_attributes), 1)
        keys = at_attributes[0].keys()
        attribute_types = {str(at_attributes[0].get(k)) for k in keys}

        return attribute_types

class DowngradeTestTDB(DowngradeTestBase):
    backend = 'tdb'

    # Check that running sambadowngradedatabase with a TDB backend:
    # * Replaces all GUID keys with DN keys
    # * Removes ORDERED_INTEGER from @ATTRIBUTES
    # * Repacks database with pack format version 1
    def test_downgrade_database(self):
        type_prefix = "LDB_SYNTAX_"
        ordered_int_type = ldb.SYNTAX_ORDERED_INTEGER[len(type_prefix):]

        dn_keys, guid_keys, pack_formats = self.ldbdump_keys_pack_formats()
        self.assertGreater(len(guid_keys), 20)
        self.assertEqual(len(dn_keys), 0)
        self.assertTrue(ordered_int_type in self.attribute_types())
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT_V2])

        num_guid_keys_before_downgrade = len(guid_keys)

        self.check_run("%s -H %s" % (COMMAND, self.sam_path),
                       msg="Running sambadowngradedatabase")

        dn_keys, guid_keys, pack_formats = self.ldbdump_keys_pack_formats()
        self.assertEqual(len(guid_keys), 0)
        self.assertEqual(len(dn_keys), num_guid_keys_before_downgrade)
        self.assertTrue(ordered_int_type not in self.attribute_types())
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT])

class DowngradeTestMDB(DowngradeTestBase):
    backend = 'mdb'

    # Check that running sambadowngradedatabase with a TDB backend:
    # * Does NOT replace GUID keys with DN keys
    # * Removes ORDERED_INTEGER from @ATTRIBUTES
    # * Repacks database with pack format version 1
    def test_undo_guid(self):
        type_prefix = "LDB_SYNTAX_"
        ordered_int_type = ldb.SYNTAX_ORDERED_INTEGER[len(type_prefix):]

        dn_keys, guid_keys, pack_formats = self.ldbdump_keys_pack_formats()
        self.assertGreater(len(guid_keys), 20)
        self.assertEqual(len(dn_keys), 0)
        self.assertTrue(ordered_int_type in self.attribute_types())
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT_V2])

        num_guid_keys_before_downgrade = len(guid_keys)

        self.check_run("%s -H %s" % (COMMAND, self.sam_path),
                       msg="Running sambadowngradedatabase")

        dn_keys, guid_keys, pack_formats = self.ldbdump_keys_pack_formats()
        self.assertEqual(len(guid_keys), num_guid_keys_before_downgrade)
        self.assertEqual(len(dn_keys), 0)
        self.assertTrue(ordered_int_type not in self.attribute_types())
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT])

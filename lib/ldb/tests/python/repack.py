import os
from unittest import TestCase
import shutil
from subprocess import check_output
import ldb

TDB_PREFIX = "tdb://"
MDB_PREFIX = "mdb://"

def tempdir():
    import tempfile
    try:
        dir_prefix = os.path.join(os.environ["SELFTEST_PREFIX"], "tmp")
    except KeyError:
        dir_prefix = None
    return tempfile.mkdtemp(dir=dir_prefix)


# Check enabling and disabling GUID indexing works and that the database is
# repacked at version 2 if GUID indexing is enabled, or version 1 if disabled.
class GUIDIndexAndPackFormatTests(TestCase):
    prefix = TDB_PREFIX

    def setup_newdb(self):
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir,
                                     "guidpackformattest.ldb")
        url = self.prefix + self.filename
        self.l = ldb.Ldb(url, options=["modules:"])

        self.num_recs_added = 0

    #guidindexpackv1.ldb is a pre-made database packed with version 1 format
    #but with GUID indexing enabled, which is not allowed, so Samba should
    #repack the database on the first transaction.
    def setup_premade_v1_db(self):
        db_name = "guidindexpackv1.ldb"
        this_file_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(this_file_dir, "../", db_name)
        self.testdir = tempdir()
        self.filename = os.path.join(self.testdir, db_name)

        shutil.copy(db_path, self.filename)

        url = self.prefix + self.filename
        self.l = ldb.Ldb(url, options=["modules:"])
        self.num_recs_added = 10

    def tearDown(self):
        if hasattr(self, 'testdir'):
            shutil.rmtree(self.testdir)

    def add_one_rec(self):
        ouuid = 0x0123456789abcdef + self.num_recs_added
        ouuid_s = '0' + hex(ouuid)[2:]
        dn = "OU=GUIDPFTEST{},DC=SAMBA,DC=ORG".format(self.num_recs_added)
        rec = {"dn": dn, "objectUUID": ouuid_s, "distinguishedName": dn}
        self.l.add(rec)
        self.num_recs_added += 1

        # Turn GUID back into a str for easier comparisons
        return rec

    def set_guid_indexing(self, enable=True):
        modmsg = ldb.Message()
        modmsg.dn = ldb.Dn(self.l, '@INDEXLIST')

        attrs = {"@IDXGUID": [b"objectUUID"],
                 "@IDX_DN_GUID": [b"GUID"]}
        for attr, val in attrs.items():
            replace = ldb.FLAG_MOD_REPLACE
            el = val if enable else []
            el = ldb.MessageElement(elements=el, flags=replace, name=attr)
            modmsg.add(el)

        self.l.modify(modmsg)

    # Parse out the comments above each record that ldbdump produces
    # containing pack format version and KV level key for each record.
    # Return all GUID index keys and the set of all unique pack formats.
    def ldbdump_guid_keys_pack_formats(self):
        dump = check_output(["bin/ldbdump", "-i", self.filename])
        dump = dump.decode("utf-8")
        dump = dump.split("\n")

        comments = [s for s in dump if s.startswith("#")]

        guid_key_tag = "# key: GUID="
        guid_keys = {c[len(guid_key_tag):] for c in comments
                         if c.startswith(guid_key_tag)}

        pack_format_tag = "# pack format: "
        pack_formats = {c[len(pack_format_tag):] for c in comments
                        if c.startswith(pack_format_tag)}
        pack_formats = [int(s, 16) for s in pack_formats]

        return guid_keys, pack_formats

    # Put the whole database in a dict so we can easily check the database
    # hasn't changed
    def get_database(self):
        recs = self.l.search(base="", scope=ldb.SCOPE_SUBTREE, expression="")
        db = dict()
        for r in recs:
            dn = str(r.dn)
            self.assertNotIn(dn, db)
            db[dn] = dict()
            for k in r.keys():
                k = str(k)
                db[dn][k] = str(r.get(k))
        return db

    # Toggle GUID indexing on and off a few times, and check that when GUID
    # indexing is enabled, the database is repacked to pack format V2, and
    # when GUID indexing is disabled again, the database is repacked with
    # pack format V1.
    def toggle_guidindex_check_pack(self):
        expect_db = self.get_database()

        for enable in [False, False, True, False, True, True, False]:
            pf = ldb.PACKING_FORMAT_V2 if enable else ldb.PACKING_FORMAT

            self.set_guid_indexing(enable=enable)

            guid_keys, pack_formats = self.ldbdump_guid_keys_pack_formats()
            num_guid_keys = self.num_recs_added if enable else 0
            self.assertEqual(len(guid_keys), num_guid_keys)
            self.assertEqual(pack_formats, [pf])
            self.assertEqual(self.get_database(), expect_db)

            rec = self.add_one_rec()
            expect_db[rec['dn']] = rec

            guid_keys, pack_formats = self.ldbdump_guid_keys_pack_formats()
            num_guid_keys = self.num_recs_added if enable else 0
            self.assertEqual(len(guid_keys), num_guid_keys)
            self.assertEqual(pack_formats, [pf])
            self.assertEqual(self.get_database(), expect_db)

    # Check a newly created database is initially packed at V1, then is
    # repacked at V2 when GUID indexing is enabled.
    def test_repack(self):
        self.setup_newdb()

        guid_keys, pack_formats = self.ldbdump_guid_keys_pack_formats()
        self.assertEqual(len(guid_keys), 0)
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT])
        self.assertEqual(self.get_database(), {})

        self.l.add({"dn": "@ATTRIBUTES"})

        guid_keys, pack_formats = self.ldbdump_guid_keys_pack_formats()
        self.assertEqual(len(guid_keys), 0)
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT])
        self.assertEqual(self.get_database(), {})

        self.l.add({"dn": "@INDEXLIST",
                    "@IDXONE": [b"1"],
                    "@IDXGUID": [b"objectUUID"],
                    "@IDX_DN_GUID": [b"GUID"]})

        guid_keys, pack_formats = self.ldbdump_guid_keys_pack_formats()
        self.assertEqual(len(guid_keys), 0)
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT_V2])
        self.assertEqual(self.get_database(), {})

        rec = self.add_one_rec()
        expect_db = {rec["dn"]: rec}

        guid_keys, pack_formats = self.ldbdump_guid_keys_pack_formats()
        self.assertEqual(len(guid_keys), 1)
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT_V2])
        self.assertEqual(self.get_database(), expect_db)

        self.toggle_guidindex_check_pack()

    # Check a database with V1 format with GUID indexing enabled is repacked
    # with version 2 format.
    def test_guid_indexed_v1_db(self):
        self.setup_premade_v1_db()

        expect_db = self.get_database()

        guid_keys, pack_formats = self.ldbdump_guid_keys_pack_formats()
        self.assertEqual(len(guid_keys), self.num_recs_added)
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT])
        self.assertEqual(self.get_database(), expect_db)

        rec = self.add_one_rec()
        expect_db[rec['dn']] = rec

        guid_keys, pack_formats = self.ldbdump_guid_keys_pack_formats()
        self.assertEqual(len(guid_keys), self.num_recs_added)
        self.assertEqual(pack_formats, [ldb.PACKING_FORMAT_V2])
        self.assertEqual(self.get_database(), expect_db)

        self.toggle_guidindex_check_pack()


if __name__ == '__main__':
    import unittest


    unittest.TestProgram()

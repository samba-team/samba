# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import fnmatch
import os
import shutil
import tempfile
from io import StringIO

from wafsamba.samba_abi import (
    abi_build_vscript,
    abi_match_excludes_as_patterns,
    abi_write_vscript,
    normalise_signature,
    symbol_as_pattern,
)
from wafsamba.tests import TestCase


class NormaliseSignatureTests(TestCase):

    def test_function_simple(self):
        self.assertEqual("int (const struct GUID *, const struct GUID *)",
            normalise_signature("$2 = {int (const struct GUID *, const struct GUID *)} 0xe871 <GUID_compare>"))

    def test_maps_Bool(self):
        # Some types have different internal names
        self.assertEqual("bool (const struct GUID *)",
            normalise_signature("$1 = {_Bool (const struct GUID *)} 0xe75b <GUID_all_zero>"))

    def test_function_keep(self):
        self.assertEqual(
            "enum ndr_err_code (struct ndr_push *, int, const union winreg_Data *)",
            normalise_signature("enum ndr_err_code (struct ndr_push *, int, const union winreg_Data *)"))

    def test_struct_constant(self):
        self.assertEqual(
            'uuid = {time_low = 0, time_mid = 0, time_hi_and_version = 0, clock_seq = "\\000", node = "\\000\\000\\000\\000\\000"}, if_version = 0',
            normalise_signature('$239 = {uuid = {time_low = 0, time_mid = 0, time_hi_and_version = 0, clock_seq = "\\000", node = "\\000\\000\\000\\000\\000"}, if_version = 0}'))

    def test_incomplete_sequence(self):
        # Newer versions of gdb insert these incomplete sequence elements
        self.assertEqual(
            'uuid = {time_low = 2324192516, time_mid = 7403, time_hi_and_version = 4553, clock_seq = "\\237\\350", node = "\\b\\000+\\020H`"}, if_version = 2',
            normalise_signature('$244 = {uuid = {time_low = 2324192516, time_mid = 7403, time_hi_and_version = 4553, clock_seq = "\\237", <incomplete sequence \\350>, node = "\\b\\000+\\020H`"}, if_version = 2}'))
        self.assertEqual(
            'uuid = {time_low = 2324192516, time_mid = 7403, time_hi_and_version = 4553, clock_seq = "\\237\\350", node = "\\b\\000+\\020H`"}, if_version = 2',
            normalise_signature('$244 = {uuid = {time_low = 2324192516, time_mid = 7403, time_hi_and_version = 4553, clock_seq = "\\237\\350", node = "\\b\\000+\\020H`"}, if_version = 2}'))


class WriteVscriptTests(TestCase):

    def test_one(self):
        f = StringIO()
        abi_write_vscript(f, "MYLIB", "1.0", [], {
            "old": "1.0",
            "new": "1.0"}, ["*"])
        self.assertEqual(f.getvalue(), """\
1.0 {
\tglobal:
\t\t*;
\tlocal:
\t\t_end;
\t\t__bss_start;
\t\t_edata;
};
""")

    def test_one_no_linker_symbols(self):
        f = StringIO()
        abi_write_vscript(f, "MYLIB", "1.0", [], {
            "old": "1.0",
            "new": "1.0"}, ["*"], hide_linker_symbols=False)
        self.assertEqual(f.getvalue(), """\
1.0 {
\tglobal:
\t\t*;
};
""")

    def test_exclude_no_linker_symbols(self):
        f = StringIO()
        abi_write_vscript(f, "MYLIB", "1.0", [], {
            "exc_old": "0.1",
            "old": "0.1",
            "new": "1.0"}, ["!exc_*"], hide_linker_symbols=False)
        self.assertEqual(f.getvalue(), """\
1.0 {
\tglobal:
\t\t*;
\tlocal:
\t\texc_*;
};
""")

    def test_simple(self):
        # No restrictions.
        f = StringIO()
        abi_write_vscript(f, "MYLIB", "1.0", ["0.1"], {
            "old": "0.1",
            "new": "1.0"}, ["*"])
        self.assertEqual(f.getvalue(), """\
MYLIB_0.1 {
\tglobal:
\t\told;
};

1.0 {
\tglobal:
\t\t*;
\tlocal:
\t\t_end;
\t\t__bss_start;
\t\t_edata;
};
""")

    def test_exclude(self):
        f = StringIO()
        abi_write_vscript(f, "MYLIB", "1.0", [], {
            "exc_old": "0.1",
            "old": "0.1",
            "new": "1.0"}, ["!exc_*"])
        self.assertEqual(f.getvalue(), """\
1.0 {
\tglobal:
\t\t*;
\tlocal:
\t\texc_*;
\t\t_end;
\t\t__bss_start;
\t\t_edata;
};
""")

    def test_excludes_and_includes(self):
        f = StringIO()
        abi_write_vscript(f, "MYLIB", "1.0", [], {
            "pub_foo": "1.0",
            "exc_bar": "1.0",
            "other": "1.0"
            }, ["pub_*", "!exc_*"])
        self.assertEqual(f.getvalue(), """\
1.0 {
\tglobal:
\t\tpub_*;
\tlocal:
\t\texc_*;
\t\t_end;
\t\t__bss_start;
\t\t_edata;
\t\t*;
};
""")


class FakeNode(object):

    def __init__(self, path):
        self.path = path

    def abspath(self, env=None):
        return self.path

    def bldpath(self, env=None):
        return self.path


class FakeEnv(object):

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeTask(object):

    def __init__(self, inputs, output, **env):
        self.inputs = [FakeNode(i) for i in inputs]
        self.outputs = [FakeNode(output)]
        self.env = FakeEnv(**env)


class BuildVscriptTests(TestCase):

    def setUp(self):
        super().setUp()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        super().tearDown()

    def write_file(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, mode='w') as f:
            f.write(content)
        return path

    def build_vscript(self, inputs, abi_match, no_linker_symbols,
                      private_library=False, version="MYLIB_1.0"):
        output = os.path.join(self.tmpdir, "mylib.vscript")
        task = FakeTask(inputs, output,
                        LIBNAME="MYLIB",
                        VERSION=version,
                        ABI_MATCH=abi_match,
                        PRIVATE_LIBRARY=private_library,
                        LD_VERSION_SCRIPT_NO_LINKER_SYMBOLS=no_linker_symbols)
        abi_build_vscript(task)
        with open(output) as f:
            return f.read()

    def sigs_files(self):
        return [
            self.write_file("MYLIB-0.1.sigs",
                            "kept_old: int (void)\n"
                            "removed_old: int (void)\n"
                            "exc_old: int (void)\n"),
            self.write_file("MYLIB-1.0.sigs",
                            "kept_old: int (void)\n"
                            "new: int (void)\n"),
        ]

    def test_keep_removed_symbols(self):
        # Without LD_VERSION_SCRIPT_NO_LINKER_SYMBOLS the removed
        # symbols stay in the version nodes they were added in.
        vscript = self.build_vscript(self.sigs_files(),
                                     ["!exc_*", "*"],
                                     no_linker_symbols=False)
        self.assertEqual(vscript, """\
MYLIB_0.1 {
\tglobal:
\t\tkept_old;
\t\tremoved_old;
\t\texc_old;
};

MYLIB_1.0 {
\tglobal:
\t\t*;
\tlocal:
\t\texc_*;
\t\t_end;
\t\t__bss_start;
\t\t_edata;
};
""")

    def test_prune_removed_symbols(self):
        # removed_old is part of the ABI, but no longer in the
        # latest ABI file, so it's pruned. exc_old isn't part of
        # the ABI, so it keeps its original version.
        vscript = self.build_vscript(self.sigs_files(),
                                     ["!exc_*", "*"],
                                     no_linker_symbols=True)
        self.assertEqual(vscript, """\
MYLIB_0.1 {
\tglobal:
\t\tkept_old;
\t\texc_old;
};

MYLIB_1.0 {
\tglobal:
\t\t*;
\tlocal:
\t\texc_*;
};
""")

    def version_script_map(self):
        return self.write_file("version-script.map", """\
# comment
UPSTREAM_1.0 {
\tglobal:
\t\tup_func;
\t\tup_glob_*;
\tlocal:
\t\tup_hidden;
\t\t*;
};
""")

    def test_version_script_map(self):
        vscript = self.build_vscript([self.version_script_map()],
                                     [],
                                     no_linker_symbols=False,
                                     private_library=True,
                                     version="MYLIB_PRIVATE")
        self.assertEqual(vscript, """\
MYLIB_PRIVATE {
\tglobal:
\t\tup_func;
\t\tup_glob_*;
\tlocal:
\t\tup_hidden;
\t\t_end;
\t\t__bss_start;
\t\t_edata;
\t\t*;
};
""")

    def test_version_script_map_as_patterns(self):
        vscript = self.build_vscript([self.version_script_map()],
                                     [],
                                     no_linker_symbols=True,
                                     private_library=True,
                                     version="MYLIB_PRIVATE")
        self.assertEqual(vscript, """\
MYLIB_PRIVATE {
\tglobal:
\t\tup_fun[c];
\t\tup_glob_*;
\tlocal:
\t\tup_hidde[n];
\t\t*;
};
""")

    def test_excludes(self):
        abi_match = ["!exc_name", "!exc_*", "*"]
        vscript = self.build_vscript(self.sigs_files(), abi_match,
                                     no_linker_symbols=False)
        self.assertIn("\t\texc_name;\n", vscript)
        self.assertIn("\t\texc_*;\n", vscript)

    def test_excludes_as_patterns(self):
        # The linker doesn't warn about patterns not matching any
        # symbol, e.g. symbols of modules, which are not linked
        # statically.
        abi_match = ["!exc_name", "!exc_*", "*"]
        vscript = self.build_vscript(self.sigs_files(), abi_match,
                                     no_linker_symbols=True)
        self.assertEqual(vscript, """\
MYLIB_0.1 {
\tglobal:
\t\tkept_old;
\t\texc_old;
};

MYLIB_1.0 {
\tglobal:
\t\t*;
\tlocal:
\t\texc_nam[e];
\t\texc_*;
};
""")


class AbiMatchExcludesAsPatternsTests(TestCase):

    def test_global_star(self):
        self.assertEqual(
            abi_match_excludes_as_patterns(["!priv2ld", "!pdb_*_init"]),
            ["!priv2l[d]", "!pdb_*_init"])
        self.assertEqual(
            abi_match_excludes_as_patterns(["!priv2ld", "*"]),
            ["!priv2l[d]", "*"])

    def test_global_pattern(self):
        # A global pattern has precedence over a local pattern,
        # so the exact name has to stay.
        self.assertEqual(
            abi_match_excludes_as_patterns(
                ["!ndr_table_x", "!other_x", "ndr_*"]),
            ["!ndr_table_x", "!other_[x]", "ndr_*"])

    def test_includes_unchanged(self):
        self.assertEqual(
            abi_match_excludes_as_patterns(["pub_func", "pub_*"]),
            ["pub_func", "pub_*"])


class SymbolAsPatternTests(TestCase):

    def test_symbol(self):
        self.assertEqual(symbol_as_pattern("foo"), "fo[o]")
        self.assertTrue(fnmatch.fnmatch("foo", symbol_as_pattern("foo")))
        self.assertFalse(fnmatch.fnmatch("fo", symbol_as_pattern("foo")))
        self.assertFalse(fnmatch.fnmatch("foo2", symbol_as_pattern("foo")))

    def test_single_char(self):
        self.assertEqual(symbol_as_pattern("x"), "[x]")

    def test_pattern(self):
        self.assertEqual(symbol_as_pattern("foo_*"), "foo_*")
        self.assertEqual(symbol_as_pattern("fo?"), "fo?")
        self.assertEqual(symbol_as_pattern("fo[o]"), "fo[o]")

# Unix SMB/CIFS implementation.
#
# Copyright (C) Catalyst.Net Ltd. 2022
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


import subprocess
import os
from samba.tests import TestCaseInTempDir
from pprint import pprint

HERE = os.path.dirname(__file__)
S4_SERVER = os.path.join(HERE, '../../../../bin/test_s4_logging')
S3_SERVER = os.path.join(HERE, '../../../../bin/test_s3_logging')

CLASS_LIST = ["all", "tdb", "printdrivers", "lanman", "smb",
              "rpc_parse", "rpc_srv", "rpc_cli", "passdb", "sam", "auth",
              "winbind", "vfs", "idmap", "quota", "acls", "locking", "msdfs",
              "dmapi", "registry", "scavenger", "dns", "ldb", "tevent",
              "auth_audit", "auth_json_audit", "kerberos", "drs_repl",
              "smb2", "smb2_credits", "dsdb_audit", "dsdb_json_audit",
              "dsdb_password_audit", "dsdb_password_json_audit",
              "dsdb_transaction_audit", "dsdb_transaction_json_audit",
              "dsdb_group_audit", "dsdb_group_json_audit"]


CLASS_CODES = {k: i for i, k in enumerate(CLASS_LIST)}


class S4LoggingTests(TestCaseInTempDir):
    server = S4_SERVER
    def _write_smb_conf(self,
                        default_level=2,
                        default_file="default",
                        mapping=()):
        self.smbconf = os.path.join(self.tempdir, "smb.conf")

        with open(self.smbconf, "w") as f:
            f.write('[global]\n')
            if default_file is not None:
                dest = os.path.join(self.tempdir,
                                    default_file)
                f.write(f"    log file = {dest}\n")

            f.write("    log level = ")
            if default_level:
                f.write(f"{default_level}")

            for dbg_class, log_level, log_file in mapping:
                f.write(' ')
                f.write(dbg_class)
                if log_level is not None:
                    f.write(f':{log_level}')
                if log_file is not None:
                    dest = os.path.join(self.tempdir,
                                        log_file)

                    f.write(f'@{dest}')
            f.write('\n')
        self.addCleanup(os.unlink, self.smbconf)

    def _extract_log_level_line(self, new_level=2):
        # extricate the 'log level' line from the smb.conf, returning
        # the value, and replacing the log level line with something
        # innocuous.
        smbconf2 = self.smbconf + 'new'
        with open(self.smbconf) as f:
            with open(smbconf2, 'w') as f2:
                for line in f:
                    if 'log level' in line:
                        debug_arg = line.split('=', 1)[1].strip()
                        if new_level is not None:
                            f2.write(f'    log level = {new_level}\n')
                    else:
                        f2.write(line)
        os.replace(smbconf2, self.smbconf)
        return debug_arg

    def _get_expected_strings(self, mapping,
                              level_filter,
                              default_file='default',
                              file_filter=None):
        default = os.path.join(self.tempdir, default_file)
        expected = {default: []}
        # this kind of thing:
        # "  logging for 'dns' [21], at level 4"
        for dbg_class, log_level, log_file in mapping:
            if log_file is None:
                log_file = default_file

            f = os.path.join(self.tempdir, log_file)
            expected.setdefault(f, [])
            if log_level < level_filter:
                continue
            if file_filter not in (None, log_file):
                continue
            s = (f"  logging for '{dbg_class}' [{CLASS_CODES[dbg_class]}], "
                 f"at level {level_filter}")
            expected[f].append(s)

        return expected

    def _run_s4_logger(self, log_level, *extra_args):
        cmd = [self.server,
               '-s', self.smbconf,
               '-L', str(log_level),
               *extra_args]

        p = subprocess.run(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0,
                         f"'{' '.join(cmd)}' failed ({p.returncode})")

        return p.stdout.decode(), p.stderr.decode()

    def assert_string_contains(self, string, expected_lines,
                               filename=None):
        expected_lines = set(expected_lines)
        string_lines = set(string.split('\n'))
        present_lines = string_lines & expected_lines
        if present_lines != expected_lines:
            if filename:
                print(filename)
            print("expected %d lines, found %d" %
                  (len(expected_lines), len(present_lines)))
            print("missing lines:")
            pprint(expected_lines - present_lines)
            raise AssertionError("missing lines")

    def assert_file_contains(self, filename, expected_lines):
        with open(filename) as f:
            string = f.read()
        self.assert_string_contains(string, expected_lines, filename)

    def assert_n_known_lines_string(self, string, n):
        count = string.count("logging for '")
        if count != n:
            raise AssertionError(
                f"string has {count} lines, expected {n}")

    def assert_n_known_lines(self, filename, n):
        with open(filename) as f:
            string = f.read()
        count = string.count("  logging for '")
        if count != n:
            raise AssertionError(
                f"{filename} has {count} lines, expected {n}")

    def assert_unlink_expected_strings(self, expected_strings):
        for k, v in expected_strings.items():
            if not os.path.exists(k):
                self.fail(f"{k} does not exist")
            self.assert_file_contains(k, v)
            self.assert_n_known_lines(k, len(v))
            os.unlink(k)

    def test_each_to_its_own(self):
        level = 4
        mapping = [(x, level, x) for x in CLASS_LIST]
        expected_strings = self._get_expected_strings(mapping, level)

        self._write_smb_conf(mapping=mapping)
        stdout, stderr = self._run_s4_logger(level)
        self.assert_unlink_expected_strings(expected_strings)

    def test_all_to_one(self):
        level = 4
        dest = 'everything'
        mapping = [(x, level, dest) for x in CLASS_LIST]
        expected_strings = self._get_expected_strings(mapping, level)

        self._write_smb_conf(mapping=mapping)
        stdout, stderr = self._run_s4_logger(level)
        self.assert_unlink_expected_strings(expected_strings)

    def test_bifurcate(self):
        level = 4
        dests = ['even', 'odd']
        mapping = [(x, level + 1, dests[i & 1])
                   for i, x in enumerate(CLASS_LIST)]
        expected_strings = self._get_expected_strings(mapping, level)

        self._write_smb_conf(mapping=mapping)
        stdout, stderr = self._run_s4_logger(level)
        self.assert_unlink_expected_strings(expected_strings)

    def test_bifurcate_level_out_of_range(self):
        # nothing will be logged, because we're logging at a too high
        # level.
        level = 4
        dests = ['even', 'odd']
        mapping = [(x, level - 1, dests[i & 1])
                   for i, x in enumerate(CLASS_LIST)]
        expected_strings = self._get_expected_strings(mapping, level)

        self._write_smb_conf(mapping=mapping)
        stdout, stderr = self._run_s4_logger(level)
        self.assert_unlink_expected_strings(expected_strings)

    def test_bifurcate_misc_log_level(self):
        # We are sending even numbers to default and odd numbers to
        # 'odd', at various levels, depending on mod 3. Like this:
        #
        # log level = 2 all:5 \
        #               tdb:4@odd \
        #               printdrivers:3 \
        #               lanman:5@odd \
        #               smb:4 \
        #               rpc_parse:3@odd \
        #               rpc_srv:5 ...
        #
        # Therefore, 'default' should get classes that are (0 or 4) % 6
        # and 'odd' should get classes that are (1 or 3) % 6.

        level = 4
        dests = [None, 'odd']
        mapping = []
        for i, x in enumerate(CLASS_LIST):
            parity = i & 1
            log_level = level + 1 - (i % 3)
            mapping.append((x, log_level, dests[parity]))

        expected_strings = self._get_expected_strings(mapping, level)

        self._write_smb_conf(mapping=mapping)
        stdout, stderr = self._run_s4_logger(level)
        self.assert_unlink_expected_strings(expected_strings)

    def test_all_different_ways_cmdline_d(self):
        level = 4
        dests = [None, 'a', 'b', 'c']
        mapping = []
        seed = 123
        for i, x in enumerate(CLASS_LIST):
            d = seed & 3
            seed = seed * 17 + 1
            log_level = seed % 10
            seed &= 0xff
            mapping.append((x, log_level, dests[d]))

        expected_strings = self._get_expected_strings(mapping, level)

        self._write_smb_conf(mapping=mapping)
        debug_arg = self._extract_log_level_line(26)

        stdout, stderr = self._run_s4_logger(level, '-d', debug_arg)
        self.assert_unlink_expected_strings(expected_strings)

    def test_all_different_ways_cmdline_d_interactive(self):
        level = 4
        dests = [None, 'a', 'b', 'c']
        mapping = []
        seed = 1234
        for i, x in enumerate(CLASS_LIST):
            d = seed & 3
            seed = seed * 13 + 1
            log_level = seed % 10
            seed &= 0xff
            mapping.append((x, log_level, dests[d]))

        expected_strings = self._get_expected_strings(mapping, level)

        self._write_smb_conf(mapping=mapping)
        debug_arg = self._extract_log_level_line(None)
        stdout, stderr = self._run_s4_logger(level, '-d', debug_arg, '-i')
        expected_lines = []
        for v in expected_strings.values():
            # stderr doesn't end up with leading '  '
            expected_lines.extend([x.strip() for x in v])

        self.assert_string_contains(stderr, expected_lines)
        self.assert_n_known_lines_string(stderr, len(expected_lines))

    def test_only_some_level_0(self):
        # running the logger with -L 0 makes the log messages run at
        # level 0 (i.e DBG_ERR), so we always see them in default,
        # even though smb.conf doesn't ask.
        mapping = [(x, 3, ['default', 'bees']['b' in x])
                   for x in CLASS_LIST]
        expected_strings = self._get_expected_strings(mapping, 0)
        self._write_smb_conf(mapping=[x for x in mapping if x[2] == 'bees'])
        stdout, stderr = self._run_s4_logger(0)
        self.assert_unlink_expected_strings(expected_strings)

    def test_only_some_level_3(self):
        # here, we're expecting the unmentioned non-b classes to just
        # disappear.
        level = 3
        mapping = [(x, level, 'bees') for x in CLASS_LIST if 'b' in x]
        expected_strings = self._get_expected_strings(mapping, level)
        self._write_smb_conf(mapping=[x for x in mapping if x[2] == 'bees'])
        stdout, stderr = self._run_s4_logger(level)
        self.assert_unlink_expected_strings(expected_strings)

    def test_none(self):
        level = 4
        mapping = []
        expected_strings = self._get_expected_strings(mapping, level)
        self._write_smb_conf(mapping=mapping)
        stdout, stderr = self._run_s4_logger(level)
        self.assert_unlink_expected_strings(expected_strings)

    def test_none_high_default(self):
        # We set the default level to 5 and do nothing else special,
        # which means we need a different mapping for the smb.conf
        # than the expected strings.
        level = 4
        mapping = [(x, 5, 'default') for x in CLASS_LIST]
        expected_strings = self._get_expected_strings(mapping, level)
        # note the empty mapping in smb.conf
        self._write_smb_conf(mapping=[], default_level=5)
        stdout, stderr = self._run_s4_logger(level)
        self.assert_unlink_expected_strings(expected_strings)

    def test_none_high_cmdline_d(self):
        # We set the default level to 2, but run the 'server' with -d 10.
        level = 4
        mapping = [(x, 10, 'default') for x in CLASS_LIST]
        expected_strings = self._get_expected_strings(mapping, level)
        # note the empty mapping in smb.conf
        self._write_smb_conf(mapping=[])
        stdout, stderr = self._run_s4_logger(level, '-d', '10')
        self.assert_unlink_expected_strings(expected_strings)

    def test_interactive_high_default_simple(self):
        # running with -i should send everything to stderr.
        level = 4
        mapping = [(x, 5, 'default') for x in CLASS_LIST]
        expected_strings = self._get_expected_strings(mapping, level)
        self._write_smb_conf(mapping=[], default_level=5)
        stdout, stderr = self._run_s4_logger(level, '-i')
        expected_lines = []
        for v in expected_strings.values():
            # stderr doesn't end up with leading '  '
            expected_lines.extend([x.strip() for x in v])

        self.assert_string_contains(stderr, expected_lines)

    def test_interactive_complex_smb_conf(self):
        # running with -i should send everything to stderr. The
        # smb.conf will set the levels, but the target files are
        # overridden.
        # (this is the test_bifurcate_misc_log_level() smb.conf).
        level = 4
        dests = [None, 'odd']
        mapping = []
        for i, x in enumerate(CLASS_LIST):
            parity = i & 1
            log_level = level + 1 - (i % 3)
            mapping.append((x, log_level, dests[parity]))

        expected_strings = self._get_expected_strings(mapping, level)

        self._write_smb_conf(mapping=mapping)
        stdout, stderr = self._run_s4_logger(level, '-i')
        expected_lines = []
        for v in expected_strings.values():
            # stderr doesn't end up with leading '  '
            expected_lines.extend([x.strip() for x in v])

        self.assert_string_contains(stderr, expected_lines)


class S3LoggingTests(S4LoggingTests):
    server = S3_SERVER
    # These tests were developed for testing the test_logger when
    # linked against CMDLINE_S4 (see lib/util/wscript_build), but can
    # also run when linked against CMDLINE_S3.

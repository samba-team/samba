# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst IT Ltd 2017.
#
# Originally written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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

import re
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.tests import BlackboxProcessError
from samba.tests import check_help_consistency
from samba.common import get_string
from samba import version


class HelpTestCase(SambaToolCmdTest):
    """Tests for samba-tool help and --help

    We test for consistency and lack of crashes."""

    def _find_sub_commands(self, args):
        self.runcmd(*args)

    def test_help_tree(self):
        # we call actual subprocesses, because we are probing the
        # actual help output where there is no sub-command. Don't copy
        # this if you have an actual command: for that use
        # self.runcmd() or self.runsubcmd().
        known_commands = [[]]
        failed_commands = []

        for i in range(4):
            new_commands = []
            for c in known_commands:
                line = ' '.join(['samba-tool'] + c + ['--help'])
                try:
                    output = self.check_output(line)
                except BlackboxProcessError as e:
                    output = e.stdout
                    failed_commands.append(c)
                output = get_string(output)
                tail = output.partition('Available subcommands:')[2]
                subcommands = re.findall(r'^\s*([\w-]+)\s+-', tail,
                                         re.MULTILINE)
                for s in subcommands:
                    new_commands.append(c + [s])

                # check that `samba-tool help X Y` == `samba-tool X Y --help`
                line = ' '.join(['samba-tool', 'help'] + c)
                try:
                    output2 = self.check_output(line)
                except BlackboxProcessError as e:
                    output2 = e.stdout
                    failed_commands.append(c)

                output2 = get_string(output2)
                self.assertEqual(output, output2)

                err = check_help_consistency(output,
                                             options_start='Options:',
                                             options_end='Available subcommands:')
                if err is not None:
                    self.fail("consistency error with %s:\n%s" % (line, err))

            if not new_commands:
                break

            known_commands = new_commands

        self.assertEqual(failed_commands, [])

    def test_bad_password_option(self):
        """Do we get a warning with an invalid --pass option?"""
        (result, out, err) = self.run_command(["samba-tool",
                                               "processes",
                                               "--pass-the-salt-please",
                                               "pleeease"])
        self.assertIn("if '--pass-the-salt-please' is not misspelt", err)
        self.assertIn("the appropriate list in is_password_option", err)

    def test_version(self):
        """Does --version work?"""
        (result, out, err) = self.run_command(["samba-tool", "--version"])
        self.assertEqual(version, out.strip())

    def test_sub_command_version(self):
        """Does --version work in a sub-command?"""
        (result, out, err) = self.run_command(["samba-tool", "spn", "--version"])
        self.assertEqual(version, out.strip())

    def test_leaf_command_version(self):
        """Does --version work in a leaf command?"""
        (result, out, err) = self.run_command(["samba-tool", "contact", "edit",
                                               "--version"])
        self.assertEqual(version, out.strip())

    def test_help_version(self):
        """Is version mentioned in --help?"""
        (result, out, err) = self.run_command(["samba-tool", "spn", "--help"])
        self.assertIn(version, out)

    def test_version_beats_help(self):
        """Does samba-tool --help --version print version?"""
        (result, out, err) = self.run_command(["samba-tool", "spn", "--help", "-V"])
        self.assertEqual(version, out.strip())
        (result, out, err) = self.run_command(["samba-tool", "--help", "-V"])
        self.assertEqual(version, out.strip())
        (result, out, err) = self.run_command(["samba-tool", "dns", "-V", "--help"])
        self.assertEqual(version, out.strip())

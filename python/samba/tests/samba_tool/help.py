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
from samba.compat import get_string


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

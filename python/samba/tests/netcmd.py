# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2009-2011
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

"""Tests for samba.netcmd."""

import os
import tempfile

from io import StringIO
from samba.netcmd import Command
from samba.netcmd.testparm import cmd_testparm
from samba.netcmd.main import cmd_sambatool
import samba.tests


class NetCmdTestCase(samba.tests.TestCaseInTempDir):

    def run_netcmd(self, cmd_klass, args, retcode=0):
        cmd = cmd_klass(outf=StringIO(), errf=StringIO())
        cmd.command_name = "apricots"
        try:
            retval = cmd._run(*args)
        except Exception as e:
            cmd.show_command_error(e)
            retval = 1
        self.assertEqual(retcode, retval)
        return cmd.outf.getvalue(), cmd.errf.getvalue()

    def iter_all_subcommands(self):
        todo = list(cmd_sambatool.subcommands.items())
        while todo:
            (path, cmd) = todo.pop()
            yield path, cmd
            subcmds = getattr(cmd, "subcommands", {})
            todo.extend([(path + " " + k, v) for (k, v) in
                         subcmds.items()])


class TestParmTests(NetCmdTestCase):

    def setUp(self):
        super().setUp()

        # Override these global parameters in case their default values are
        # invalid.
        contents = """[global]
    netbios name = test
    lock dir = /
    pid directory = /
[tmp]
    path = /
"""
        self.smbconf = self.create_smbconf(contents)

    def create_smbconf(self, contents):
        smbconf = tempfile.NamedTemporaryFile(mode='w',
                                              dir=self.tempdir,
                                              delete=False)
        self.addCleanup(os.remove, smbconf.name)

        try:
            smbconf.write(contents)
        finally:
            smbconf.close()

        return smbconf

    def test_no_client_ip(self):
        out, err = self.run_netcmd(cmd_testparm, ["--client-name=foo"],
                                   retcode=-1)
        self.assertEqual("", out)
        self.assertEqual(
            "ERROR: Both a DNS name and an IP address are "
            "required for the host access check\n", err)

    def test_section(self):
        # We don't get an opportunity to verify the output, as the parameters
        # are dumped directly to stdout, so just check the return code.
        self.run_netcmd(cmd_testparm,
                        ["--configfile=%s" % self.smbconf.name,
                         "--section-name=tmp"],
                        retcode=None)

    def test_section_globals(self):
        # We can have '[global]' and '[globals]'
        for name in ['global', 'globals']:
            self.run_netcmd(cmd_testparm,
                            [f"--configfile={self.smbconf.name}",
                             f"--section-name={name}"],
                            retcode=None)

    def test_no_such_section(self):
        out, err = self.run_netcmd(cmd_testparm,
                                   ["--configfile=%s" % self.smbconf.name,
                                    "--section-name=foo"],
                                   retcode=-1)
        # Ensure all exceptions are caught.
        self.assertEqual("", out)
        self.assertNotIn("uncaught exception", err)

        out, err = self.run_netcmd(cmd_testparm,
                                   ["--configfile=%s" % self.smbconf.name,
                                    "--section-name=foo",
                                    "--parameter-name=foo"],
                                   retcode=-1)
        # Ensure all exceptions are caught.
        self.assertEqual("", out)
        self.assertNotIn("uncaught exception", err)

    def test_no_such_parameter(self):
        out, err = self.run_netcmd(cmd_testparm,
                                   ["--configfile=%s" % self.smbconf.name,
                                    "--section-name=tmp",
                                    "--parameter-name=foo"],
                                   retcode=-1)
        # Ensure all exceptions are caught.
        self.assertEqual("", out)
        self.assertNotIn("uncaught exception", err)


class CommandTests(NetCmdTestCase):

    def test_description(self):
        class cmd_foo(Command):
            """Mydescription"""
        self.assertEqual("Mydescription", cmd_foo().short_description)

    def test_name(self):
        class cmd_foo(Command):
            pass
        self.assertEqual("foo", cmd_foo().name)

    def test_synopsis_everywhere(self):
        missing = []
        for path, cmd in self.iter_all_subcommands():
            if cmd.synopsis is None:
                missing.append(path)
        if missing:
            self.fail("The following commands do not have a synopsis set: %r" %
                      missing)

    def test_short_description_everywhere(self):
        missing = []
        for path, cmd in self.iter_all_subcommands():
            if cmd.short_description is None:
                missing.append(path)
        if not missing:
            return
        self.fail(
            "The following commands do not have a short description set: %r" %
            missing)

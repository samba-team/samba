#!/usr/bin/env python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2009
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

from cStringIO import StringIO
from samba.netcmd import Command
from samba.netcmd.testparm import cmd_testparm
import samba.tests

class NetCmdTestCase(samba.tests.TestCase):

    def run_netcmd(self, cmd_klass, args, retcode=0):
        cmd = cmd_klass()
        cmd.outf = StringIO()
        cmd.errf = StringIO()
        try:
            retval = cmd._run(cmd_klass.__name__, *args)
        except Exception, e:
            cmd.show_command_error(e)
            retval = 1
        self.assertEquals(retcode, retval)
        return cmd.outf.getvalue(), cmd.errf.getvalue()


class TestParmTests(NetCmdTestCase):

    def test_no_client_ip(self):
        out, err = self.run_netcmd(cmd_testparm, ["--client-name=foo"],
            retcode=-1)
        self.assertEquals("", out)
        self.assertEquals(
            "ERROR: Both a DNS name and an IP address are "
            "required for the host access check\n", err)


class CommandTests(samba.tests.TestCase):

    def test_description(self):
        class cmd_foo(Command):
            """Mydescription"""
        self.assertEquals("Mydescription", cmd_foo().description)

    def test_name(self):
        class cmd_foo(Command):
            pass
        self.assertEquals("foo", cmd_foo().name)

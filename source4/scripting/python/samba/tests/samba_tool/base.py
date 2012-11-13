# Unix SMB/CIFS implementation.
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
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

# This provides a wrapper around the cmd interface so that tests can
# easily be built on top of it and have minimal code to run basic tests
# of the commands. A list of the environmental variables can be found in
# ~/selftest/selftest.pl
#
# These can all be accesses via os.environ["VARIBLENAME"] when needed

import random
import string
from samba.auth import system_session
from samba.samdb import SamDB
from cStringIO import StringIO
from samba.netcmd.main import cmd_sambatool
import samba.tests

class SambaToolCmdTest(samba.tests.TestCaseInTempDir):

    def getSamDB(self, *argv):
        """a convenience function to get a samdb instance so that we can query it"""

        # We build a fake command to get the options created the same
        # way the command classes do it. It would be better if the command
        # classes had a way to more cleanly do this, but this lets us write
        # tests for now
        cmd = cmd_sambatool.subcommands["user"].subcommands["setexpiry"]
        parser, optiongroups = cmd._create_parser("user")
        opts, args = parser.parse_args(list(argv))
        # Filter out options from option groups
        args = args[1:]
        kwargs = dict(opts.__dict__)
        for option_group in parser.option_groups:
            for option in option_group.option_list:
                if option.dest is not None:
                    del kwargs[option.dest]
        kwargs.update(optiongroups)

        H = kwargs.get("H", None)
        sambaopts = kwargs.get("sambaopts", None)
        credopts = kwargs.get("credopts", None)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        return samdb


    def runcmd(self, name, *args):
        """run a single level command"""
        cmd = cmd_sambatool.subcommands[name]
        cmd.outf = StringIO()
        cmd.errf = StringIO()
        result = cmd._run(name, *args)
        return (result, cmd.outf.getvalue(), cmd.errf.getvalue())

    def runsubcmd(self, name, sub, *args):
        """run a command with sub commands"""
        # The reason we need this function seperate from runcmd is
        # that the .outf StringIO assignment is overriden if we use
        # runcmd, so we can't capture stdout and stderr
        cmd = cmd_sambatool.subcommands[name].subcommands[sub]
        cmd.outf = StringIO()
        cmd.errf = StringIO()
        result = cmd._run(name, *args)
        return (result, cmd.outf.getvalue(), cmd.errf.getvalue())

    def assertCmdSuccess(self, val, msg=""):
        self.assertIsNone(val, msg)

    def assertCmdFail(self, val, msg=""):
        self.assertIsNotNone(val, msg)

    def assertMatch(self, base, string, msg=""):
        self.assertTrue(string in base, msg)

    def randomName(self, count=8):
        """Create a random name, cap letters and numbers, and always starting with a letter"""
        name = random.choice(string.ascii_uppercase)
        name += ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase+ string.digits) for x in range(count - 1))
        return name

    def randomPass(self, count=16):
        name = random.choice(string.ascii_uppercase)
        name += random.choice(string.digits)
        name += random.choice(string.ascii_lowercase)
        name += ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase+ string.digits) for x in range(count - 3))
        return name

    def assertWithin(self, val1, val2, delta, msg=""):
        """Assert that val1 is within delta of val2, useful for time computations"""
        self.assertTrue(((val1 + delta) > val2) and ((val1 - delta) < val2), msg)

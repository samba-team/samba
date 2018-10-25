# Blackbox tests for the "net ads ... --json" commands
# Copyright (C) 2018 Intra2net AG
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

import json
import re

import samba.tests
from samba.compat import get_string

COMMAND         = "bin/net ads"
# extract keys from non-json version
PLAIN_KEY_REGEX = re.compile ("^([^ \t:][^:]*):")

class BaseWrapper (object):
    """
    Guard the base so it doesn't inherit from TestCase. This prevents it from
    being run by unittest directly.
    """

    class NetAdsJSONTests_Base(samba.tests.BlackboxTestCase):
        """Blackbox tests for JSON output of the net ads suite of commands."""
        subcmd = None

        def setUp(self):
            super(BaseWrapper.NetAdsJSONTests_Base, self).setUp()

        def test_json_wellformed (self):
            """The output of ``--json`` commands must parse as JSON."""
            argv = "%s %s --json" % (COMMAND, self.subcmd)
            try:
                out = self.check_output(argv)
                json.loads (get_string(out))
            except samba.tests.BlackboxProcessError as e:
                self.fail("Error calling [%s]: %s" % (argv, e))

        def test_json_matching_entries (self):
            """
            The ``--json`` variants must contain the same keys as their
            respective plain counterpart.

            Does not check nested dictionaries (e. g. the ``Flags`` value of
            ``net ads lookup``..
            """
            argv = "%s %s" % (COMMAND, self.subcmd)
            try:
                out_plain = get_string(self.check_output(argv))
            except samba.tests.BlackboxProcessError as e:
                self.fail("Error calling [%s]: %s" % (argv, e))

            argv = "%s %s --json" % (COMMAND, self.subcmd)
            try:
                out_jsobj = self.check_output(argv)
            except samba.tests.BlackboxProcessError as e:
                self.fail("Error calling [%s]: %s" % (argv, e))

            parsed = json.loads (get_string(out_jsobj))

            for key in [ re.match (PLAIN_KEY_REGEX, line).group(1)
                         for line in out_plain.split ("\n")
                            if line != "" and line [0] not in " \t:" ]:
                self.assertTrue (parsed.get (key) is not None)
                del parsed [key]

            self.assertTrue (len (parsed) == 0) # tolerate no leftovers

class NetAdsJSONInfoTests(BaseWrapper.NetAdsJSONTests_Base):
    subcmd = "info"

class NetAdsJSONlookupTests(BaseWrapper.NetAdsJSONTests_Base):
    subcmd = "lookup"

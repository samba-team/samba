# Blackbox tests for "samba-tool drs" command
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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

"""Blackbox tests for samba-tool drs showrepl."""
from __future__ import print_function
import samba.tests
import drs_base
import re
import json
from samba.compat import PY3

if PY3:
    json_str = str
else:
    json_str = unicode

GUID_RE = r'[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}'
HEX8_RE = r'0x[\da-f]{8}'
DN_RE = r'(?:(?:CN|DC)=[\\:\w -]+,)+DC=com'


class SambaToolDrsShowReplTests(drs_base.DrsBaseTestCase):
    """Blackbox test case for samba-tool drs."""

    def assertRegex(self, exp, s, flags=0):
        m = re.search(exp, s, flags=flags)
        if m is None:
            self.fail("%r did not match /%s/" % (s, exp))
        return m

    def setUp(self):
        super(SambaToolDrsShowReplTests, self).setUp()

        self.dc1 = samba.tests.env_get_var_value("DC1")
        self.dc2 = samba.tests.env_get_var_value("DC2")

        creds = self.get_credentials()
        self.cmdline_creds = "-U%s/%s%%%s" % (creds.get_domain(),
                                              creds.get_username(),
                                              creds.get_password())

    def test_samba_tool_showrepl(self):
        """Tests 'samba-tool drs showrepl' command.
        """
        # Output should be like:
        #      <site-name>/<domain-name>
        #      DSA Options: <hex-options>
        #      DSA object GUID: <DSA-object-GUID>
        #      DSA invocationId: <DSA-invocationId>
        #      <Inbound-connections-list>
        #      <Outbound-connections-list>
        #      <KCC-objects>
        #      ...
        #   TODO: Perhaps we should check at least for
        #         DSA's objectGUDI and invocationId
        out = self.check_output("samba-tool drs showrepl "
                                "%s %s" % (self.dc1, self.cmdline_creds))

        # We want to assert that we are getting the same results, but
        # dates and GUIDs change randomly.
        #
        # There are sections with headers like ==== THIS ===="
        (header,
         _inbound, inbound,
         _outbound, outbound,
         _conn, conn) = out.split("====")

        self.assertEqual(_inbound, ' INBOUND NEIGHBORS ')
        self.assertEqual(_outbound, ' OUTBOUND NEIGHBORS ')
        self.assertEqual(_conn, ' KCC CONNECTION OBJECTS ')

        self.assertRegex(r'^Default-First-Site-Name\\LOCALDC\s+'
                         r"DSA Options: %s\s+"
                         r"DSA object GUID: %s\s+"
                         r"DSA invocationId: %s" %
                         (HEX8_RE, GUID_RE, GUID_RE), header)

        for p in ['DC=DomainDnsZones,DC=samba,DC=example,DC=com',
                  'CN=Configuration,DC=samba,DC=example,DC=com',
                  'DC=samba,DC=example,DC=com',
                  'CN=Schema,CN=Configuration,DC=samba,DC=example,DC=com',
                  'DC=ForestDnsZones,DC=samba,DC=example,DC=com']:
            self.assertRegex(r'%s\n'
                             r'\tDefault-First-Site-Name\\[A-Z]+ via RPC\n'
                             r'\t\tDSA object GUID: %s\n'
                             r'\t\tLast attempt @ [^\n]+\n'
                             r'\t\t\d+ consecutive failure\(s\).\n'
                             r'\t\tLast success @ [^\n]+\n'
                             r'\n' % (p, GUID_RE), inbound)

            self.assertRegex(r'%s\n'
                             r'\tDefault-First-Site-Name\\[A-Z]+ via RPC\n'
                             r'\t\tDSA object GUID: %s\n'
                             r'\t\tLast attempt @ [^\n]+\n'
                             r'\t\t\d+ consecutive failure\(s\).\n'
                             r'\t\tLast success @ [^\n]+\n'
                             r'\n' % (p, GUID_RE), outbound)

        self.assertRegex(r'Connection --\n'
                         r'\tConnection name: %s\n'
                         r'\tEnabled        : TRUE\n'
                         r'\tServer DNS name : \w+.samba.example.com\n'
                         r'\tServer DN name  : %s'
                         r'\n' % (GUID_RE, DN_RE), conn)

    def test_samba_tool_showrepl_json(self):
        """Tests 'samba-tool drs showrepl --json' command.
        """
        out = self.check_output("samba-tool drs showrepl %s %s --json" %
                                (self.dc1, self.cmdline_creds))

        print(out)

        d = json.loads(out)
        self.assertEqual(set(d), set(['repsFrom',
                                      'repsTo',
                                      "NTDSConnections",
                                      "dsa"]))

        # dsa
        for k in ["objectGUID", "invocationId"]:
            self.assertRegex('^%s$' % GUID_RE, d['dsa'][k])
        self.assertTrue(isinstance(d['dsa']["options"], int))

        # repsfrom and repsto
        for reps in (d['repsFrom'], d['repsTo']):
            for r in reps:
                for k in ('NC dn', "NTDS DN"):
                    self.assertRegex('^%s$' % DN_RE, r[k])
                for k in ("last attempt time",
                          "last attempt message",
                          "last success"):
                    self.assertTrue(isinstance(r[k], json_str))
                self.assertRegex('^%s$' % GUID_RE, r["DSA objectGUID"])
                self.assertTrue(isinstance(r["consecutive failures"], int))

        # ntdsconnection
        for n in d["NTDSConnections"]:
            self.assertRegex(r'^[\w]+\.samba\.example\.com$', n["dns name"])
            self.assertRegex("^%s$" % GUID_RE, n["name"])
            self.assertTrue(isinstance(n['enabled'], bool))
            self.assertTrue(isinstance(n['options'], int))
            self.assertTrue(isinstance(n['replicates NC'], list))
            self.assertRegex("^%s$" % DN_RE, n["remote DN"])

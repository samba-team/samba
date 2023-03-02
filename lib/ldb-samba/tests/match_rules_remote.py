#!/usr/bin/env python3

import optparse
import sys
import os
import samba
import samba.getopt as options

from samba.tests.subunitrun import SubunitOptions, TestProgram

from samba.samdb import SamDB
from samba.auth import system_session
from samba import sd_utils
from samba.ndr import ndr_unpack
from ldb import Message, MessageElement, Dn, LdbError
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from ldb import SCOPE_BASE, SCOPE_SUBTREE, SCOPE_ONELEVEL

from match_rules import MatchRulesTestsBase


class MatchRulesTestsUser(MatchRulesTestsBase):
    def setUp(self):
        self.sambaopts = sambaopts
        self.credopts = credopts
        self.host = host
        super().setUp()
        self.sd_utils = sd_utils.SDUtils(self.ldb)

        self.user_pass = "samba123@"
        self.match_test_user = "matchtestuser"
        self.ldb.newuser(self.match_test_user,
                         self.user_pass,
                         userou=self.ou_rdn)
        user_creds = self.insta_creds(template=self.creds,
                                      username=self.match_test_user,
                                      userpass=self.user_pass)
        self.user_ldb = SamDB(host, credentials=user_creds, lp=self.lp)
        token_res = self.user_ldb.search(scope=SCOPE_BASE,
                                         base="",
                                         attrs=["tokenGroups"])
        self.user_sid = ndr_unpack(samba.dcerpc.security.dom_sid,
                                   token_res[0]["tokenGroups"][0])

        self.member_attr_guid = "bf9679c0-0de6-11d0-a285-00aa003049e2"

    def test_with_denied_link(self):

        # add an ACE that denies the user Read Property (RP) access to
        # the member attr (which is similar to making the attribute
        # confidential)
        ace = "(OD;;RP;{0};;{1})".format(self.member_attr_guid,
                                         self.user_sid)
        g2_dn = Dn(self.ldb, "CN=g2,%s" % self.ou_groups)

        # add the ACE that denies access to the attr under test
        self.sd_utils.dacl_add_ace(g2_dn, ace)

        # Search without transitive match must return 0 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        # Search with transitive match must return 1 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        # Search as a user match must return 0 results as the intermediate link can't be seen
        res1 = self.user_ldb.search("cn=g4,%s" % self.ou_groups,
                                    scope=SCOPE_BASE,
                                    expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)



parser = optparse.OptionParser("match_rules_remote.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

TestProgram(module=__name__, opts=subunitopts)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# test tokengroups attribute against internal token calculation

import optparse
import sys
import os

sys.path.append("bin/python")
import samba
samba.ensure_external_module("testtools", "testtools")
samba.ensure_external_module("subunit", "subunit/python")

import samba.getopt as options

from samba.auth import system_session
from samba import ldb
from samba.samdb import SamDB
from samba.ndr import ndr_pack, ndr_unpack

from subunit.run import SubunitTestRunner
import unittest

from samba.dcerpc import security
from samba.auth import AUTH_SESSION_INFO_DEFAULT_GROUPS, AUTH_SESSION_INFO_AUTHENTICATED, AUTH_SESSION_INFO_SIMPLE_PRIVILEGES


parser = optparse.OptionParser("ldap.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

url = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

class TokenTest(unittest.TestCase):

    def setUp(self):
        super(TokenTest, self).setUp()
        self.ldb = samdb
        self.base_dn = samdb.domain_dn()

    def test_TokenGroups(self):
        """Testing rootDSE tokengroups against internal calculation"""
        if not url.startswith("ldap"):
            self.fail(msg="This test is only valid on ldap")

        res = self.ldb.search("", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEquals(len(res), 1)

        print("Geting tokenGroups from rootDSE")
        tokengroups = []
        for sid in res[0]['tokenGroups']:
            tokengroups.append(str(ndr_unpack(samba.dcerpc.security.dom_sid, sid)))

        print("Geting token from user session")
        session_info_flags = ( AUTH_SESSION_INFO_DEFAULT_GROUPS |
                               AUTH_SESSION_INFO_AUTHENTICATED |
                               AUTH_SESSION_INFO_SIMPLE_PRIVILEGES)
        session = samba.auth.user_session(self.ldb, lp_ctx=lp, dn="<SID=%s>" % tokengroups[0],
                                          session_info_flags=session_info_flags)

        token = session.security_token
        sids = []
        for s in token.sids:
            sids.append(str(s))
        sidset1 = set(tokengroups)
        sidset2 = set(sids)
        if sidset1 != sidset2:
            print("token sids don't match")
            print("tokengroups: %s" % tokengroups)
            print("calculated : %s" % sids);
            print("difference : %s" % sidset1.difference(sidset2))
            self.fail(msg="token groups don't match")



if not "://" in url:
    if os.path.isfile(url):
        url = "tdb://%s" % url
    else:
        url = "ldap://%s" % url

samdb = SamDB(url, credentials=creds, session_info=system_session(lp), lp=lp)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(TokenTest)).wasSuccessful():
    rc = 1
sys.exit(rc)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Basic sanity-checks of user login. This sanity-checks that a user can login
# over both NTLM and Kerberos, that incorrect passwords are rejected, and that
# the user can change their password successfully.
#
# Copyright Andrew Bartlett 2018
#
from __future__ import print_function
import optparse
import sys
from samba.tests.subunitrun import TestProgram, SubunitOptions
import samba.getopt as options
from samba.auth import system_session
from samba.credentials import MUST_USE_KERBEROS
from samba.dsdb import UF_NORMAL_ACCOUNT
from samba.samdb import SamDB
from password_lockout_base import BasePasswordTestCase

sys.path.insert(0, "bin/python")

parser = optparse.OptionParser("password_lockout.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
global_creds = credopts.get_credentials(lp)


#
# Tests start here
#
class BasicUserAuthTests(BasePasswordTestCase):

    def setUp(self):
        self.host = host
        self.host_url = host_url
        self.lp = lp
        self.global_creds = global_creds
        self.ldb = SamDB(url=self.host_url, credentials=self.global_creds,
                         session_info=system_session(self.lp), lp=self.lp)
        super(BasicUserAuthTests, self).setUp()

    def _test_login_basics(self, creds):
        username = creds.get_username()
        userpass = creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)
        if creds.get_kerberos_state() == MUST_USE_KERBEROS:
            logoncount_relation = 'greater'
            lastlogon_relation = 'greater'
            print("Performs a lockout attempt against LDAP using Kerberos")
        else:
            logoncount_relation = 'equal'
            lastlogon_relation = 'equal'
            print("Performs a lockout attempt against LDAP using NTLM")

        # get the intial logon values for this user
        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=("greater", 0),
                                  logonCount=(logoncount_relation, 0),
                                  lastLogon=("greater", 0),
                                  lastLogonTimestamp=("greater", 0),
                                  userAccountControl=UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg='Initial test setup...')
        badPasswordTime = int(res[0]["badPasswordTime"][0])
        logonCount = int(res[0]["logonCount"][0])
        lastLogon = int(res[0]["lastLogon"][0])
        lastLogonTimestamp = int(res[0]["lastLogonTimestamp"][0])

        test_creds = self.insta_creds(creds)

        # check logging in with the wrong password fails
        test_creds.set_password("thatsAcomplPASS1xBAD")
        self.assertLoginFailure(self.host_url, test_creds, self.lp)
        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg='Test login with wrong password')
        badPasswordTime = int(res[0]["badPasswordTime"][0])

        # check logging in with the correct password succeeds
        test_creds.set_password(userpass)
        user_ldb = SamDB(url=self.host_url, credentials=test_creds, lp=self.lp)
        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=(logoncount_relation, logonCount),
                                  lastLogon=('greater', lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg='Test login with correct password')
        logonCount = int(res[0]["logonCount"][0])
        lastLogon = int(res[0]["lastLogon"][0])

        # check that the user can change its password
        new_password = "thatsAcomplPASS2"
        user_ldb.modify_ldif("""
dn: %s
changetype: modify
delete: userPassword
userPassword: %s
add: userPassword
userPassword: %s
""" % (userdn, userpass, new_password))

        # discard the old creds (i.e. get rid of our valid Kerberos ticket)
        del test_creds
        test_creds = self.insta_creds(creds)
        test_creds.set_password(userpass)

        # for Kerberos, logging in with the old password fails
        if creds.get_kerberos_state() == MUST_USE_KERBEROS:
            self.assertLoginFailure(self.host_url, test_creds, self.lp)
            info_msg = 'Test Kerberos login with old password fails'
            expectBadPwdTime = ("greater", badPasswordTime)
            res = self._check_account(userdn,
                                      badPwdCount=1,
                                      badPasswordTime=expectBadPwdTime,
                                      logonCount=logonCount,
                                      lastLogon=lastLogon,
                                      lastLogonTimestamp=lastLogonTimestamp,
                                      userAccountControl=UF_NORMAL_ACCOUNT,
                                      msDSUserAccountControlComputed=0,
                                      msg=info_msg)
            badPasswordTime = int(res[0]["badPasswordTime"][0])
        else:
            # for NTLM, logging in with the old password succeeds
            user_ldb = SamDB(url=self.host_url, credentials=test_creds,
                             lp=self.lp)
            info_msg = 'Test NTLM login with old password succeeds'
            res = self._check_account(userdn,
                                      badPwdCount=0,
                                      badPasswordTime=badPasswordTime,
                                      logonCount=logonCount,
                                      lastLogon=lastLogon,
                                      lastLogonTimestamp=lastLogonTimestamp,
                                      userAccountControl=UF_NORMAL_ACCOUNT,
                                      msDSUserAccountControlComputed=0,
                                      msg=info_msg)

        # check logging in with the new password succeeds
        test_creds.set_password(new_password)
        user_ldb = SamDB(url=self.host_url, credentials=test_creds, lp=self.lp)
        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=(logoncount_relation, logonCount),
                                  lastLogon=(lastlogon_relation, lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg='Test login with new password succeeds')

    def test_login_basics_krb5(self):
        self._test_login_basics(self.lockout1krb5_creds)

    def test_login_basics_ntlm(self):
        self._test_login_basics(self.lockout1ntlm_creds)


host_url = "ldap://%s" % host

TestProgram(module=__name__, opts=subunitopts)

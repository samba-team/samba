#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
"""Test communication of credentials etc, between an RODC and a RWDC.

How does it work when the password is changed on the RWDC?
"""

import optparse
import sys
import base64
import uuid
import subprocess
import itertools
import time

sys.path.insert(0, "bin/python")
import samba
import ldb

from samba.tests.subunitrun import SubunitOptions, TestProgram
import samba.getopt as options

from samba.auth import system_session
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS, MUST_USE_KERBEROS
from samba import gensec, dsdb
from ldb import SCOPE_BASE, LdbError, ERR_INVALID_CREDENTIALS
from samba.dcerpc import security, samr

import password_lockout_base

def passwd_encode(pw):
    return base64.b64encode(('"%s"' % pw).encode('utf-16-le'))


class RodcRwdcTestException(Exception):
    pass


def make_creds(username, password, kerberos_state=None):
    # use the global CREDS as a template
    c = Credentials()
    c.set_username(username)
    c.set_password(password)
    c.set_domain(CREDS.get_domain())
    c.set_realm(CREDS.get_realm())
    c.set_workstation(CREDS.get_workstation())

    if kerberos_state is None:
        kerberos_state = CREDS.get_kerberos_state()
    c.set_kerberos_state(kerberos_state)

    print('-' * 73)
    if kerberos_state == MUST_USE_KERBEROS:
        print("we seem to be using kerberos for %s %s" % (username, password))
    elif kerberos_state == DONT_USE_KERBEROS:
        print("NOT using kerberos for %s %s" % (username, password))
    else:
        print("kerberos state is %s" % kerberos_state)

    c.set_gensec_features(c.get_gensec_features() |
                          gensec.FEATURE_SEAL)
    return c


def set_auto_replication(dc, allow):
    credstring = '-U%s%%%s' % (CREDS.get_username(),
                               CREDS.get_password())

    on_or_off = '-' if allow else '+'

    for opt in ['DISABLE_INBOUND_REPL',
                'DISABLE_OUTBOUND_REPL']:
        cmd = ['bin/samba-tool',
               'drs', 'options',
               credstring, dc,
               "--dsa-option=%s%s" % (on_or_off, opt)]

        p = subprocess.Popen(cmd,
                             stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if p.returncode:
            if 'LDAP_REFERRAL' not in stderr:
                raise RodcRwdcTestException()
            print ("ignoring +%s REFERRAL error; assuming %s is RODC" %
                   (opt, dc))


def preload_rodc_user(user_dn):
    credstring = '-U%s%%%s' % (CREDS.get_username(),
                               CREDS.get_password())

    set_auto_replication(RWDC, True)
    cmd = ['bin/samba-tool',
           'rodc', 'preload',
           user_dn,
           credstring,
           '--server', RWDC,]

    print(' '.join(cmd))
    subprocess.check_call(cmd)
    set_auto_replication(RWDC, False)



def get_server_ref_from_samdb(samdb):
    server_name = samdb.get_serverName()
    res = samdb.search(server_name,
                       scope=ldb.SCOPE_BASE,
                       attrs=['serverReference'])

    return res[0]['serverReference'][0]

class RodcRwdcCachedTests(password_lockout_base.BasePasswordTestCase):
    counter = itertools.count(1).next

    def _check_account_initial(self, dn):
        self.force_replication()
        return super(RodcRwdcCachedTests, self)._check_account_initial(dn)

    def _check_account(self, dn,
                       badPwdCount=None,
                       badPasswordTime=None,
                       logonCount=None,
                       lastLogon=None,
                       lastLogonTimestamp=None,
                       lockoutTime=None,
                       userAccountControl=None,
                       msDSUserAccountControlComputed=None,
                       effective_bad_password_count=None,
                       msg=None,
                       badPwdCountOnly=False):
        # Wait for the RWDC to get any delayed messages
        # e.g. SendToSam or KRB5 bad passwords via winbindd
        if (self.kerberos and isinstance(badPasswordTime, tuple) or
            badPwdCount == 0):
            time.sleep(5)

        return super(RodcRwdcCachedTests,
                     self)._check_account(dn, badPwdCount, badPasswordTime,
                                          logonCount, lastLogon,
                                          lastLogonTimestamp, lockoutTime,
                                          userAccountControl,
                                          msDSUserAccountControlComputed,
                                          effective_bad_password_count, msg,
                                          True)

    def force_replication(self, base=None):
        if base is None:
            base = self.base_dn

        # XXX feels like a horrendous way to do it.
        credstring = '-U%s%%%s' % (CREDS.get_username(),
                                   CREDS.get_password())
        cmd = ['bin/samba-tool',
               'drs', 'replicate',
               RODC, RWDC, base,
               credstring,
               '--sync-forced']

        p = subprocess.Popen(cmd,
                             stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if p.returncode:
            print("failed with code %s" % p.returncode)
            print(' '.join(cmd))
            print("stdout")
            print(stdout)
            print("stderr")
            print(stderr)
            raise RodcRwdcTestException()

    def _change_password(self, user_dn, old_password, new_password):
        self.rwdc_db.modify_ldif(
            "dn: %s\n"
            "changetype: modify\n"
            "delete: userPassword\n"
            "userPassword: %s\n"
            "add: userPassword\n"
            "userPassword: %s\n" % (user_dn, old_password, new_password))

    def tearDown(self):
        super(RodcRwdcCachedTests, self).tearDown()
        set_auto_replication(RWDC, True)

    def setUp(self):
        self.kerberos = False # To be set later

        self.rodc_db = SamDB('ldap://%s' % RODC, credentials=CREDS,
                             session_info=system_session(LP), lp=LP)

        self.rwdc_db = SamDB('ldap://%s' % RWDC, credentials=CREDS,
                             session_info=system_session(LP), lp=LP)

        # Define variables for BasePasswordTestCase
        self.lp = LP
        self.global_creds = CREDS
        self.host = RWDC
        self.host_url = 'ldap://%s' % RWDC
        self.ldb = SamDB(url='ldap://%s' % RWDC, session_info=system_session(self.lp),
                         credentials=self.global_creds, lp=self.lp)

        super(RodcRwdcCachedTests, self).setUp()
        self.host_url = 'ldap://%s' % RODC

        self.samr = samr.samr("ncacn_ip_tcp:%s[seal]" % self.host, self.lp, self.global_creds)
        self.samr_handle = self.samr.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.samr_domain = self.samr.OpenDomain(self.samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED, self.domain_sid)

        self.base_dn = self.rwdc_db.domain_dn()

        root = self.rodc_db.search(base='', scope=ldb.SCOPE_BASE,
                                   attrs=['dsServiceName'])
        self.service = root[0]['dsServiceName'][0]
        self.tag = uuid.uuid4().hex

        self.rwdc_dsheuristics = self.rwdc_db.get_dsheuristics()
        self.rwdc_db.set_dsheuristics("000000001")

        set_auto_replication(RWDC, False)

        # make sure DCs are synchronized before the test
        self.force_replication()

    def delete_ldb_connections(self):
        super(RodcRwdcCachedTests, self).delete_ldb_connections()
        del self.rwdc_db
        del self.rodc_db

    def test_cache_and_flush_password(self):
        username = self.lockout1krb5_creds.get_username()
        userpass = self.lockout1krb5_creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        ldb_system = SamDB(session_info=system_session(self.lp),
                           credentials=self.global_creds, lp=self.lp)

        res = ldb_system.search(userdn, attrs=['unicodePwd'])
        self.assertFalse('unicodePwd' in res[0])

        preload_rodc_user(userdn)

        res = ldb_system.search(userdn, attrs=['unicodePwd'])
        self.assertTrue('unicodePwd' in res[0])

        newpass = userpass + '!'

        # Forcing replication should blank out password (when changed)
        self._change_password(userdn, userpass, newpass)
        self.force_replication()

        res = ldb_system.search(userdn, attrs=['unicodePwd'])
        self.assertFalse('unicodePwd' in res[0])

    def test_login_lockout_krb5(self):
        username = self.lockout1krb5_creds.get_username()
        userpass = self.lockout1krb5_creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        preload_rodc_user(userdn)

        self.kerberos = True

        self.rodc_dn = get_server_ref_from_samdb(self.rodc_db)

        res = self.rodc_db.search(self.rodc_dn,
                                  scope=ldb.SCOPE_BASE,
                                  attrs=['msDS-RevealOnDemandGroup'])

        group = res[0]['msDS-RevealOnDemandGroup'][0]

        m = ldb.Message()
        m.dn = ldb.Dn(self.rwdc_db, group)
        m['member'] = ldb.MessageElement(userdn, ldb.FLAG_MOD_ADD, 'member')
        self.rwdc_db.modify(m)

        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, self.base_dn)

        self.account_lockout_duration = 10
        account_lockout_duration_ticks = -int(self.account_lockout_duration * (1e7))

        m["lockoutDuration"] = ldb.MessageElement(str(account_lockout_duration_ticks),
                                                  ldb.FLAG_MOD_REPLACE,
                                                  "lockoutDuration")

        self.lockout_observation_window = 10
        lockout_observation_window_ticks = -int(self.lockout_observation_window * (1e7))

        m["lockOutObservationWindow"] = ldb.MessageElement(str(lockout_observation_window_ticks),
                                                           ldb.FLAG_MOD_REPLACE,
                                                           "lockOutObservationWindow")

        self.rwdc_db.modify(m)
        self.force_replication()

        self._test_login_lockout_rodc_rwdc(self.lockout1krb5_creds, userdn)

    def test_login_lockout_ntlm(self):
        username = self.lockout1ntlm_creds.get_username()
        userpass = self.lockout1ntlm_creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        preload_rodc_user(userdn)

        self.kerberos = False

        self.rodc_dn = get_server_ref_from_samdb(self.rodc_db)

        res = self.rodc_db.search(self.rodc_dn,
                                  scope=ldb.SCOPE_BASE,
                                  attrs=['msDS-RevealOnDemandGroup'])

        group = res[0]['msDS-RevealOnDemandGroup'][0]

        m = ldb.Message()
        m.dn = ldb.Dn(self.rwdc_db, group)
        m['member'] = ldb.MessageElement(userdn, ldb.FLAG_MOD_ADD, 'member')
        self.rwdc_db.modify(m)

        self._test_login_lockout_rodc_rwdc(self.lockout1ntlm_creds, userdn)

    def test_login_lockout_not_revealed(self):
        '''Test that SendToSam is restricted by preloaded users/groups'''

        username = self.lockout1ntlm_creds.get_username()
        userpass = self.lockout1ntlm_creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        # Preload but do not add to revealed group
        preload_rodc_user(userdn)

        self.kerberos = False

        creds = self.lockout1ntlm_creds

        # Open a second LDB connection with the user credentials. Use the
        # command line credentials for informations like the domain, the realm
        # and the workstation.
        creds_lockout = self.insta_creds(creds)

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")

        self.assertLoginFailure(self.host_url, creds_lockout, self.lp)

        badPasswordTime = 0
        logonCount = 0
        lastLogon = 0
        lastLogonTimestamp=0
        logoncount_relation = ''
        lastlogon_relation = ''

        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg='lastlogontimestamp with wrong password')
        badPasswordTime = int(res[0]["badPasswordTime"][0])

        # BadPwdCount on RODC increases alongside RWDC
        res = self.rodc_db.search(userdn, attrs=['badPwdCount'])
        self.assertTrue('badPwdCount' in res[0])
        self.assertEqual(int(res[0]['badPwdCount'][0]), 1)

        # Correct old password
        creds_lockout.set_password(userpass)

        ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)

        # Wait for potential SendToSam...
        time.sleep(5)

        # BadPwdCount on RODC decreases, but not the RWDC
        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=(logoncount_relation, logonCount),
                                  lastLogon=('greater', lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg='badPwdCount not reset on RWDC')

        res = self.rodc_db.search(userdn, attrs=['badPwdCount'])
        self.assertTrue('badPwdCount' in res[0])
        self.assertEqual(int(res[0]['badPwdCount'][0]), 0)

    def _test_login_lockout_rodc_rwdc(self, creds, userdn):
        username = creds.get_username()
        userpass = creds.get_password()

        # Open a second LDB connection with the user credentials. Use the
        # command line credentials for informations like the domain, the realm
        # and the workstation.
        creds_lockout = self.insta_creds(creds)

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")

        self.assertLoginFailure(self.host_url, creds_lockout, self.lp)

        badPasswordTime = 0
        logonCount = 0
        lastLogon = 0
        lastLogonTimestamp=0
        logoncount_relation = ''
        lastlogon_relation = ''

        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg='lastlogontimestamp with wrong password')
        badPasswordTime = int(res[0]["badPasswordTime"][0])

        # Correct old password
        creds_lockout.set_password(userpass)

        ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)

        # lastLogonTimestamp should not change
        # lastLogon increases if badPwdCount is non-zero (!)
        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=(logoncount_relation, logonCount),
                                  lastLogon=('greater', lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg='LLTimestamp is updated to lastlogon')

        logonCount = int(res[0]["logonCount"][0])
        lastLogon = int(res[0]["lastLogon"][0])

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")

        self.assertLoginFailure(self.host_url, creds_lockout, self.lp)

        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)
        badPasswordTime = int(res[0]["badPasswordTime"][0])

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")

        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()

        except LdbError as e1:
            (num, msg) = e1.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=2,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)
        badPasswordTime = int(res[0]["badPasswordTime"][0])

        print("two failed password change")

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")

        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()

        except LdbError as e2:
            (num, msg) = e2.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=3,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  lockoutTime=("greater", badPasswordTime),
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=dsdb.UF_LOCKOUT)
        badPasswordTime = int(res[0]["badPasswordTime"][0])
        lockoutTime = int(res[0]["lockoutTime"][0])

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")
        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()
        except LdbError as e3:
            (num, msg) = e3.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=3,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  lockoutTime=lockoutTime,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=dsdb.UF_LOCKOUT)

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")
        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()
        except LdbError as e4:
            (num, msg) = e4.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=3,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  lockoutTime=lockoutTime,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=dsdb.UF_LOCKOUT)

        # The correct password, but we are locked out
        creds_lockout.set_password(userpass)
        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()
        except LdbError as e5:
            (num, msg) = e5.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=3,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=logonCount,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  lockoutTime=lockoutTime,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=dsdb.UF_LOCKOUT)

        # wait for the lockout to end
        time.sleep(self.account_lockout_duration + 1)
        print(self.account_lockout_duration + 1)

        res = self._check_account(userdn,
                                  badPwdCount=3, effective_bad_password_count=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=logonCount,
                                  lockoutTime=lockoutTime,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)

        # The correct password after letting the timeout expire

        creds_lockout.set_password(userpass)

        creds_lockout2 = self.insta_creds(creds_lockout)

        ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout2, lp=self.lp)
        time.sleep(3)

        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=(logoncount_relation, logonCount),
                                  lastLogon=(lastlogon_relation, lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  lockoutTime=lockoutTime,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg="lastLogon is way off")

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")
        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()
        except LdbError as e6:
            (num, msg) = e6.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lockoutTime=lockoutTime,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)
        badPasswordTime = int(res[0]["badPasswordTime"][0])

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")
        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()
        except LdbError as e7:
            (num, msg) = e7.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=2,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lockoutTime=lockoutTime,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)
        badPasswordTime = int(res[0]["badPasswordTime"][0])

        time.sleep(self.lockout_observation_window + 1)

        res = self._check_account(userdn,
                                  badPwdCount=2, effective_bad_password_count=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=logonCount,
                                  lockoutTime=lockoutTime,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")
        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()
        except LdbError as e8:
            (num, msg) = e8.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lockoutTime=lockoutTime,
                                  lastLogon=lastLogon,
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)
        badPasswordTime = int(res[0]["badPasswordTime"][0])

        # The correct password without letting the timeout expire
        creds_lockout.set_password(userpass)
        ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)

        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=(logoncount_relation, logonCount),
                                  lockoutTime=lockoutTime,
                                  lastLogon=("greater", lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)

class RodcRwdcTests(password_lockout_base.BasePasswordTestCase):
    counter = itertools.count(1).next

    def force_replication(self, base=None):
        if base is None:
            base = self.base_dn

        # XXX feels like a horrendous way to do it.
        credstring = '-U%s%%%s' % (CREDS.get_username(),
                                   CREDS.get_password())
        cmd = ['bin/samba-tool',
               'drs', 'replicate',
               RODC, RWDC, base,
               credstring,
               '--sync-forced']

        p = subprocess.Popen(cmd,
                             stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if p.returncode:
            print("failed with code %s" % p.returncode)
            print(' '.join(cmd))
            print("stdout")
            print(stdout)
            print("stderr")
            print(stderr)
            raise RodcRwdcTestException()

    def _check_account_initial(self, dn):
        self.force_replication()
        return super(RodcRwdcTests, self)._check_account_initial(dn)

    def tearDown(self):
        super(RodcRwdcTests, self).tearDown()
        self.rwdc_db.set_dsheuristics(self.rwdc_dsheuristics)
        CREDS.set_kerberos_state(DONT_USE_KERBEROS)
        set_auto_replication(RWDC, True)

    def setUp(self):
        self.rodc_db = SamDB('ldap://%s' % RODC, credentials=CREDS,
                             session_info=system_session(LP), lp=LP)

        self.rwdc_db = SamDB('ldap://%s' % RWDC, credentials=CREDS,
                             session_info=system_session(LP), lp=LP)

        # Define variables for BasePasswordTestCase
        self.lp = LP
        self.global_creds = CREDS
        self.host = RWDC
        self.host_url = 'ldap://%s' % RWDC
        self.ldb = SamDB(url='ldap://%s' % RWDC, session_info=system_session(self.lp),
                         credentials=self.global_creds, lp=self.lp)

        super(RodcRwdcTests, self).setUp()
        self.host = RODC
        self.host_url = 'ldap://%s' % RODC
        self.ldb = SamDB(url='ldap://%s' % RODC, session_info=system_session(self.lp),
                         credentials=self.global_creds, lp=self.lp)

        self.samr = samr.samr("ncacn_ip_tcp:%s[seal]" % self.host, self.lp, self.global_creds)
        self.samr_handle = self.samr.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.samr_domain = self.samr.OpenDomain(self.samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED, self.domain_sid)

        self.base_dn = self.rwdc_db.domain_dn()

        root = self.rodc_db.search(base='', scope=ldb.SCOPE_BASE,
                                   attrs=['dsServiceName'])
        self.service = root[0]['dsServiceName'][0]
        self.tag = uuid.uuid4().hex

        self.rwdc_dsheuristics = self.rwdc_db.get_dsheuristics()
        self.rwdc_db.set_dsheuristics("000000001")

        set_auto_replication(RWDC, False)

        # make sure DCs are synchronized before the test
        self.force_replication()
        self.rwdc_dn = get_server_ref_from_samdb(self.rwdc_db)
        self.rodc_dn = get_server_ref_from_samdb(self.rodc_db)

    def delete_ldb_connections(self):
        super(RodcRwdcTests, self).delete_ldb_connections()
        del self.rwdc_db
        del self.rodc_db

    def assertReferral(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
            self.fail("failed to raise ldap referral")
        except ldb.LdbError as e9:
            (code, msg) = e9.args
            self.assertEqual(code, ldb.ERR_REFERRAL,
                             "expected referral, got %s %s" % (code, msg))

    def _test_rodc_dsheuristics(self):
        d = self.rodc_db.get_dsheuristics()
        self.assertReferral(self.rodc_db.set_dsheuristics, "000000001")
        self.assertReferral(self.rodc_db.set_dsheuristics, d)

    def TEST_rodc_heuristics_kerberos(self):
        CREDS.set_kerberos_state(MUST_USE_KERBEROS)
        self._test_rodc_dsheuristics()

    def TEST_rodc_heuristics_ntlm(self):
        CREDS.set_kerberos_state(DONT_USE_KERBEROS)
        self._test_rodc_dsheuristics()

    def _test_add(self, objects, cross_ncs=False):
        for o in objects:
            dn = o['dn']
            if cross_ncs:
                base = str(self.rwdc_db.get_config_basedn())
                controls = ["search_options:1:2"]
                cn = dn.split(',', 1)[0]
                expression = '(%s)' % cn
            else:
                base = dn
                controls = []
                expression = None

            try:
                res = self.rodc_db.search(base,
                                          expression=expression,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=['dn'],
                                          controls=controls)
                self.assertEqual(len(res), 0)
            except ldb.LdbError as e:
                if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                    raise

            try:
                self.rwdc_db.add(o)
            except ldb.LdbError as e:
                (ecode, emsg) = e.args
                self.fail("Failed to add %s to rwdc: ldb error: %s %s" %
                          (ecode, emsg))

            if cross_ncs:
                self.force_replication(base=base)
            else:
                self.force_replication()

            try:
                res = self.rodc_db.search(base,
                                          expression=expression,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=['dn'],
                                          controls=controls)
                self.assertEqual(len(res), 1)
            except ldb.LdbError as e:
                self.assertNotEqual(e.args[0], ldb.ERR_NO_SUCH_OBJECT,
                                    "replication seems to have failed")

    def _test_add_replicated_objects(self, mode):
        tag = "%s%s" % (self.tag, mode)
        self._test_add([
            {
                'dn': "ou=%s1,%s" % (tag, self.base_dn),
                "objectclass": "organizationalUnit"
            },
            {
                'dn': "cn=%s2,%s" % (tag, self.base_dn),
                "objectclass": "user"
            },
            {
                'dn': "cn=%s3,%s" % (tag, self.base_dn),
                "objectclass": "group"
            },
        ])
        self.rwdc_db.delete("ou=%s1,%s" % (tag, self.base_dn))
        self.rwdc_db.delete("cn=%s2,%s" % (tag, self.base_dn))
        self.rwdc_db.delete("cn=%s3,%s" % (tag, self.base_dn))

    def test_add_replicated_objects_kerberos(self):
        CREDS.set_kerberos_state(MUST_USE_KERBEROS)
        self._test_add_replicated_objects('kerberos')

    def test_add_replicated_objects_ntlm(self):
        CREDS.set_kerberos_state(DONT_USE_KERBEROS)
        self._test_add_replicated_objects('ntlm')

    def _test_add_replicated_connections(self, mode):
        tag = "%s%s" % (self.tag, mode)
        self._test_add([
            {
                'dn': "cn=%sfoofoofoo,%s" % (tag, self.service),
                "objectclass": "NTDSConnection",
                'enabledConnection': 'TRUE',
                'fromServer': self.base_dn,
                'options': '0'
            },
        ], cross_ncs=True)
        self.rwdc_db.delete("cn=%sfoofoofoo,%s" % (tag, self.service))

    def test_add_replicated_connections_kerberos(self):
        CREDS.set_kerberos_state(MUST_USE_KERBEROS)
        self._test_add_replicated_connections('kerberos')

    def test_add_replicated_connections_ntlm(self):
        CREDS.set_kerberos_state(DONT_USE_KERBEROS)
        self._test_add_replicated_connections('ntlm')

    def _test_modify_replicated_attributes(self):
        dn = 'CN=Guest,CN=Users,' + self.base_dn
        value = self.tag
        for attr in ['carLicense', 'middleName']:
            m = ldb.Message()
            m.dn = ldb.Dn(self.rwdc_db, dn)
            m[attr] = ldb.MessageElement(value,
                                         ldb.FLAG_MOD_REPLACE,
                                         attr)
            try:
                self.rwdc_db.modify(m)
            except ldb.LdbError as e:
                self.fail("Failed to modify %s %s on RWDC %s with %s" %
                          (dn, attr, RWDC, e))

            self.force_replication()

            try:
                res = self.rodc_db.search(dn,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=[attr])
                results = [x[attr][0] for x in res]
                self.assertEqual(results, [value])
            except ldb.LdbError as e:
                self.assertNotEqual(e.args[0], ldb.ERR_NO_SUCH_OBJECT,
                                    "replication seems to have failed")

    def test_modify_replicated_attributes_kerberos(self):
        CREDS.set_kerberos_state(MUST_USE_KERBEROS)
        self._test_modify_replicated_attributes()

    def test_modify_replicated_attributes_ntlm(self):
        CREDS.set_kerberos_state(DONT_USE_KERBEROS)
        self._test_modify_replicated_attributes()

    def _test_add_modify_delete(self):
        dn = "cn=%s_add_modify,%s" % (self.tag, self.base_dn)
        values = ["%s%s" % (i, self.tag) for i in range(3)]
        attr = "carLicense"
        self._test_add([
            {
                'dn': dn,
                "objectclass": "user",
                attr: values[0]
            },
        ])
        self.force_replication()
        for value in values[1:]:

            m = ldb.Message()
            m.dn = ldb.Dn(self.rwdc_db, dn)
            m[attr] = ldb.MessageElement(value,
                                         ldb.FLAG_MOD_REPLACE,
                                         attr)
            try:
                self.rwdc_db.modify(m)
            except ldb.LdbError as e:
                self.fail("Failed to modify %s %s on RWDC %s with %s" %
                          (dn, attr, RWDC, e))

            self.force_replication()

            try:
                res = self.rodc_db.search(dn,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=[attr])
                results = [x[attr][0] for x in res]
                self.assertEqual(results, [value])
            except ldb.LdbError as e:
                self.assertNotEqual(e.args[0], ldb.ERR_NO_SUCH_OBJECT,
                                    "replication seems to have failed")

        self.rwdc_db.delete(dn)
        self.force_replication()
        try:
            res = self.rodc_db.search(dn,
                                      scope=ldb.SCOPE_SUBTREE,
                                      attrs=[attr])
            if len(res) > 0:
                self.fail("Failed to delete %s" % (dn))
        except ldb.LdbError as e:
            self.assertEqual(e.args[0], ldb.ERR_NO_SUCH_OBJECT,
                             "Failed to delete %s" % (dn))

    def test_add_modify_delete_kerberos(self):
        CREDS.set_kerberos_state(MUST_USE_KERBEROS)
        self._test_add_modify_delete()

    def test_add_modify_delete_ntlm(self):
        CREDS.set_kerberos_state(DONT_USE_KERBEROS)
        self._test_add_modify_delete()

    def _new_user(self):
        username = "u%sX%s" % (self.tag[:12], self.counter())
        password = 'password#1'
        dn = 'CN=%s,CN=Users,%s' % (username, self.base_dn)
        o = {
            'dn': dn,
            "objectclass": "user",
            'sAMAccountName': username,
        }
        try:
            self.rwdc_db.add(o)
        except ldb.LdbError as e:
            self.fail("Failed to add %s to rwdc: ldb error: %s" % (o, e))

        self.rwdc_db.modify_ldif("dn: %s\n"
                                 "changetype: modify\n"
                                 "delete: userPassword\n"
                                 "add: userPassword\n"
                                 "userPassword: %s\n" % (dn, password))
        self.rwdc_db.enable_account("(sAMAccountName=%s)" % username)
        return (dn, username, password)

    def _change_password(self, user_dn, old_password, new_password):
        self.rwdc_db.modify_ldif(
            "dn: %s\n"
            "changetype: modify\n"
            "delete: userPassword\n"
            "userPassword: %s\n"
            "add: userPassword\n"
            "userPassword: %s\n" % (user_dn, old_password, new_password))

    def try_ldap_logon(self, server, creds, errno=None):
        try:
            tmpdb = SamDB('ldap://%s' % server, credentials=creds,
                          session_info=system_session(LP), lp=LP)
            if errno is not None:
                self.fail("logon failed to fail with ldb error %s" % errno)
        except ldb.LdbError as e10:
            (code, msg) = e10.args
            if code != errno:
                if errno is None:
                    self.fail("logon incorrectly raised ldb error (code=%s)" %
                              code)
                else:
                    self.fail("logon failed to raise correct ldb error"
                              "Expected: %s Got: %s" %
                              (errno, code))


    def zero_min_password_age(self):
        min_pwd_age = int(self.rwdc_db.get_minPwdAge())
        if min_pwd_age != 0:
            self.rwdc_db.set_minPwdAge('0')

    def _test_ldap_change_password(self, errno=None):
        self.zero_min_password_age()

        dn, username, password = self._new_user()
        creds1 = make_creds(username, password)

        # With NTLM, this should fail on RODC before replication,
        # because the user isn't known.
        self.try_ldap_logon(RODC, creds1, ldb.ERR_INVALID_CREDENTIALS)
        self.force_replication()

        # Now the user is replicated to RODC, so logon should work
        self.try_ldap_logon(RODC, creds1)

        passwords = ['password#%s' % i for i in range(1, 6)]
        for prev, password in zip(passwords[:-1], passwords[1:]):
            self._change_password(dn, prev, password)

        # The password has changed enough times to make the old
        # password invalid (though with kerberos that doesn't matter).
        # For NTLM, the old creds should always fail
        self.try_ldap_logon(RODC, creds1, errno)
        self.try_ldap_logon(RWDC, creds1, errno)

        creds2 = make_creds(username, password)

        # new creds work straight away with NTLM, because although it
        # doesn't have the password, it knows the user and forwards
        # the query.
        self.try_ldap_logon(RODC, creds2)
        self.try_ldap_logon(RWDC, creds2)

        self.force_replication()

        # After another replication check RODC still works and fails,
        # as appropriate to various creds
        self.try_ldap_logon(RODC, creds2)
        self.try_ldap_logon(RODC, creds1, errno)

        prev = password
        password = 'password#6'
        self._change_password(dn, prev, password)
        creds3 = make_creds(username, password)

        # previous password should still work.
        self.try_ldap_logon(RWDC, creds2)
        self.try_ldap_logon(RODC, creds2)

        # new password should still work.
        self.try_ldap_logon(RWDC, creds3)
        self.try_ldap_logon(RODC, creds3)

        # old password should still fail (but not on kerberos).
        self.try_ldap_logon(RWDC, creds1, errno)
        self.try_ldap_logon(RODC, creds1, errno)

    def test_ldap_change_password_kerberos(self):
        CREDS.set_kerberos_state(MUST_USE_KERBEROS)
        self._test_ldap_change_password()

    def test_ldap_change_password_ntlm(self):
        CREDS.set_kerberos_state(DONT_USE_KERBEROS)
        self._test_ldap_change_password(ldb.ERR_INVALID_CREDENTIALS)

    def _test_ldap_change_password_reveal_on_demand(self, errno=None):
        self.zero_min_password_age()

        res = self.rodc_db.search(self.rodc_dn,
                                  scope=ldb.SCOPE_BASE,
                                  attrs=['msDS-RevealOnDemandGroup'])

        group = res[0]['msDS-RevealOnDemandGroup'][0]

        user_dn, username, password = self._new_user()
        creds1 = make_creds(username, password)

        m = ldb.Message()
        m.dn = ldb.Dn(self.rwdc_db, group)
        m['member'] = ldb.MessageElement(user_dn, ldb.FLAG_MOD_ADD, 'member')
        self.rwdc_db.modify(m)

        # Against Windows, this will just forward if no account exists on the KDC
        # Therefore, this does not error on Windows.
        self.try_ldap_logon(RODC, creds1, ldb.ERR_INVALID_CREDENTIALS)

        self.force_replication()

        # The proxy case
        self.try_ldap_logon(RODC, creds1)
        preload_rodc_user(user_dn)

        # Now the user AND password are replicated to RODC, so logon should work (not proxy case)
        self.try_ldap_logon(RODC, creds1)

        passwords = ['password#%s' % i for i in range(1, 6)]
        for prev, password in zip(passwords[:-1], passwords[1:]):
            self._change_password(user_dn, prev, password)

        # The password has changed enough times to make the old
        # password invalid, but the RODC shouldn't know that.
        self.try_ldap_logon(RODC, creds1)
        self.try_ldap_logon(RWDC, creds1, errno)

        creds2 = make_creds(username, password)
        self.try_ldap_logon(RWDC, creds2)
        # We can forward WRONG_PASSWORD over NTLM.
        # This SHOULD succeed.
        self.try_ldap_logon(RODC, creds2)


    def test_change_password_reveal_on_demand_ntlm(self):
        CREDS.set_kerberos_state(DONT_USE_KERBEROS)
        self._test_ldap_change_password_reveal_on_demand(ldb.ERR_INVALID_CREDENTIALS)

    def test_change_password_reveal_on_demand_kerberos(self):
        CREDS.set_kerberos_state(MUST_USE_KERBEROS)
        self._test_ldap_change_password_reveal_on_demand()

    def test_login_lockout_krb5(self):
        username = self.lockout1krb5_creds.get_username()
        userpass = self.lockout1krb5_creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        preload_rodc_user(userdn)

        use_kerberos = self.lockout1krb5_creds.get_kerberos_state()
        fail_creds = self.insta_creds(self.template_creds,
                                      username=username,
                                      userpass=userpass+"X",
                                      kerberos_state=use_kerberos)

        try:
            ldb = SamDB(url=self.host_url, credentials=fail_creds, lp=self.lp)
            self.fail()
        except LdbError as e11:
            (num, msg) = e11.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        # Succeed to reset everything to 0
        success_creds = self.insta_creds(self.template_creds,
                                         username=username,
                                         userpass=userpass,
                                         kerberos_state=use_kerberos)

        ldb = SamDB(url=self.host_url, credentials=success_creds, lp=self.lp)

        self._test_login_lockout(self.lockout1krb5_creds)

    def test_login_lockout_ntlm(self):
        username = self.lockout1ntlm_creds.get_username()
        userpass = self.lockout1ntlm_creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        preload_rodc_user(userdn)

        use_kerberos = self.lockout1ntlm_creds.get_kerberos_state()
        fail_creds = self.insta_creds(self.template_creds,
                                      username=username,
                                      userpass=userpass+"X",
                                      kerberos_state=use_kerberos)

        try:
            ldb = SamDB(url=self.host_url, credentials=fail_creds, lp=self.lp)
            self.fail()
        except LdbError as e12:
            (num, msg) = e12.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        # Succeed to reset everything to 0
        ldb = SamDB(url=self.host_url, credentials=self.lockout1ntlm_creds, lp=self.lp)

        self._test_login_lockout(self.lockout1ntlm_creds)

    def test_multiple_logon_krb5(self):
        username = self.lockout1krb5_creds.get_username()
        userpass = self.lockout1krb5_creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        preload_rodc_user(userdn)

        use_kerberos = self.lockout1krb5_creds.get_kerberos_state()
        fail_creds = self.insta_creds(self.template_creds,
                                      username=username,
                                      userpass=userpass+"X",
                                      kerberos_state=use_kerberos)

        try:
            ldb = SamDB(url=self.host_url, credentials=fail_creds, lp=self.lp)
            self.fail()
        except LdbError as e13:
            (num, msg) = e13.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        # Succeed to reset everything to 0
        success_creds = self.insta_creds(self.template_creds,
                                         username=username,
                                         userpass=userpass,
                                         kerberos_state=use_kerberos)

        ldb = SamDB(url=self.host_url, credentials=success_creds, lp=self.lp)

        self._test_multiple_logon(self.lockout1krb5_creds)

    def test_multiple_logon_ntlm(self):
        username = self.lockout1ntlm_creds.get_username()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)
        userpass = self.lockout1ntlm_creds.get_password()

        preload_rodc_user(userdn)

        use_kerberos = self.lockout1ntlm_creds.get_kerberos_state()
        fail_creds = self.insta_creds(self.template_creds,
                                      username=username,
                                      userpass=userpass+"X",
                                      kerberos_state=use_kerberos)

        try:
            ldb = SamDB(url=self.host_url, credentials=fail_creds, lp=self.lp)
            self.fail()
        except LdbError as e14:
            (num, msg) = e14.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        # Succeed to reset everything to 0
        ldb = SamDB(url=self.host_url, credentials=self.lockout1ntlm_creds, lp=self.lp)

        self._test_multiple_logon(self.lockout1ntlm_creds)

def main():
    global RODC, RWDC, CREDS, LP
    parser = optparse.OptionParser(
        "rodc_rwdc.py [options] <rodc host> <rwdc host>")

    sambaopts = options.SambaOptions(parser)
    versionopts = options.VersionOptions(parser)
    credopts = options.CredentialsOptions(parser)
    subunitopts = SubunitOptions(parser)

    parser.add_option_group(sambaopts)
    parser.add_option_group(versionopts)
    parser.add_option_group(credopts)
    parser.add_option_group(subunitopts)

    opts, args = parser.parse_args()

    LP = sambaopts.get_loadparm()
    CREDS = credopts.get_credentials(LP)
    CREDS.set_gensec_features(CREDS.get_gensec_features() |
                              gensec.FEATURE_SEAL)

    try:
        RODC, RWDC = args
    except ValueError:
        parser.print_usage()
        sys.exit(1)

    set_auto_replication(RWDC, True)
    try:
        TestProgram(module=__name__, opts=subunitopts)
    finally:
        set_auto_replication(RWDC, True)

main()

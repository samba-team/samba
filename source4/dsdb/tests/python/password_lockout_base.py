from __future__ import print_function
import samba

from samba.auth import system_session
from samba.credentials import Credentials, DONT_USE_KERBEROS, MUST_USE_KERBEROS
from ldb import SCOPE_BASE, LdbError
from ldb import ERR_CONSTRAINT_VIOLATION
from ldb import ERR_INVALID_CREDENTIALS
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_REPLACE
from samba import gensec, dsdb
from samba.samdb import SamDB
import samba.tests
from samba.tests import delete_force
from samba.dcerpc import security, samr
from samba.ndr import ndr_unpack

import time

class BasePasswordTestCase(samba.tests.TestCase):
    def _open_samr_user(self, res):
        self.assertTrue("objectSid" in res[0])

        (domain_sid, rid) = ndr_unpack(security.dom_sid, res[0]["objectSid"][0]).split()
        self.assertEquals(self.domain_sid, domain_sid)

        return self.samr.OpenUser(self.samr_domain, security.SEC_FLAG_MAXIMUM_ALLOWED, rid)

    def _check_attribute(self, res, name, value):
        if value is None:
            self.assertTrue(name not in res[0],
                            msg="attr[%s]=%r on dn[%s]" %
                            (name, res[0], res[0].dn))
            return

        if isinstance(value, tuple):
            (mode, value) = value
        else:
            mode = "equal"

        if mode == "ignore":
            return

        if mode == "absent":
            self.assertFalse(name in res[0],
                            msg="attr[%s] not missing on dn[%s]" %
                            (name, res[0].dn))
            return

        self.assertTrue(name in res[0],
                        msg="attr[%s] missing on dn[%s]" %
                        (name, res[0].dn))
        self.assertTrue(len(res[0][name]) == 1,
                        msg="attr[%s]=%r on dn[%s]" %
                        (name, res[0][name], res[0].dn))


        print("%s = '%s'" % (name, res[0][name][0]))

        if mode == "present":
            return

        if mode == "equal":
            v = int(res[0][name][0])
            value = int(value)
            msg = ("attr[%s]=[%s] != [%s] on dn[%s]\n"
                   "(diff %d; actual value is %s than expected)"  %
                   (name, v, value, res[0].dn, v - value,
                    ('less' if v < value else 'greater')))

            self.assertTrue(v == value, msg)
            return

        if mode == "greater":
            v = int(res[0][name][0])
            self.assertTrue(v > int(value),
                            msg="attr[%s]=[%s] <= [%s] on dn[%s] (diff %d)" %
                            (name, v, int(value), res[0].dn, v - int(value)))
            return
        if mode == "less":
            v = int(res[0][name][0])
            self.assertTrue(v < int(value),
                            msg="attr[%s]=[%s] >= [%s] on dn[%s] (diff %d)" %
                            (name, v, int(value), res[0].dn, v - int(value)))
            return
        self.assertEqual(mode, not mode, "Invalid Mode[%s]" % mode)

    def _check_account_initial(self, userdn):
        self._check_account(userdn,
                            badPwdCount=0,
                            badPasswordTime=0,
                            logonCount=0,
                            lastLogon=0,
                            lastLogonTimestamp=("absent", None),
                            userAccountControl=
                            dsdb.UF_NORMAL_ACCOUNT,
                            msDSUserAccountControlComputed=0)

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
        print('-=' * 36)
        if msg is not None:
            print("\033[01;32m %s \033[00m\n" % msg)
        attrs = [
           "objectSid",
           "badPwdCount",
           "badPasswordTime",
           "lastLogon",
           "lastLogonTimestamp",
           "logonCount",
           "lockoutTime",
           "userAccountControl",
           "msDS-User-Account-Control-Computed"
        ]

        # in order to prevent some time resolution problems we sleep for
        # 10 micro second
        time.sleep(0.01)

        res = self.ldb.search(dn, scope=SCOPE_BASE, attrs=attrs)
        self.assertTrue(len(res) == 1)
        self._check_attribute(res, "badPwdCount", badPwdCount)
        self._check_attribute(res, "lockoutTime", lockoutTime)
        self._check_attribute(res, "badPasswordTime", badPasswordTime)
        if not badPwdCountOnly:
            self._check_attribute(res, "logonCount", logonCount)
            self._check_attribute(res, "lastLogon", lastLogon)
            self._check_attribute(res, "lastLogonTimestamp", lastLogonTimestamp)
            self._check_attribute(res, "userAccountControl", userAccountControl)
            self._check_attribute(res, "msDS-User-Account-Control-Computed",
                                  msDSUserAccountControlComputed)

            lastLogon = int(res[0]["lastLogon"][0])
            logonCount = int(res[0]["logonCount"][0])

        samr_user = self._open_samr_user(res)
        uinfo3 = self.samr.QueryUserInfo(samr_user, 3)
        uinfo5 = self.samr.QueryUserInfo(samr_user, 5)
        uinfo16 = self.samr.QueryUserInfo(samr_user, 16)
        uinfo21 = self.samr.QueryUserInfo(samr_user, 21)
        self.samr.Close(samr_user)

        expected_acb_info = 0
        if not badPwdCountOnly:
            if userAccountControl & dsdb.UF_NORMAL_ACCOUNT:
                expected_acb_info |= samr.ACB_NORMAL
            if userAccountControl & dsdb.UF_ACCOUNTDISABLE:
                expected_acb_info |= samr.ACB_DISABLED
            if userAccountControl & dsdb.UF_PASSWD_NOTREQD:
                expected_acb_info |= samr.ACB_PWNOTREQ
            if msDSUserAccountControlComputed & dsdb.UF_LOCKOUT:
                expected_acb_info |= samr.ACB_AUTOLOCK
            if msDSUserAccountControlComputed & dsdb.UF_PASSWORD_EXPIRED:
                expected_acb_info |= samr.ACB_PW_EXPIRED

            self.assertEquals(uinfo3.acct_flags, expected_acb_info)
            self.assertEquals(uinfo3.last_logon, lastLogon)
            self.assertEquals(uinfo3.logon_count, logonCount)

        expected_bad_password_count = 0
        if badPwdCount is not None:
            expected_bad_password_count = badPwdCount
        if effective_bad_password_count is None:
            effective_bad_password_count = expected_bad_password_count

        self.assertEquals(uinfo3.bad_password_count, expected_bad_password_count)

        if not badPwdCountOnly:
            self.assertEquals(uinfo5.acct_flags, expected_acb_info)
            self.assertEquals(uinfo5.bad_password_count, effective_bad_password_count)
            self.assertEquals(uinfo5.last_logon, lastLogon)
            self.assertEquals(uinfo5.logon_count, logonCount)

            self.assertEquals(uinfo16.acct_flags, expected_acb_info)

            self.assertEquals(uinfo21.acct_flags, expected_acb_info)
            self.assertEquals(uinfo21.bad_password_count, effective_bad_password_count)
            self.assertEquals(uinfo21.last_logon, lastLogon)
            self.assertEquals(uinfo21.logon_count, logonCount)


        # check LDAP again and make sure the samr.QueryUserInfo
        # doesn't have any impact.
        res2 = self.ldb.search(dn, scope=SCOPE_BASE, attrs=attrs)
        self.assertEquals(res[0], res2[0])

        # in order to prevent some time resolution problems we sleep for
        # 10 micro second
        time.sleep(0.01)
        return res

    def _readd_user(self, creds, lockOutObservationWindow=0):
        username = creds.get_username()
        userpass = creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        delete_force(self.ldb, userdn)
        self.ldb.add({
             "dn": userdn,
             "objectclass": "user",
             "sAMAccountName": username})

        self.addCleanup(delete_force, self.ldb, userdn)

        # Sets the initial user password with a "special" password change
        # I think that this internally is a password set operation and it can
        # only be performed by someone which has password set privileges on the
        # account (at least in s4 we do handle it like that).
        self.ldb.modify_ldif("""
dn: """ + userdn + """
changetype: modify
delete: userPassword
add: userPassword
userPassword: """ + userpass + """
""")
        # Enables the user account
        self.ldb.enable_account("(sAMAccountName=%s)" % username)

        use_kerberos = creds.get_kerberos_state()
        fail_creds = self.insta_creds(self.template_creds,
                                      username=username,
                                      userpass=userpass+"X",
                                      kerberos_state=use_kerberos)
        self._check_account_initial(userdn)

        # Fail once to get a badPasswordTime
        try:
            ldb = SamDB(url=self.host_url, credentials=fail_creds, lp=self.lp)
            self.fail()
        except LdbError as e:
            (num, msg) = e.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        # Succeed to reset everything to 0
        ldb = SamDB(url=self.host_url, credentials=creds, lp=self.lp)

        return ldb

    def assertLoginFailure(self, url, creds, lp, errno=ERR_INVALID_CREDENTIALS):
        try:
            ldb = SamDB(url=url, credentials=creds, lp=lp)
            self.fail("Login unexpectedly succeeded")
        except LdbError as e1:
            (num, msg) = e1.args
            if errno is not None:
                self.assertEquals(num, errno, ("Login failed in the wrong way"
                                               "(got err %d, expected %d)" %
                                               (num, errno)))

    def setUp(self):
        super(BasePasswordTestCase, self).setUp()

        self.global_creds.set_gensec_features(self.global_creds.get_gensec_features() |
                                              gensec.FEATURE_SEAL)

        self.template_creds = Credentials()
        self.template_creds.set_username("testuser")
        self.template_creds.set_password("thatsAcomplPASS1")
        self.template_creds.set_domain(self.global_creds.get_domain())
        self.template_creds.set_realm(self.global_creds.get_realm())
        self.template_creds.set_workstation(self.global_creds.get_workstation())
        self.template_creds.set_gensec_features(self.global_creds.get_gensec_features())
        self.template_creds.set_kerberos_state(self.global_creds.get_kerberos_state())


        # Gets back the basedn
        base_dn = self.ldb.domain_dn()

        # Gets back the configuration basedn
        configuration_dn = self.ldb.get_config_basedn().get_linearized()

        # Get the old "dSHeuristics" if it was set
        dsheuristics = self.ldb.get_dsheuristics()

        # Reset the "dSHeuristics" as they were before
        self.addCleanup(self.ldb.set_dsheuristics, dsheuristics)

        res = self.ldb.search(base_dn,
                         scope=SCOPE_BASE, attrs=["lockoutDuration", "lockOutObservationWindow", "lockoutThreshold"])

        if "lockoutDuration" in res[0]:
            lockoutDuration = res[0]["lockoutDuration"][0]
        else:
            lockoutDuration = 0

        if "lockoutObservationWindow" in res[0]:
            lockoutObservationWindow = res[0]["lockoutObservationWindow"][0]
        else:
            lockoutObservationWindow = 0

        if "lockoutThreshold" in res[0]:
            lockoutThreshold = res[0]["lockoutThreshold"][0]
        else:
            lockoutTreshold = 0

        self.addCleanup(self.ldb.modify_ldif, """
dn: """ + base_dn + """
changetype: modify
replace: lockoutDuration
lockoutDuration: """ + str(lockoutDuration) + """
replace: lockoutObservationWindow
lockoutObservationWindow: """ + str(lockoutObservationWindow) + """
replace: lockoutThreshold
lockoutThreshold: """ + str(lockoutThreshold) + """
""")

        m = Message()
        m.dn = Dn(self.ldb, base_dn)

        self.account_lockout_duration = 2
        account_lockout_duration_ticks = -int(self.account_lockout_duration * (1e7))

        m["lockoutDuration"] = MessageElement(str(account_lockout_duration_ticks),
                                              FLAG_MOD_REPLACE, "lockoutDuration")

        account_lockout_threshold = 3
        m["lockoutThreshold"] = MessageElement(str(account_lockout_threshold),
                                               FLAG_MOD_REPLACE, "lockoutThreshold")

        self.lockout_observation_window = 2
        lockout_observation_window_ticks = -int(self.lockout_observation_window * (1e7))

        m["lockOutObservationWindow"] = MessageElement(str(lockout_observation_window_ticks),
                                                       FLAG_MOD_REPLACE, "lockOutObservationWindow")

        self.ldb.modify(m)

        # Set the "dSHeuristics" to activate the correct "userPassword" behaviour
        self.ldb.set_dsheuristics("000000001")

        # Get the old "minPwdAge"
        minPwdAge = self.ldb.get_minPwdAge()

        # Reset the "minPwdAge" as it was before
        self.addCleanup(self.ldb.set_minPwdAge, minPwdAge)

        # Set it temporarely to "0"
        self.ldb.set_minPwdAge("0")

        self.base_dn = self.ldb.domain_dn()

        self.domain_sid = security.dom_sid(self.ldb.get_domain_sid())
        self.samr = samr.samr("ncacn_ip_tcp:%s[seal]" % self.host, self.lp, self.global_creds)
        self.samr_handle = self.samr.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        self.samr_domain = self.samr.OpenDomain(self.samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED, self.domain_sid)

        self.addCleanup(self.delete_ldb_connections)

        # (Re)adds the test user accounts
        self.lockout1krb5_creds = self.insta_creds(self.template_creds,
                                                   username="lockout1krb5",
                                                   userpass="thatsAcomplPASS0",
                                                   kerberos_state=MUST_USE_KERBEROS)
        self.lockout1krb5_ldb = self._readd_user(self.lockout1krb5_creds)
        self.lockout1ntlm_creds = self.insta_creds(self.template_creds,
                                                   username="lockout1ntlm",
                                                   userpass="thatsAcomplPASS0",
                                                   kerberos_state=DONT_USE_KERBEROS)
        self.lockout1ntlm_ldb = self._readd_user(self.lockout1ntlm_creds)

    def delete_ldb_connections(self):
        del self.lockout1krb5_ldb
        del self.lockout1ntlm_ldb
        del self.ldb

    def tearDown(self):
        super(BasePasswordTestCase, self).tearDown()

    def _test_login_lockout(self, creds):
        username = creds.get_username()
        userpass = creds.get_password()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        use_kerberos = creds.get_kerberos_state()
        # This unlocks by waiting for account_lockout_duration
        if use_kerberos == MUST_USE_KERBEROS:
            logoncount_relation = 'greater'
            lastlogon_relation = 'greater'
            print("Performs a lockout attempt against LDAP using Kerberos")
        else:
            logoncount_relation = 'equal'
            lastlogon_relation = 'equal'
            print("Performs a lockout attempt against LDAP using NTLM")

        # Change password on a connection as another user
        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=("greater", 0),
                                  logonCount=(logoncount_relation, 0),
                                  lastLogon=("greater", 0),
                                  lastLogonTimestamp=("greater", 0),
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)
        badPasswordTime = int(res[0]["badPasswordTime"][0])
        logonCount = int(res[0]["logonCount"][0])
        lastLogon = int(res[0]["lastLogon"][0])
        firstLogon = lastLogon
        lastLogonTimestamp = int(res[0]["lastLogonTimestamp"][0])
        print(firstLogon)
        print(lastLogonTimestamp)


        self.assertGreater(lastLogon, badPasswordTime)
        self.assertGreaterEqual(lastLogon, lastLogonTimestamp)

        # Open a second LDB connection with the user credentials. Use the
        # command line credentials for informations like the domain, the realm
        # and the workstation.
        creds_lockout = self.insta_creds(creds)

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
        self.assertGreater(lastLogon, badPasswordTime)
        self.assertGreaterEqual(lastLogon, lastLogonTimestamp)

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

        except LdbError as e2:
            (num, msg) = e2.args
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

        except LdbError as e3:
            (num, msg) = e3.args
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

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")
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

        # The correct password, but we are locked out
        creds_lockout.set_password(userpass)
        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()
        except LdbError as e6:
            (num, msg) = e6.args
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
                                  lockoutTime=0,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg="lastLogon is way off")

        logonCount = int(res[0]["logonCount"][0])
        lastLogon = int(res[0]["lastLogon"][0])

        # The wrong password
        creds_lockout.set_password("thatsAcomplPASS1x")
        try:
            ldb_lockout = SamDB(url=self.host_url, credentials=creds_lockout, lp=self.lp)
            self.fail()
        except LdbError as e7:
            (num, msg) = e7.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lockoutTime=0,
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
        except LdbError as e8:
            (num, msg) = e8.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=2,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lockoutTime=0,
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
                                  lockoutTime=0,
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
        except LdbError as e9:
            (num, msg) = e9.args
            self.assertEquals(num, ERR_INVALID_CREDENTIALS)

        res = self._check_account(userdn,
                                  badPwdCount=1,
                                  badPasswordTime=("greater", badPasswordTime),
                                  logonCount=logonCount,
                                  lockoutTime=0,
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
                                  lockoutTime=0,
                                  lastLogon=("greater", lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)

    def _test_multiple_logon(self, creds):
        # Test the happy case in which a user logs on correctly, then
        # logs on correctly again, so that the bad password and
        # lockout times are both zero the second time. The lastlogon
        # time should increase.

        # Open a second LDB connection with the user credentials. Use the
        # command line credentials for informations like the domain, the realm
        # and the workstation.
        username = creds.get_username()
        userdn = "cn=%s,cn=users,%s" % (username, self.base_dn)

        use_kerberos = creds.get_kerberos_state()
        if use_kerberos == MUST_USE_KERBEROS:
            print("Testing multiple logon with Kerberos")
            logoncount_relation = 'greater'
            lastlogon_relation = 'greater'
        else:
            print("Testing multiple logon with NTLM")
            logoncount_relation = 'equal'
            lastlogon_relation = 'equal'

        SamDB(url=self.host_url, credentials=self.insta_creds(creds), lp=self.lp)

        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=("greater", 0),
                                  logonCount=(logoncount_relation, 0),
                                  lastLogon=("greater", 0),
                                  lastLogonTimestamp=("greater", 0),
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)
        badPasswordTime = int(res[0]["badPasswordTime"][0])
        logonCount = int(res[0]["logonCount"][0])
        lastLogon = int(res[0]["lastLogon"][0])
        lastLogonTimestamp = int(res[0]["lastLogonTimestamp"][0])
        firstLogon = lastLogon
        print("last logon is %d" % lastLogon)
        self.assertGreater(lastLogon, badPasswordTime)
        self.assertGreaterEqual(lastLogon, lastLogonTimestamp)

        time.sleep(1)
        SamDB(url=self.host_url, credentials=self.insta_creds(creds), lp=self.lp)

        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=(logoncount_relation, logonCount),
                                  lastLogon=(lastlogon_relation, lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                  dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0,
                                  msg=("second logon, firstlogon was %s" %
                                       firstLogon))


        lastLogon = int(res[0]["lastLogon"][0])

        time.sleep(1)

        SamDB(url=self.host_url, credentials=self.insta_creds(creds), lp=self.lp)

        res = self._check_account(userdn,
                                  badPwdCount=0,
                                  badPasswordTime=badPasswordTime,
                                  logonCount=(logoncount_relation, logonCount),
                                  lastLogon=(lastlogon_relation, lastLogon),
                                  lastLogonTimestamp=lastLogonTimestamp,
                                  userAccountControl=
                                    dsdb.UF_NORMAL_ACCOUNT,
                                  msDSUserAccountControlComputed=0)

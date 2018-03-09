# Unix SMB/CIFS implementation.
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

from __future__ import print_function
"""Tests for the Auth and AuthZ logging.
"""
from samba import auth
import samba.tests
from samba.messaging import Messaging
from samba.dcerpc.messaging import MSG_AUTH_LOG, AUTH_EVENT_NAME
from samba.dcerpc import srvsvc, dnsserver
import time
import json
import os
from samba import smb
from samba.samdb import SamDB
import samba.tests.auth_log_base
from samba.credentials import Credentials, DONT_USE_KERBEROS, MUST_USE_KERBEROS
from samba import NTSTATUSError
from subprocess import call
from ldb import LdbError

class AuthLogTests(samba.tests.auth_log_base.AuthLogTestBase):

    def setUp(self):
        super(AuthLogTests, self).setUp()
        self.remoteAddress = os.environ["CLIENT_IP"]

    def tearDown(self):
        super(AuthLogTests, self).tearDown()



    def _test_rpc_ncacn_np(self, authTypes, creds, service,
                           binding, protection, checkFunction):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    (msg["Authorization"]["serviceDescription"] == "DCE/RPC" or
                     msg["Authorization"]["serviceDescription"] == service) and
                    msg["Authorization"]["authType"] == authTypes[0] and
                    msg["Authorization"]["transportProtection"] == protection)

        if binding:
            binding = "[%s]" % binding

        if service == "dnsserver":
            x = dnsserver.dnsserver("ncacn_np:%s%s" % (self.server, binding),
                                self.get_loadparm(),
                                creds)
        elif service == "srvsvc":
            x = srvsvc.srvsvc("ncacn_np:%s%s" % (self.server, binding),
                              self.get_loadparm(),
                              creds)

        # The connection is passed to ensure the server
        # messaging context stays up until all the messages have been received.
        messages = self.waitForMessages(isLastExpectedMessage, x)
        checkFunction(messages, authTypes, service, binding, protection)

    def rpc_ncacn_np_ntlm_check(self, messages, authTypes, service,
                                binding, protection):

        expected_messages = len(authTypes)
        self.assertEquals(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("SMB",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals(authTypes[1], msg["Authentication"]["authDescription"])

        # Check the second message it should be an Authorization
        msg = messages[1]
        self.assertEquals("Authorization", msg["type"])
        self.assertEquals("SMB",
                          msg["Authorization"]["serviceDescription"])
        self.assertEquals(authTypes[2], msg["Authorization"]["authType"])
        self.assertEquals("SMB", msg["Authorization"]["transportProtection"])

        # Check the third message it should be an Authentication
        # if we are expecting 4 messages
        if expected_messages == 4:
            def checkServiceDescription(desc):
                return (desc == "DCE/RPC" or desc == service)

            msg = messages[2]
            self.assertEquals("Authentication", msg["type"])
            self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
            self.assertTrue(
                checkServiceDescription(msg["Authentication"]["serviceDescription"]))

            self.assertEquals(authTypes[3], msg["Authentication"]["authDescription"])

    def rpc_ncacn_np_krb5_check(self, messages, authTypes, service, binding, protection):

        expected_messages = len(authTypes)
        self.assertEquals(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authentication
        # This is almost certainly Authentication over UDP, and is probably
        # returning message too big,
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("Kerberos KDC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals(authTypes[1], msg["Authentication"]["authDescription"])

        # Check the second message it should be an Authentication
        # This this the TCP Authentication in response to the message too big
        # response to the UDP Authentication
        msg = messages[1]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("Kerberos KDC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals(authTypes[2], msg["Authentication"]["authDescription"])

        # Check the third message it should be an Authorization
        msg = messages[2]
        self.assertEquals("Authorization", msg["type"])
        serviceDescription = "SMB"
        print("binding %s" % binding)
        if binding == "[smb2]":
            serviceDescription = "SMB2"

        self.assertEquals(serviceDescription,
                          msg["Authorization"]["serviceDescription"])
        self.assertEquals(authTypes[3], msg["Authorization"]["authType"])
        self.assertEquals("SMB", msg["Authorization"]["transportProtection"])


    def test_rpc_ncacn_np_ntlm_dns_sign(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncacn_np(["NTLMSSP",
                                 "NTLMSSP",
                                 "NTLMSSP",
                                 "NTLMSSP"],
                                creds, "dnsserver", "sign", "SIGN",
                                self.rpc_ncacn_np_ntlm_check)

    def test_rpc_ncacn_np_ntlm_srv_sign(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncacn_np(["NTLMSSP",
                                 "NTLMSSP",
                                 "NTLMSSP",
                                 "NTLMSSP"],
                                creds, "srvsvc", "sign", "SIGN",
                                self.rpc_ncacn_np_ntlm_check)

    def test_rpc_ncacn_np_ntlm_dns(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncacn_np(["ncacn_np",
                                 "NTLMSSP",
                                 "NTLMSSP"],
                                creds, "dnsserver", "", "SMB",
                                self.rpc_ncacn_np_ntlm_check)

    def test_rpc_ncacn_np_ntlm_srv(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncacn_np(["ncacn_np",
                                 "NTLMSSP",
                                 "NTLMSSP"],
                                creds, "srvsvc", "", "SMB",
                                self.rpc_ncacn_np_ntlm_check)

    def test_rpc_ncacn_np_krb_dns_sign(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_np(["krb5",
                                 "ENC-TS Pre-authentication",
                                 "ENC-TS Pre-authentication",
                                 "krb5"],
                                 creds, "dnsserver", "sign", "SIGN",
                                 self.rpc_ncacn_np_krb5_check)

    def test_rpc_ncacn_np_krb_srv_sign(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_np(["krb5",
                                 "ENC-TS Pre-authentication",
                                 "ENC-TS Pre-authentication",
                                 "krb5"],
                                 creds, "srvsvc", "sign", "SIGN",
                                 self.rpc_ncacn_np_krb5_check)

    def test_rpc_ncacn_np_krb_dns(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_np(["ncacn_np",
                                 "ENC-TS Pre-authentication",
                                 "ENC-TS Pre-authentication",
                                 "krb5"],
                                creds, "dnsserver", "", "SMB",
                                self.rpc_ncacn_np_krb5_check)

    def test_rpc_ncacn_np_krb_dns_smb2(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_np(["ncacn_np",
                                 "ENC-TS Pre-authentication",
                                 "ENC-TS Pre-authentication",
                                 "krb5"],
                                creds, "dnsserver", "smb2", "SMB",
                                self.rpc_ncacn_np_krb5_check)

    def test_rpc_ncacn_np_krb_srv(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_np(["ncacn_np",
                                "ENC-TS Pre-authentication",
                                "ENC-TS Pre-authentication",
                                "krb5"],
                                creds, "srvsvc", "", "SMB",
                                self.rpc_ncacn_np_krb5_check)

    def _test_rpc_ncacn_ip_tcp(self, authTypes, creds, service,
                               binding, protection, checkFunction):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "DCE/RPC" and
                    msg["Authorization"]["authType"] == authTypes[0] and
                    msg["Authorization"]["transportProtection"] == protection)

        if binding:
            binding = "[%s]" % binding

        if service == "dnsserver":
            conn = dnsserver.dnsserver("ncacn_ip_tcp:%s%s" % (self.server, binding),
                                       self.get_loadparm(),
                                       creds)
        elif service == "srvsvc":
            conn = srvsvc.srvsvc("ncacn_ip_tcp:%s%s" % (self.server, binding),
                                 self.get_loadparm(),
                                 creds)


        messages = self.waitForMessages(isLastExpectedMessage, conn)
        checkFunction(messages, authTypes, service, binding, protection)

    def rpc_ncacn_ip_tcp_ntlm_check(self, messages, authTypes, service,
                                    binding, protection):

        expected_messages = len(authTypes)
        self.assertEquals(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authorization
        msg = messages[0]
        self.assertEquals("Authorization", msg["type"])
        self.assertEquals("DCE/RPC",
                          msg["Authorization"]["serviceDescription"])
        self.assertEquals(authTypes[1], msg["Authorization"]["authType"])
        self.assertEquals("NONE", msg["Authorization"]["transportProtection"])

        # Check the second message it should be an Authentication
        msg = messages[1]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("DCE/RPC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals(authTypes[2], msg["Authentication"]["authDescription"])

    def rpc_ncacn_ip_tcp_krb5_check(self, messages, authTypes, service,
                                    binding, protection):

        expected_messages = len(authTypes)
        self.assertEquals(expected_messages,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authorization
        msg = messages[0]
        self.assertEquals("Authorization", msg["type"])
        self.assertEquals("DCE/RPC",
                          msg["Authorization"]["serviceDescription"])
        self.assertEquals(authTypes[1], msg["Authorization"]["authType"])
        self.assertEquals("NONE", msg["Authorization"]["transportProtection"])

        # Check the second message it should be an Authentication
        msg = messages[1]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("Kerberos KDC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals(authTypes[2], msg["Authentication"]["authDescription"])

        # Check the third message it should be an Authentication
        msg = messages[2]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("Kerberos KDC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals(authTypes[2], msg["Authentication"]["authDescription"])

    def test_rpc_ncacn_ip_tcp_ntlm_dns_sign(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncacn_ip_tcp(["NTLMSSP",
                                     "ncacn_ip_tcp",
                                     "NTLMSSP"],
                                     creds, "dnsserver", "sign", "SIGN",
                                     self.rpc_ncacn_ip_tcp_ntlm_check)

    def test_rpc_ncacn_ip_tcp_krb5_dns_sign(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_ip_tcp(["krb5",
                                     "ncacn_ip_tcp",
                                     "ENC-TS Pre-authentication",
                                     "ENC-TS Pre-authentication"],
                                     creds, "dnsserver", "sign", "SIGN",
                                     self.rpc_ncacn_ip_tcp_krb5_check)

    def test_rpc_ncacn_ip_tcp_ntlm_dns(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncacn_ip_tcp(["NTLMSSP",
                                     "ncacn_ip_tcp",
                                     "NTLMSSP"],
                                     creds, "dnsserver", "", "SIGN",
                                     self.rpc_ncacn_ip_tcp_ntlm_check)

    def test_rpc_ncacn_ip_tcp_krb5_dns(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_ip_tcp(["krb5",
                                     "ncacn_ip_tcp",
                                     "ENC-TS Pre-authentication",
                                     "ENC-TS Pre-authentication"],
                                     creds, "dnsserver", "", "SIGN",
                                     self.rpc_ncacn_ip_tcp_krb5_check)

    def test_rpc_ncacn_ip_tcp_ntlm_dns_connect(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncacn_ip_tcp(["NTLMSSP",
                                     "ncacn_ip_tcp",
                                     "NTLMSSP"],
                                     creds, "dnsserver", "connect", "NONE",
                                     self.rpc_ncacn_ip_tcp_ntlm_check)

    def test_rpc_ncacn_ip_tcp_krb5_dns_connect(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_ip_tcp(["krb5",
                                     "ncacn_ip_tcp",
                                     "ENC-TS Pre-authentication",
                                     "ENC-TS Pre-authentication"],
                                     creds, "dnsserver", "connect", "NONE",
                                     self.rpc_ncacn_ip_tcp_krb5_check)

    def test_rpc_ncacn_ip_tcp_ntlm_dns_seal(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        self._test_rpc_ncacn_ip_tcp(["NTLMSSP",
                                     "ncacn_ip_tcp",
                                     "NTLMSSP"],
                                     creds, "dnsserver", "seal", "SEAL",
                                     self.rpc_ncacn_ip_tcp_ntlm_check)

    def test_rpc_ncacn_ip_tcp_krb5_dns_seal(self):
        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=MUST_USE_KERBEROS)
        self._test_rpc_ncacn_ip_tcp(["krb5",
                                     "ncacn_ip_tcp",
                                     "ENC-TS Pre-authentication",
                                     "ENC-TS Pre-authentication"],
                                     creds, "dnsserver", "seal", "SEAL",
                                     self.rpc_ncacn_ip_tcp_krb5_check)

    def test_ldap(self):

        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "LDAP" and
                    msg["Authorization"]["transportProtection"] == "SIGN" and
                    msg["Authorization"]["authType"] == "krb5")

        self.samdb = SamDB(url="ldap://%s" % os.environ["SERVER"],
                           lp = self.get_loadparm(),
                           credentials=self.get_credentials())

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(3,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("Kerberos KDC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals("ENC-TS Pre-authentication",
                           msg["Authentication"]["authDescription"])

        # Check the first message it should be an Authentication
        msg = messages[1]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("Kerberos KDC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals("ENC-TS Pre-authentication",
                           msg["Authentication"]["authDescription"])

    def test_ldap_ntlm(self):

        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "LDAP" and
                    msg["Authorization"]["transportProtection"] == "SEAL" and
                    msg["Authorization"]["authType"] == "NTLMSSP")

        self.samdb = SamDB(url="ldap://%s" % os.environ["SERVER_IP"],
                           lp = self.get_loadparm(),
                           credentials=self.get_credentials())

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(2,
                          len(messages),
                          "Did not receive the expected number of messages")
        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("LDAP",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals("NTLMSSP", msg["Authentication"]["authDescription"])

    def test_ldap_simple_bind(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "LDAP" and
                    msg["Authorization"]["transportProtection"] == "TLS" and
                    msg["Authorization"]["authType"] == "simple bind")

        creds = self.insta_creds(template=self.get_credentials())
        creds.set_bind_dn("%s\\%s" % (creds.get_domain(),
                                     creds.get_username()))

        self.samdb = SamDB(url="ldaps://%s" % os.environ["SERVER"],
                           lp = self.get_loadparm(),
                           credentials=creds)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(2,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("LDAP",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals("simple bind",
                           msg["Authentication"]["authDescription"])

    def test_ldap_simple_bind_bad_password(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"] == "LDAP" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD" and
                    msg["Authentication"]["authDescription"] == "simple bind")

        creds = self.insta_creds(template=self.get_credentials())
        creds.set_password("badPassword")
        creds.set_bind_dn("%s\\%s" % (creds.get_domain(),
                                     creds.get_username()))

        thrown = False
        try:
            self.samdb = SamDB(url="ldaps://%s" % os.environ["SERVER"],
                               lp = self.get_loadparm(),
                               credentials=creds)
        except LdbError:
            thrown = True
        self.assertEquals(thrown, True)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")


    def test_ldap_simple_bind_bad_user(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"] == "LDAP" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER" and
                    msg["Authentication"]["authDescription"] == "simple bind")

        creds = self.insta_creds(template=self.get_credentials())
        creds.set_bind_dn("%s\\%s" % (creds.get_domain(), "badUser"))

        thrown = False
        try:
            self.samdb = SamDB(url="ldaps://%s" % os.environ["SERVER"],
                               lp = self.get_loadparm(),
                               credentials=creds)
        except LdbError:
            thrown = True
        self.assertEquals(thrown, True)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")


    def test_ldap_simple_bind_unparseable_user(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"] == "LDAP" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER" and
                    msg["Authentication"]["authDescription"] == "simple bind")

        creds = self.insta_creds(template=self.get_credentials())
        creds.set_bind_dn("%s\\%s" % (creds.get_domain(), "abdcef"))

        thrown = False
        try:
            self.samdb = SamDB(url="ldaps://%s" % os.environ["SERVER"],
                               lp = self.get_loadparm(),
                               credentials=creds)
        except LdbError:
            thrown = True
        self.assertEquals(thrown, True)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")

    #
    # Note: as this test does not expect any messages it will
    #       time out in the call to self.waitForMessages.
    #       This is expected, but it will slow this test.
    def test_ldap_anonymous_access_bind_only(self):
        # Should be no logging for anonymous bind
        # so receiving any message indicates a failure.
        def isLastExpectedMessage( msg):
            return True

        creds = self.insta_creds(template=self.get_credentials())
        creds.set_anonymous()

        self.samdb = SamDB(url="ldaps://%s" % os.environ["SERVER"],
                           lp = self.get_loadparm(),
                           credentials=creds)

        messages = self.waitForMessages( isLastExpectedMessage)
        self.assertEquals(0,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_ldap_anonymous_access(self):
        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"]  == "LDAP" and
                    msg["Authorization"]["transportProtection"] == "TLS" and
                    msg["Authorization"]["account"] == "ANONYMOUS LOGON" and
                    msg["Authorization"]["authType"] == "no bind")

        creds = self.insta_creds(template=self.get_credentials())
        creds.set_anonymous()

        self.samdb = SamDB(url="ldaps://%s" % os.environ["SERVER"],
                           lp = self.get_loadparm(),
                           credentials=creds)

        try:
            res = self.samdb.search(base=self.samdb.domain_dn())
            self.fail( "Expected an LdbError exception")
        except LdbError:
            pass

        messages = self.waitForMessages( isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")
    def test_smb(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "SMB" and
                    msg["Authorization"]["authType"] == "krb5" and
                    msg["Authorization"]["transportProtection"] == "SMB")

        creds = self.insta_creds(template=self.get_credentials())
        smb.SMB(self.server,
                "sysvol",
                lp=self.get_loadparm(),
                creds=creds)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(3,
                          len(messages),
                          "Did not receive the expected number of messages")
        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("Kerberos KDC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals("ENC-TS Pre-authentication",
                           msg["Authentication"]["authDescription"])

        # Check the second message it should be an Authentication
        msg = messages[1]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("Kerberos KDC",
                           msg["Authentication"]["serviceDescription"])
        self.assertEquals("ENC-TS Pre-authentication",
                           msg["Authentication"]["authDescription"])

    def test_smb_bad_password(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "Kerberos KDC" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD" and
                    msg["Authentication"]["authDescription"]
                        == "ENC-TS Pre-authentication")

        creds = self.insta_creds(template=self.get_credentials())
        creds.set_password("badPassword")

        thrown = False
        try:
            smb.SMB(self.server,
                    "sysvol",
                    lp=self.get_loadparm(),
                    creds=creds)
        except NTSTATUSError:
            thrown = True
        self.assertEquals(thrown, True)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")


    def test_smb_bad_user(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "Kerberos KDC" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER" and
                    msg["Authentication"]["authDescription"]
                        == "ENC-TS Pre-authentication")

        creds = self.insta_creds(template=self.get_credentials())
        creds.set_username("badUser")

        thrown = False
        try:
            smb.SMB(self.server,
                    "sysvol",
                    lp=self.get_loadparm(),
                    creds=creds)
        except NTSTATUSError:
            thrown = True
        self.assertEquals(thrown, True)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_smb1_anonymous(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "SMB" and
                    msg["Authorization"]["authType"] == "NTLMSSP" and
                    msg["Authorization"]["account"] == "ANONYMOUS LOGON" and
                    msg["Authorization"]["transportProtection"] == "SMB")

        server   = os.environ["SERVER"]

        path = "//%s/IPC$" % server
        auth = "-N"
        call(["bin/smbclient", path, auth, "-mNT1", "-c quit"])

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(3,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_NO_SUCH_USER",
                          msg["Authentication"]["status"])
        self.assertEquals("SMB",
                          msg["Authentication"]["serviceDescription"])
        self.assertEquals("NTLMSSP",
                          msg["Authentication"]["authDescription"])
        self.assertEquals("No-Password",
                          msg["Authentication"]["passwordType"])

        # Check the second message it should be an Authentication
        msg = messages[1]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK",
                          msg["Authentication"]["status"])
        self.assertEquals("SMB",
                          msg["Authentication"]["serviceDescription"])
        self.assertEquals("NTLMSSP",
                          msg["Authentication"]["authDescription"])
        self.assertEquals("No-Password",
                          msg["Authentication"]["passwordType"])
        self.assertEquals("ANONYMOUS LOGON",
                          msg["Authentication"]["becameAccount"])

    def test_smb2_anonymous(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "SMB2" and
                    msg["Authorization"]["authType"] == "NTLMSSP" and
                    msg["Authorization"]["account"] == "ANONYMOUS LOGON" and
                    msg["Authorization"]["transportProtection"] == "SMB")

        server   = os.environ["SERVER"]

        path = "//%s/IPC$" % server
        auth = "-N"
        call(["bin/smbclient", path, auth, "-mSMB3", "-c quit"])

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(3,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_NO_SUCH_USER",
                          msg["Authentication"]["status"])
        self.assertEquals("SMB2",
                          msg["Authentication"]["serviceDescription"])
        self.assertEquals("NTLMSSP",
                          msg["Authentication"]["authDescription"])
        self.assertEquals("No-Password",
                          msg["Authentication"]["passwordType"])

        # Check the second message it should be an Authentication
        msg = messages[1]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK",
                          msg["Authentication"]["status"])
        self.assertEquals("SMB2",
                          msg["Authentication"]["serviceDescription"])
        self.assertEquals("NTLMSSP",
                          msg["Authentication"]["authDescription"])
        self.assertEquals("No-Password",
                          msg["Authentication"]["passwordType"])
        self.assertEquals("ANONYMOUS LOGON",
                          msg["Authentication"]["becameAccount"])

    def test_smb_no_krb_spnego(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "SMB" and
                    msg["Authorization"]["authType"] == "NTLMSSP" and
                    msg["Authorization"]["transportProtection"] == "SMB")

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        smb.SMB(self.server,
                "sysvol",
                lp=self.get_loadparm(),
                creds=creds)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(2,
                          len(messages),
                          "Did not receive the expected number of messages")
        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("SMB",
                          msg["Authentication"]["serviceDescription"])
        self.assertEquals("NTLMSSP",
                          msg["Authentication"]["authDescription"])
        self.assertEquals("NTLMv2",
                          msg["Authentication"]["passwordType"])

    def test_smb_no_krb_spnego_bad_password(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"] == "SMB" and
                    msg["Authentication"]["authDescription"] == "NTLMSSP" and
                    msg["Authentication"]["passwordType"] == "NTLMv2" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD")

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        creds.set_password("badPassword")

        thrown = False
        try:
            smb.SMB(self.server,
                    "sysvol",
                    lp=self.get_loadparm(),
                    creds=creds)
        except NTSTATUSError:
            thrown = True
        self.assertEquals(thrown, True)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_smb_no_krb_spnego_bad_user(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"] == "SMB" and
                    msg["Authentication"]["authDescription"] == "NTLMSSP" and
                    msg["Authentication"]["passwordType"] == "NTLMv2" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER")

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        creds.set_username("badUser")

        thrown = False
        try:
            smb.SMB(self.server,
                    "sysvol",
                    lp=self.get_loadparm(),
                    creds=creds)
        except NTSTATUSError:
            thrown = True
        self.assertEquals(thrown, True)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_smb_no_krb_no_spnego_no_ntlmv2(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "SMB" and
                    msg["Authorization"]["authType"] == "bare-NTLM" and
                    msg["Authorization"]["transportProtection"] == "SMB")

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        smb.SMB(self.server,
                "sysvol",
                lp=self.get_loadparm(),
                creds=creds,
                ntlmv2_auth=False,
                use_spnego=False)

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(2,
                          len(messages),
                          "Did not receive the expected number of messages")
        # Check the first message it should be an Authentication
        msg = messages[0]
        self.assertEquals("Authentication", msg["type"])
        self.assertEquals("NT_STATUS_OK", msg["Authentication"]["status"])
        self.assertEquals("SMB",
                          msg["Authentication"]["serviceDescription"])
        self.assertEquals("bare-NTLM",
                          msg["Authentication"]["authDescription"])
        self.assertEquals("NTLMv1",
                          msg["Authentication"]["passwordType"])

    def test_smb_no_krb_no_spnego_no_ntlmv2_bad_password(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"] == "SMB" and
                    msg["Authentication"]["authDescription"] == "bare-NTLM" and
                    msg["Authentication"]["passwordType"] == "NTLMv1" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD")

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        creds.set_password("badPassword")

        thrown = False
        try:
            smb.SMB(self.server,
                    "sysvol",
                    lp=self.get_loadparm(),
                    creds=creds,
                    ntlmv2_auth=False,
                    use_spnego=False)
        except NTSTATUSError:
            thrown = True
        self.assertEquals(thrown, True)


        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_smb_no_krb_no_spnego_no_ntlmv2_bad_user(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"] == "SMB" and
                    msg["Authentication"]["authDescription"] == "bare-NTLM" and
                    msg["Authentication"]["passwordType"] == "NTLMv1" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER")

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        creds.set_username("badUser")

        thrown = False
        try:
            smb.SMB(self.server,
                    "sysvol",
                    lp=self.get_loadparm(),
                    creds=creds,
                    ntlmv2_auth=False,
                    use_spnego=False)
        except NTSTATUSError:
            thrown = True
        self.assertEquals(thrown, True)


        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(1,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_samlogon_interactive(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "interactive" and
                    msg["Authentication"]["status"] == "NT_STATUS_OK" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]
        samlogon = "samlogon %s %s %s %d" % (user, password, workstation, 1)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_interactive_bad_password(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "interactive" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = os.environ["USERNAME"]
        password = "badPassword"
        samlogon = "samlogon %s %s %s %d" % (user, password, workstation, 1)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_interactive_bad_user(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "interactive" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = "badUser"
        password = os.environ["PASSWORD"]
        samlogon = "samlogon %s %s %s %d" % (user, password, workstation, 1)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_network(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "network" and
                    msg["Authentication"]["status"] == "NT_STATUS_OK" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]
        samlogon = "samlogon %s %s %s %d" % (user, password, workstation, 2)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_network_bad_password(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "network" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = os.environ["USERNAME"]
        password = "badPassword"
        samlogon = "samlogon %s %s %s %d" % (user, password, workstation, 2)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_network_bad_user(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "network" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = "badUser"
        password =  os.environ["PASSWORD"]
        samlogon = "samlogon %s %s %s %d" % (user, password, workstation, 2)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_network_mschap(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "network" and
                    msg["Authentication"]["status"] == "NT_STATUS_OK" and
                    msg["Authentication"]["passwordType"] == "MSCHAPv2" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]
        samlogon = "samlogon %s %s %s %d 0x00010000" % (user, password, workstation, 2)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_network_mschap_bad_password(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "network" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD" and
                    msg["Authentication"]["passwordType"] == "MSCHAPv2" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = os.environ["USERNAME"]
        password = "badPassword"
        samlogon = "samlogon %s %s %s %d 0x00010000" % (user, password, workstation, 2)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_network_mschap_bad_user(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "network" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER" and
                    msg["Authentication"]["passwordType"] == "MSCHAPv2" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = "badUser"
        password = os.environ["PASSWORD"]
        samlogon = "samlogon %s %s %s %d 0x00010000" % (user, password, workstation, 2)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

    def test_samlogon_schannel_seal(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "network" and
                    msg["Authentication"]["status"] == "NT_STATUS_OK" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]
        samlogon = "schannel;samlogon %s %s %s" % (user, password, workstation)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

        # Check the second to last message it should be an Authorization
        msg = messages[-2]
        self.assertEquals("Authorization", msg["type"])
        self.assertEquals("DCE/RPC",
                          msg["Authorization"]["serviceDescription"])
        self.assertEquals("schannel",  msg["Authorization"]["authType"])
        self.assertEquals("SEAL", msg["Authorization"]["transportProtection"])

    # Signed logons get promoted to sealed, this test ensures that
    # this behaviour is not removed accidently
    def test_samlogon_schannel_sign(self):

        workstation = "AuthLogTests"

        def isLastExpectedMessage( msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SamLogon" and
                    msg["Authentication"]["authDescription"]
                        == "network" and
                    msg["Authentication"]["status"] == "NT_STATUS_OK" and
                    msg["Authentication"]["workstation"]
                        == r"\\%s" % workstation)

        server   = os.environ["SERVER"]
        user     = os.environ["USERNAME"]
        password = os.environ["PASSWORD"]
        samlogon = "schannelsign;samlogon %s %s %s" % (user, password, workstation)


        call(["bin/rpcclient", "-c", samlogon, "-U%", server])

        messages = self.waitForMessages( isLastExpectedMessage)
        messages = self.remove_netlogon_messages(messages)
        received = len(messages)
        self.assertIs(True,
                      (received == 5 or received == 6),
                      "Did not receive the expected number of messages")

        # Check the second to last message it should be an Authorization
        msg = messages[-2]
        self.assertEquals("Authorization", msg["type"])
        self.assertEquals("DCE/RPC",
                          msg["Authorization"]["serviceDescription"])
        self.assertEquals("schannel",  msg["Authorization"]["authType"])
        self.assertEquals("SEAL", msg["Authorization"]["transportProtection"])

# Integration tests for pycredentials
#
# Copyright (C) Catalyst IT Ltd. 2017
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
from samba.tests import TestCase, delete_force
import os

import samba
from samba.auth import system_session
from samba.credentials import Credentials, CLI_CRED_NTLMv2_AUTH
from samba.dcerpc import netlogon, ntlmssp
from samba.dcerpc.netlogon import netr_Authenticator, netr_WorkstationInformation
from samba.dcerpc.misc import SEC_CHAN_WKSTA
from samba.dsdb import (
    UF_WORKSTATION_TRUST_ACCOUNT,
    UF_PASSWD_NOTREQD,
    UF_NORMAL_ACCOUNT)
from samba.ndr import ndr_pack
from samba.samdb import SamDB
"""
Integration tests for pycredentials
"""

MACHINE_NAME = "PCTM"
USER_NAME    = "PCTU"

class PyCredentialsTests(TestCase):

    def setUp(self):
        super(PyCredentialsTests, self).setUp()

        self.server      = os.environ["SERVER"]
        self.domain      = os.environ["DOMAIN"]
        self.host        = os.environ["SERVER_IP"]
        self.lp          = self.get_loadparm()

        self.credentials = self.get_credentials()

        self.session     = system_session()
        self.ldb = SamDB(url="ldap://%s" % self.host,
                         session_info=self.session,
                         credentials=self.credentials,
                         lp=self.lp)

        self.create_machine_account()
        self.create_user_account()


    def tearDown(self):
        super(PyCredentialsTests, self).tearDown()
        delete_force(self.ldb, self.machine_dn)
        delete_force(self.ldb, self.user_dn)

    # Until a successful netlogon connection has been established there will
    # not be a valid authenticator associated with the credentials
    # and new_client_authenticator should throw a ValueError
    def test_no_netlogon_connection(self):
        self.assertRaises(ValueError,
                          self.machine_creds.new_client_authenticator)

    # Once a netlogon connection has been established,
    # new_client_authenticator should return a value
    #
    def test_have_netlogon_connection(self):
        c = self.get_netlogon_connection()
        a = self.machine_creds.new_client_authenticator()
        self.assertIsNotNone(a)

    # Get an authenticator and use it on a sequence of operations requiring
    # an authenticator
    def test_client_authenticator(self):
        c = self.get_netlogon_connection()
        (authenticator, subsequent) = self.get_authenticator(c)
        self.do_NetrLogonSamLogonWithFlags(c, authenticator, subsequent)
        (authenticator, subsequent) = self.get_authenticator(c)
        self.do_NetrLogonGetDomainInfo(c, authenticator, subsequent)
        (authenticator, subsequent) = self.get_authenticator(c)
        self.do_NetrLogonGetDomainInfo(c, authenticator, subsequent)
        (authenticator, subsequent) = self.get_authenticator(c)
        self.do_NetrLogonGetDomainInfo(c, authenticator, subsequent)

    # Test Credentials.encrypt_netr_crypt_password
    # By performing a NetrServerPasswordSet2
    # And the logging on using the new password.
    def test_encrypt_netr_password(self):
        # Change the password
        self.do_Netr_ServerPasswordSet2()
        # Now use the new password to perform an operation
        self.do_DsrEnumerateDomainTrusts()


   # Change the current machine account pazssword with a
   # netr_ServerPasswordSet2 call.

    def do_Netr_ServerPasswordSet2(self):
        c = self.get_netlogon_connection()
        (authenticator, subsequent) = self.get_authenticator(c)
        PWD_LEN  = 32
        DATA_LEN = 512
        newpass = samba.generate_random_password(PWD_LEN, PWD_LEN)
        filler  = [ord(x) for x in os.urandom(DATA_LEN-PWD_LEN)]
        pwd = netlogon.netr_CryptPassword()
        pwd.length = PWD_LEN
        pwd.data = filler + [ord(x) for x in newpass]
        self.machine_creds.encrypt_netr_crypt_password(pwd)
        c.netr_ServerPasswordSet2(self.server,
                                  self.machine_creds.get_workstation(),
                                  SEC_CHAN_WKSTA,
                                  self.machine_name,
                                  authenticator,
                                  pwd)

        self.machine_pass = newpass
        self.machine_creds.set_password(newpass)

    # Perform a DsrEnumerateDomainTrusts, this provides confirmation that
    # a netlogon connection has been correctly established
    def do_DsrEnumerateDomainTrusts(self):
        c = self.get_netlogon_connection()
        trusts = c.netr_DsrEnumerateDomainTrusts(
            self.server,
            netlogon.NETR_TRUST_FLAG_IN_FOREST |
            netlogon.NETR_TRUST_FLAG_OUTBOUND  |
            netlogon.NETR_TRUST_FLAG_INBOUND)

    # Establish sealed schannel netlogon connection over TCP/IP
    #
    def get_netlogon_connection(self):
        return netlogon.netlogon("ncacn_ip_tcp:%s[schannel,seal]" % self.server,
                                 self.lp,
                                 self.machine_creds)

    #
    # Create the machine account
    def create_machine_account(self):
        self.machine_pass = samba.generate_random_password(32, 32)
        self.machine_name = MACHINE_NAME
        self.machine_dn = "cn=%s,%s" % (self.machine_name, self.ldb.domain_dn())

        # remove the account if it exists, this will happen if a previous test
        # run failed
        delete_force(self.ldb, self.machine_dn)

        utf16pw = unicode(
            '"' + self.machine_pass.encode('utf-8') + '"', 'utf-8'
        ).encode('utf-16-le')
        self.ldb.add({
            "dn": self.machine_dn,
            "objectclass": "computer",
            "sAMAccountName": "%s$" % self.machine_name,
            "userAccountControl":
                str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD),
            "unicodePwd": utf16pw})

        self.machine_creds = Credentials()
        self.machine_creds.guess(self.get_loadparm())
        self.machine_creds.set_secure_channel_type(SEC_CHAN_WKSTA)
        self.machine_creds.set_password(self.machine_pass)
        self.machine_creds.set_username(self.machine_name + "$")
        self.machine_creds.set_workstation(self.machine_name)

    #
    # Create a test user account
    def create_user_account(self):
        self.user_pass = samba.generate_random_password(32, 32)
        self.user_name = USER_NAME
        self.user_dn = "cn=%s,%s" % (self.user_name, self.ldb.domain_dn())

        # remove the account if it exists, this will happen if a previous test
        # run failed
        delete_force(self.ldb, self.user_dn)

        utf16pw = unicode(
            '"' + self.user_pass.encode('utf-8') + '"', 'utf-8'
        ).encode('utf-16-le')
        self.ldb.add({
            "dn": self.user_dn,
            "objectclass": "user",
            "sAMAccountName": "%s" % self.user_name,
            "userAccountControl": str(UF_NORMAL_ACCOUNT),
            "unicodePwd": utf16pw})

        self.user_creds = Credentials()
        self.user_creds.guess(self.get_loadparm())
        self.user_creds.set_password(self.user_pass)
        self.user_creds.set_username(self.user_name)
        self.user_creds.set_workstation(self.machine_name)
        pass

    #
    # Get the authenticator from the machine creds.
    def get_authenticator(self, c):
        auth = self.machine_creds.new_client_authenticator();
        current  = netr_Authenticator()
        current.cred.data = [ord(x) for x in auth["credential"]]
        current.timestamp = auth["timestamp"]

        subsequent = netr_Authenticator()
        return (current, subsequent)

    def do_NetrLogonSamLogonWithFlags(self, c, current, subsequent):
        logon = samlogon_logon_info(self.domain,
                                    self.machine_name,
                                    self.user_creds)

        logon_level = netlogon.NetlogonNetworkTransitiveInformation
        validation_level = netlogon.NetlogonValidationSamInfo4
        netr_flags = 0
        c.netr_LogonSamLogonWithFlags(self.server,
                                      self.user_creds.get_workstation(),
                                      current,
                                      subsequent,
                                      logon_level,
                                      logon,
                                      validation_level,
                                      netr_flags)

    def do_NetrLogonGetDomainInfo(self, c, current, subsequent):
        query = netr_WorkstationInformation()

        c.netr_LogonGetDomainInfo(self.server,
                                  self.user_creds.get_workstation(),
                                  current,
                                  subsequent,
                                  2,
                                  query)

#
# Build the logon data required by NetrLogonSamLogonWithFlags
def samlogon_logon_info(domain_name, computer_name, creds):

    target_info_blob = samlogon_target(domain_name, computer_name)

    challenge = b"abcdefgh"
    # User account under test
    response = creds.get_ntlm_response(flags=CLI_CRED_NTLMv2_AUTH,
                                       challenge=challenge,
                                       target_info=target_info_blob)

    logon = netlogon.netr_NetworkInfo()

    logon.challenge     = [ord(x) for x in challenge]
    logon.nt            = netlogon.netr_ChallengeResponse()
    logon.nt.length     = len(response["nt_response"])
    logon.nt.data       = [ord(x) for x in response["nt_response"]]
    logon.identity_info = netlogon.netr_IdentityInfo()

    (username, domain)  = creds.get_ntlm_username_domain()
    logon.identity_info.domain_name.string  = domain
    logon.identity_info.account_name.string = username
    logon.identity_info.workstation.string  = creds.get_workstation()

    return logon

#
# Build the samlogon target info.
def samlogon_target(domain_name, computer_name):
    target_info = ntlmssp.AV_PAIR_LIST()
    target_info.count = 3
    computername = ntlmssp.AV_PAIR()
    computername.AvId = ntlmssp.MsvAvNbComputerName
    computername.Value = computer_name

    domainname = ntlmssp.AV_PAIR()
    domainname.AvId = ntlmssp.MsvAvNbDomainName
    domainname.Value = domain_name

    eol = ntlmssp.AV_PAIR()
    eol.AvId = ntlmssp.MsvAvEOL
    target_info.pair = [domainname, computername, eol]

    return ndr_pack(target_info)

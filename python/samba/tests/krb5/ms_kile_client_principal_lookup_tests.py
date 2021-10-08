#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2020 Catalyst.Net Ltd
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

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from samba.dsdb import UF_NORMAL_ACCOUNT, UF_DONT_REQUIRE_PREAUTH
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    NT_ENTERPRISE_PRINCIPAL,
    NT_PRINCIPAL,
    NT_SRV_INST,
    KDC_ERR_C_PRINCIPAL_UNKNOWN,
)

global_asn1_print = False
global_hexdump = False


class MS_Kile_Client_Principal_Lookup_Tests(KDCBaseTest):
    ''' Tests for MS-KILE client principal look-up
        See [MS-KILE]: Kerberos Protocol Extensions
            secion 3.3.5.6.1 Client Principal Lookup
    '''

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def check_pac(self, samdb, auth_data, dn, uc, name, upn=None):

        pac_data = self.get_pac_data(auth_data)
        sid = self.get_objectSid(samdb, dn)
        if upn is None:
            upn = "%s@%s" % (name, uc.get_realm().lower())
        if name.endswith('$'):
            name = name[:-1]

        self.assertEqual(
            uc.get_username(),
            str(pac_data.account_name),
            "pac_data = {%s}" % str(pac_data))
        self.assertEqual(
            name,
            pac_data.logon_name,
            "pac_data = {%s}" % str(pac_data))
        self.assertEqual(
            uc.get_realm(),
            pac_data.domain_name,
            "pac_data = {%s}" % str(pac_data))
        self.assertEqual(
            upn,
            pac_data.upn,
            "pac_data = {%s}" % str(pac_data))
        self.assertEqual(
            sid,
            pac_data.account_sid,
            "pac_data = {%s}" % str(pac_data))

    def test_nt_principal_step_1(self):
        ''' Step 1
            For an NT_PRINCIPAL cname with no realm or the realm matches the
            DC's domain
                search for an account with the
                    sAMAccountName matching the cname.
        '''

        # Create user and machine accounts for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the pac, and the ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        self.check_pac(samdb, enc_part['authorization-data'], dn, uc, user_name)
        # check the crealm and cname
        cname = enc_part['cname']
        self.assertEqual(NT_PRINCIPAL, cname['name-type'])
        self.assertEqual(user_name.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), enc_part['crealm'])

    def test_nt_principal_step_2(self):
        ''' Step 2
            If not found
                search for sAMAccountName equal to the cname + "$"

        '''

        # Create a machine account for the test.
        #
        samdb = self.get_samdb()
        mach_name = "mskilemac"
        (mc, dn) = self.create_account(samdb, mach_name,
                                       account_type=self.AccountType.COMPUTER)
        realm = mc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[mach_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(mc, rep)
        key = self.get_as_rep_key(mc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mach_name])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, mc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the pac, and the ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        self.check_pac(samdb, enc_part['authorization-data'], dn, mc, mach_name + '$')
        # check the crealm and cname
        cname = enc_part['cname']
        self.assertEqual(NT_PRINCIPAL, cname['name-type'])
        self.assertEqual(mach_name.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), enc_part['crealm'])

    def test_nt_principal_step_3(self):
        ''' Step 3

            If not found
                search for a matching UPN name where the UPN is set to
                    cname@realm or cname@DC's domain name

        '''
        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        upn_name = "mskileupn"
        upn = upn_name + "@" + self.get_user_creds().get_realm().lower()
        (uc, dn) = self.create_account(samdb, user_name, upn=upn)
        realm = uc.get_realm().lower()

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[upn_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[upn_name])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the service ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        self.check_pac(samdb, enc_part['authorization-data'], dn, uc, upn_name)
        # check the crealm and cname
        cname = enc_part['cname']
        self.assertEqual(NT_PRINCIPAL, cname['name-type'])
        self.assertEqual(upn_name.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), enc_part['crealm'])

    def test_nt_principal_step_4_a(self):
        ''' Step 4, no pre-authentication
            If not found and no pre-authentication
                search for a matching altSecurityIdentity
        '''
        # Create a user account for the test.
        # with an altSecurityIdentity, and with UF_DONT_REQUIRE_PREAUTH
        # set.
        #
        #   note that in this case IDL_DRSCrackNames is called with
        #        pmsgIn.formatOffered set to
        #           DS_USER_PRINCIPAL_NAME_AND_ALTSECID
        #
        # setting UF_DONT_REQUIRE_PREAUTH seems to be the only way
        # to trigger the no pre-auth step

        samdb = self.get_samdb()
        user_name = "mskileusr"
        alt_name = "mskilealtsec"
        (uc, dn) = self.create_account(samdb, user_name,
                                       account_control=UF_DONT_REQUIRE_PREAUTH)
        realm = uc.get_realm().lower()
        alt_sec = "Kerberos:%s@%s" % (alt_name, realm)
        self.add_attribute(samdb, dn, "altSecurityIdentities", alt_sec)

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, as we've set UF_DONT_REQUIRE_PREAUTH
        # we should get a valid AS-RESP
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[alt_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_as_reply(rep)
        salt = "%s%s" % (realm.upper(), user_name)
        key = self.PasswordKey_create(
            rep['enc-part']['etype'],
            uc.get_password(),
            salt.encode('UTF8'),
            rep['enc-part']['kvno'])

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[alt_name])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc, expect_pac=False)
        self.check_tgs_reply(rep)

        # Check the contents of the service ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        #
        # We get an empty authorization-data element in the ticket.
        # i.e. no PAC
        self.assertEqual([], enc_part['authorization-data'])
        # check the crealm and cname
        cname = enc_part['cname']
        self.assertEqual(NT_PRINCIPAL, cname['name-type'])
        self.assertEqual(alt_name.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), enc_part['crealm'])

    def test_nt_principal_step_4_b(self):
        ''' Step 4, pre-authentication
            If not found and pre-authentication
                search for a matching user principal name
        '''

        # Create user and machine accounts for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        alt_name = "mskilealtsec"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()
        alt_sec = "Kerberos:%s@%s" % (alt_name, realm)
        self.add_attribute(samdb, dn, "altSecurityIdentities", alt_sec)

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[alt_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        # Note: although we used the alt security id for the pre-auth
        #       we need to use the username for the auth
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the pac, and the ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        self.check_pac(samdb,
                       enc_part['authorization-data'], dn, uc, user_name)
        # check the crealm and cname
        cname = enc_part['cname']
        self.assertEqual(NT_PRINCIPAL, cname['name-type'])
        self.assertEqual(user_name.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), enc_part['crealm'])

    def test_nt_principal_step_4_c(self):
        ''' Step 4, pre-authentication
            If not found and pre-authentication
                search for a matching user principal name

            This test uses the altsecid, so the AS-REQ should fail.
        '''

        # Create user and machine accounts for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        alt_name = "mskilealtsec"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()
        alt_sec = "Kerberos:%s@%s" % (alt_name, realm)
        self.add_attribute(samdb, dn, "altSecurityIdentities", alt_sec)

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[alt_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        # Use the alternate security identifier
        #     this should fail
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[alt_sec])
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_error_rep(rep, KDC_ERR_C_PRINCIPAL_UNKNOWN)

    def test_enterprise_principal_step_1_3(self):
        ''' Steps 1-3
            For an NT_ENTERPRISE_PRINCIPAL cname
                search for a user principal name matching the cname

        '''

        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        upn_name = "mskileupn"
        upn = upn_name + "@" + self.get_user_creds().get_realm().lower()
        (uc, dn) = self.create_account(samdb, user_name, upn=upn)
        realm = uc.get_realm().lower()

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[upn])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[upn])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the pac, and the ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        self.check_pac(
            samdb, enc_part['authorization-data'], dn, uc, upn, upn=upn)
        # check the crealm and cname
        cname = enc_part['cname']
        crealm = enc_part['crealm']
        self.assertEqual(NT_ENTERPRISE_PRINCIPAL, cname['name-type'])
        self.assertEqual(upn.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), crealm)

    def test_enterprise_principal_step_4(self):
        ''' Step 4

            If that fails
                search for an account where the sAMAccountName matches
                the name before the @

        '''

        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()
        ename = user_name + "@" + realm

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the pac, and the ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        self.check_pac(
            samdb, enc_part['authorization-data'], dn, uc, ename, upn=ename)
        # check the crealm and cname
        cname = enc_part['cname']
        crealm = enc_part['crealm']
        self.assertEqual(NT_ENTERPRISE_PRINCIPAL, cname['name-type'])
        self.assertEqual(ename.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), crealm)

    def test_enterprise_principal_step_5(self):
        ''' Step 5

            If that fails
                search for an account where the sAMAccountName matches
                the name before the @ with a $ appended.

        '''

        # Create a user account for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        (uc, _) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()

        mach_name = "mskilemac"
        (mc, dn) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)
        ename = mach_name + "@" + realm
        uname = mach_name + "$@" + realm

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(mc, rep)
        key = self.get_as_rep_key(mc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the pac, and the ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        self.check_pac(
            samdb, enc_part['authorization-data'], dn, mc, ename, upn=uname)
        # check the crealm and cname
        cname = enc_part['cname']
        crealm = enc_part['crealm']
        self.assertEqual(NT_ENTERPRISE_PRINCIPAL, cname['name-type'])
        self.assertEqual(ename.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), crealm)

    def test_enterprise_principal_step_6_a(self):
        ''' Step 6, no pre-authentication
            If not found and no pre-authentication
                search for a matching altSecurityIdentity
        '''
        # Create a user account for the test.
        # with an altSecurityIdentity, and with UF_DONT_REQUIRE_PREAUTH
        # set.
        #
        #   note that in this case IDL_DRSCrackNames is called with
        #        pmsgIn.formatOffered set to
        #           DS_USER_PRINCIPAL_NAME_AND_ALTSECID
        #
        # setting UF_DONT_REQUIRE_PREAUTH seems to be the only way
        # to trigger the no pre-auth step

        samdb = self.get_samdb()
        user_name = "mskileusr"
        alt_name = "mskilealtsec"
        (uc, dn) = self.create_account(samdb, user_name,
                                       account_control=UF_DONT_REQUIRE_PREAUTH)
        realm = uc.get_realm().lower()
        alt_sec = "Kerberos:%s@%s" % (alt_name, realm)
        self.add_attribute(samdb, dn, "altSecurityIdentities", alt_sec)
        ename = alt_name + "@" + realm

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, as we've set UF_DONT_REQUIRE_PREAUTH
        # we should get a valid AS-RESP
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_as_reply(rep)
        salt = "%s%s" % (realm.upper(), user_name)
        key = self.PasswordKey_create(
            rep['enc-part']['etype'],
            uc.get_password(),
            salt.encode('UTF8'),
            rep['enc-part']['kvno'])

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc, expect_pac=False)
        self.check_tgs_reply(rep)

        # Check the contents of the service ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        #
        # We get an empty authorization-data element in the ticket.
        # i.e. no PAC
        self.assertEqual([], enc_part['authorization-data'])
        # check the crealm and cname
        cname = enc_part['cname']
        self.assertEqual(NT_ENTERPRISE_PRINCIPAL, cname['name-type'])
        self.assertEqual(ename.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), enc_part['crealm'])

    def test_nt_enterprise_principal_step_6_b(self):
        ''' Step 4, pre-authentication
            If not found and pre-authentication
                search for a matching user principal name
        '''

        # Create user and machine accounts for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        alt_name = "mskilealtsec"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()
        alt_sec = "Kerberos:%s@%s" % (alt_name, realm)
        self.add_attribute(samdb, dn, "altSecurityIdentities", alt_sec)
        ename = alt_name + "@" + realm
        uname = user_name + "@" + realm

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        # Note: although we used the alt security id for the pre-auth
        #       we need to use the username for the auth
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[uname])
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL,
            names=[uname])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[mc.get_username()])

        (rep, enc_part) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype,
            service_creds=mc)
        self.check_tgs_reply(rep)

        # Check the contents of the pac, and the ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)
        self.check_pac(
            samdb, enc_part['authorization-data'], dn, uc, uname, upn=uname)
        # check the crealm and cname
        cname = enc_part['cname']
        self.assertEqual(NT_ENTERPRISE_PRINCIPAL, cname['name-type'])
        self.assertEqual(uname.encode('UTF8'), cname['name-string'][0])
        self.assertEqual(realm.upper().encode('UTF8'), enc_part['crealm'])

    def test_nt_principal_step_6_c(self):
        ''' Step 4, pre-authentication
            If not found and pre-authentication
                search for a matching user principal name

            This test uses the altsecid, so the AS-REQ should fail.
        '''

        # Create user and machine accounts for the test.
        #
        samdb = self.get_samdb()
        user_name = "mskileusr"
        alt_name = "mskilealtsec"
        (uc, dn) = self.create_account(samdb, user_name)
        realm = uc.get_realm().lower()
        alt_sec = "Kerberos:%s@%s" % (alt_name, realm)
        self.add_attribute(samdb, dn, "altSecurityIdentities", alt_sec)
        ename = alt_name + "@" + realm

        mach_name = "mskilemac"
        (mc, _) = self.create_account(samdb, mach_name,
                                      account_type=self.AccountType.COMPUTER)

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authentication(rep)

        # Do the next AS-REQ
        padata = self.get_enc_timestamp_pa_data(uc, rep)
        # Use the alternate security identifier
        #     this should fail
        cname = self.PrincipalName_create(
            name_type=NT_ENTERPRISE_PRINCIPAL, names=[ename])
        rep = self.as_req(cname, sname, realm, etype, padata=[padata])
        self.check_error_rep(rep, KDC_ERR_C_PRINCIPAL_UNKNOWN)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()

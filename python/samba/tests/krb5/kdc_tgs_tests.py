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

from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KRB_ERROR,
    KDC_ERR_BADMATCH,
    NT_PRINCIPAL,
    NT_SRV_INST,
)

global_asn1_print = False
global_hexdump = False


class KdcTgsTests(KDCBaseTest):

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_tgs_req_cname_does_not_not_match_authenticator_cname(self):
        ''' Try and obtain a ticket from the TGS, but supply a cname
            that differs from that provided to the krbtgt
        '''
        # Create the user account
        user_name = "tsttktusr"
        (uc, _) = self.create_account(user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96,)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authenication(rep)

        # Do the next AS-REQ
        padata = self.get_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=padata)
        self.check_as_reply(rep)

        # Request a service ticket, but use a cname that does not match
        # that in the original AS-REQ
        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        ticket = rep['ticket']

        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=["Administrator"])
        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=["host", self.dns_host_name])

        (rep, enc_part) = self.tgs_req(cname, sname, realm, ticket, key, etype)

        self.assertIsNone(
            enc_part,
            "rep = {%s}, enc_part = {%s}" % (rep, enc_part))
        self.assertEqual(KRB_ERROR, rep['msg-type'], "rep = {%s}" % rep)
        self.assertEqual(
            KDC_ERR_BADMATCH,
            rep['error-code'],
            "rep = {%s}" % rep)

    def test_ldap_service_ticket(self):
        '''Get a ticket to the ldap service
        '''
        # Create the user account
        user_name = "tsttktusr"
        (uc, _) = self.create_account(user_name)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96,)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authenication(rep)

        # Do the next AS-REQ
        padata = self.get_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=padata)
        self.check_as_reply(rep)

        enc_part2 = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part2['key'])
        ticket = rep['ticket']

        # Request a ticket to the ldap service
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST,
            names=["ldap", self.dns_host_name])

        (rep, _) = self.tgs_req(
            cname, sname, uc.get_realm(), ticket, key, etype)

        self.check_tgs_reply(rep)

    def test_get_ticket_for_host_service_of_machine_account(self):

        # Create a user and machine account for the test.
        #
        user_name = "tsttktusr"
        (uc, dn) = self.create_account(user_name)
        (mc, _) = self.create_account("tsttktmac", machine_account=True)
        realm = uc.get_realm().lower()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[user_name])
        sname = self.PrincipalName_create(
            name_type=NT_SRV_INST, names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authenication(rep)

        # Do the next AS-REQ
        padata = self.get_pa_data(uc, rep)
        key = self.get_as_rep_key(uc, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=padata)
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
            cname, sname, uc.get_realm(), ticket, key, etype)
        self.check_tgs_reply(rep)

        # Check the contents of the service ticket
        ticket = rep['ticket']
        enc_part = self.decode_service_ticket(mc, ticket)

        pac_data = self.get_pac_data(enc_part['authorization-data'])
        sid = self.get_objectSid(dn)
        upn = "%s@%s" % (uc.get_username(), realm)
        self.assertEqual(
            uc.get_username(),
            str(pac_data.account_name),
            "rep = {%s},%s" % (rep, pac_data))
        self.assertEqual(
            uc.get_username(),
            pac_data.logon_name,
            "rep = {%s},%s" % (rep, pac_data))
        self.assertEqual(
            uc.get_realm(),
            pac_data.domain_name,
            "rep = {%s},%s" % (rep, pac_data))
        self.assertEqual(
            upn,
            pac_data.upn,
            "rep = {%s},%s" % (rep, pac_data))
        self.assertEqual(
            sid,
            pac_data.account_sid,
            "rep = {%s},%s" % (rep, pac_data))


if __name__ == "__main__":
    global_asn1_print = True
    global_hexdump = True
    import unittest
    unittest.main()

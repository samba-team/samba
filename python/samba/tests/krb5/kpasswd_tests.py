#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) Catalyst.Net Ltd
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

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

from functools import partial

from samba import generate_random_password
from samba.dcerpc import krb5pac, security
from samba.sd_utils import SDUtils

from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.rfc4120_constants import (
    KDC_ERR_TGT_REVOKED,
    KDC_ERR_TKT_EXPIRED,
    KPASSWD_ACCESSDENIED,
    KPASSWD_AUTHERROR,
    KPASSWD_HARDERROR,
    KPASSWD_INITIAL_FLAG_NEEDED,
    KPASSWD_MALFORMED,
    KPASSWD_SOFTERROR,
    KPASSWD_SUCCESS,
    NT_PRINCIPAL,
    NT_SRV_INST,
)

global_asn1_print = False
global_hexdump = False


# Note: these tests do not pass on Windows, which returns different error codes
# to the ones we have chosen, and does not always return additional error data.
class KpasswdTests(KDCBaseTest):

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

        samdb = self.get_samdb()

        # Get the old 'dSHeuristics' if it was set
        dsheuristics = samdb.get_dsheuristics()

        # Reset the 'dSHeuristics' as they were before
        self.addCleanup(samdb.set_dsheuristics, dsheuristics)

        # Set the 'dSHeuristics' to activate the correct 'userPassword'
        # behaviour
        samdb.set_dsheuristics('000000001')

        # Get the old 'minPwdAge'
        minPwdAge = samdb.get_minPwdAge()

        # Reset the 'minPwdAge' as it was before
        self.addCleanup(samdb.set_minPwdAge, minPwdAge)

        # Set it temporarily to '0'
        samdb.set_minPwdAge('0')

    def _get_creds(self, expired=False):
        opts = {
            'expired_password': expired
        }

        # Create the account.
        creds = self.get_cached_creds(account_type=self.AccountType.USER,
                                      opts=opts,
                                      use_cache=False)

        return creds

    def get_kpasswd_sname(self):
        return self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                         names=['kadmin', 'changepw'])

    def get_ticket_lifetime(self, ticket):
        enc_part = ticket.ticket_private

        authtime = enc_part['authtime']
        starttime = enc_part.get('starttime', authtime)
        endtime = enc_part['endtime']

        starttime = self.get_EpochFromKerberosTime(starttime)
        endtime = self.get_EpochFromKerberosTime(endtime)

        return endtime - starttime

    # Test setting a password with kpasswd.
    def test_kpasswd_set(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        # Test the newly set password.
        creds.update_password(new_password)
        self.get_tgt(creds, fresh=True)

    # Test changing a password with kpasswd.
    def test_kpasswd_change(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

        # Test the newly set password.
        creds.update_password(new_password)
        self.get_tgt(creds, fresh=True)

    # Test kpasswd without setting the canonicalize option.
    def test_kpasswd_no_canonicalize(self):
        # Create an account for testing.
        creds = self._get_creds()

        sname = self.get_kpasswd_sname()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=sname,
                              kdc_options='0')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        creds.update_password(new_password)

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=sname,
                              kdc_options='0')

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test kpasswd with the canonicalize option reset and a non-canonical
    # (by conversion to title case) realm.
    def test_kpasswd_no_canonicalize_realm_case(self):
        # Create an account for testing.
        creds = self._get_creds()

        sname = self.get_kpasswd_sname()
        realm = creds.get_realm().capitalize()  # We use a title-cased realm.

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=sname,
                              realm=realm,
                              kdc_options='0')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        creds.update_password(new_password)

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=sname,
                              realm=realm,
                              kdc_options='0')

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test kpasswd with the canonicalize option set.
    def test_kpasswd_canonicalize(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd. We set the canonicalize flag here.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='canonicalize')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        creds.update_password(new_password)

        # Get an initial ticket to kpasswd. We set the canonicalize flag here.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='canonicalize')

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test kpasswd with the canonicalize option set and a non-canonical (by
    # conversion to title case) realm.
    def test_kpasswd_canonicalize_realm_case(self):
        # Create an account for testing.
        creds = self._get_creds()

        sname = self.get_kpasswd_sname()
        realm = creds.get_realm().capitalize()  # We use a title-cased realm.

        # Get an initial ticket to kpasswd. We set the canonicalize flag here.
        ticket = self.get_tgt(creds, sname=sname,
                              realm=realm,
                              kdc_options='canonicalize')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        creds.update_password(new_password)

        # Get an initial ticket to kpasswd. We set the canonicalize flag here.
        ticket = self.get_tgt(creds, sname=sname,
                              realm=realm,
                              kdc_options='canonicalize')

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test kpasswd rejects a password that does not meet complexity
    # requirements.
    def test_kpasswd_too_weak(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_SOFTERROR
        expected_msg = b'Password does not meet complexity requirements'

        # Set the password.
        new_password = 'password'
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        # Change the password.
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test kpasswd rejects an empty new password.
    def test_kpasswd_empty(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_SOFTERROR, KPASSWD_HARDERROR
        expected_msg = (b'Password too short, password must be at least 7 '
                        b'characters long.',
                        b'String conversion failed!')

        # Set the password.
        new_password = ''
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        expected_code = KPASSWD_HARDERROR
        expected_msg = b'String conversion failed!'

        # Change the password.
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test kpasswd rejects a request that does not include a random sequence
    # number.
    def test_kpasswd_no_seq_number(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_HARDERROR
        expected_msg = b'gensec_unwrap failed - NT_STATUS_ACCESS_DENIED\n'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET,
                              send_seq_number=False)

        # Change the password.
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE,
                              send_seq_number=False)

    # Test kpasswd rejects a ticket issued by an RODC.
    def test_kpasswd_from_rodc(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        # Have the ticket be issued by the RODC.
        ticket = self.issued_by_rodc(ticket)

        expected_code = KPASSWD_HARDERROR
        expected_msg = b'gensec_update failed - NT_STATUS_LOGON_FAILURE\n'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        # Change the password.
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test setting a password, specifying the principal of the target user.
    def test_kpasswd_set_target_princ_only(self):
        # Create an account for testing.
        creds = self._get_creds()
        username = creds.get_username()

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=username.split('/'))

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_MALFORMED
        expected_msg = (b'Realm and principal must be both present, or '
                        b'neither present',
                        b'Failed to decode packet')

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET,
                              target_princ=cname)

    # Test that kpasswd rejects a password set specifying only the realm of the
    # target user.
    def test_kpasswd_set_target_realm_only(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_MALFORMED, KPASSWD_ACCESSDENIED
        expected_msg = (b'Realm and principal must be both present, or '
                        b'neither present',
                        b'Failed to decode packet',
                        b'No such user when changing password')

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET,
                              target_realm=creds.get_realm())

    # Show that a user cannot set a password, specifying both principal and
    # realm of the target user, without having control access.
    def test_kpasswd_set_target_princ_and_realm_no_access(self):
        # Create an account for testing.
        creds = self._get_creds()
        username = creds.get_username()

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=username.split('/'))

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_ACCESSDENIED
        expected_msg = b'Not permitted to change password'

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET,
                              target_princ=cname,
                              target_realm=creds.get_realm())

    # Test setting a password, specifying both principal and realm of the
    # target user, whem the user has control access on their account.
    def test_kpasswd_set_target_princ_and_realm_access(self):
        # Create an account for testing.
        creds = self._get_creds()
        username = creds.get_username()
        tgt = self.get_tgt(creds)

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=username.split('/'))

        samdb = self.get_samdb()
        sd_utils = SDUtils(samdb)

        user_dn = creds.get_dn()
        user_sid = self.get_objectSid(samdb, user_dn)

        # Give the user control access on their account.
        ace = f'(A;;CR;;;{user_sid})'
        sd_utils.dacl_add_ace(user_dn, ace)

        # Get a non-initial ticket to kpasswd. Since we have the right to
        # change the account's password, we don't need an initial ticket.
        krbtgt_creds = self.get_krbtgt_creds()
        ticket = self.get_service_ticket(tgt,
                                         krbtgt_creds,
                                         service='kadmin',
                                         target_name='changepw',
                                         kdc_options='0')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET,
                              target_princ=cname,
                              target_realm=creds.get_realm())

    # Test setting a password when the existing password has expired.
    def test_kpasswd_set_expired_password(self):
        # Create an account for testing, with an expired password.
        creds = self._get_creds(expired=True)

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

    # Test changing a password when the existing password has expired.
    def test_kpasswd_change_expired_password(self):
        # Create an account for testing, with an expired password.
        creds = self._get_creds(expired=True)

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Check the lifetime of a kpasswd ticket is not more than two minutes.
    def test_kpasswd_ticket_lifetime(self):
        # Create an account for testing.
        creds = self._get_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        # Check the lifetime of the ticket is equal to two minutes.
        lifetime = self.get_ticket_lifetime(ticket)
        self.assertEqual(2 * 60, lifetime)

    # Ensure we cannot perform a TGS-REQ with a kpasswd ticket.
    def test_kpasswd_ticket_tgs(self):
        creds = self.get_client_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        # Change the sname of the ticket to match that of a TGT.
        realm = creds.get_realm()
        krbtgt_sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                                 names=['krbtgt', realm])
        ticket.set_sname(krbtgt_sname)

        # Try to use that ticket to get a service ticket.
        service_creds = self.get_service_creds()

        # This fails due to missing REQUESTER_SID buffer.
        self._make_tgs_request(creds, service_creds, ticket,
                               expect_error=(KDC_ERR_TGT_REVOKED,
                                             KDC_ERR_TKT_EXPIRED))

    # Ensure we cannot perform a TGS-REQ with a kpasswd ticket containing a
    # requester SID and having a remaining lifetime of two minutes.
    def test_kpasswd_ticket_requester_sid_tgs(self):
        creds = self.get_client_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        # Change the sname of the ticket to match that of a TGT.
        realm = creds.get_realm()
        krbtgt_sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                                 names=['krbtgt', realm])
        ticket.set_sname(krbtgt_sname)

        # Get the user's SID.
        samdb = self.get_samdb()

        user_dn = creds.get_dn()
        user_sid = self.get_objectSid(samdb, user_dn)

        # Modify the ticket to add a requester SID and give it two minutes to
        # live.
        ticket = self.modify_requester_sid_time(ticket,
                                                lifetime=2 * 60,
                                                requester_sid=user_sid)

        # Try to use that ticket to get a service ticket.
        service_creds = self.get_service_creds()

        # This fails due to the lifetime being too short.
        self._make_tgs_request(creds, service_creds, ticket,
                               expect_error=KDC_ERR_TKT_EXPIRED)

    # Show we can perform a TGS-REQ with a kpasswd ticket containing a
    # requester SID if the remaining lifetime exceeds two minutes.
    def test_kpasswd_ticket_requester_sid_lifetime_tgs(self):
        creds = self.get_client_creds()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=self.get_kpasswd_sname(),
                              kdc_options='0')

        # Change the sname of the ticket to match that of a TGT.
        realm = creds.get_realm()
        krbtgt_sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                                 names=['krbtgt', realm])
        ticket.set_sname(krbtgt_sname)

        # Get the user's SID.
        samdb = self.get_samdb()

        user_dn = creds.get_dn()
        user_sid = self.get_objectSid(samdb, user_dn)

        # Modify the ticket to add a requester SID and give it two minutes and
        # ten seconds to live.
        ticket = self.modify_requester_sid_time(ticket,
                                                lifetime=2 * 60 + 10,
                                                requester_sid=user_sid)

        # Try to use that ticket to get a service ticket.
        service_creds = self.get_service_creds()

        # This succeeds.
        self._make_tgs_request(creds, service_creds, ticket,
                               expect_error=False)

    # Show that we cannot provide a TGT to kpasswd to change the password.
    def test_kpasswd_tgt(self):
        # Create an account for testing, and get a TGT.
        creds = self._get_creds()
        tgt = self.get_tgt(creds)

        # Change the sname of the ticket to match that of kadmin/changepw.
        tgt.set_sname(self.get_kpasswd_sname())

        expected_code = KPASSWD_AUTHERROR
        expected_msg = b'A TGT may not be used as a ticket to kpasswd'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(tgt,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        # Change the password.
        self.kpasswd_exchange(tgt,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test that kpasswd rejects requests with a service ticket.
    def test_kpasswd_non_initial(self):
        # Create an account for testing, and get a TGT.
        creds = self._get_creds()
        tgt = self.get_tgt(creds)

        # Get a non-initial ticket to kpasswd.
        krbtgt_creds = self.get_krbtgt_creds()
        ticket = self.get_service_ticket(tgt,
                                         krbtgt_creds,
                                         service='kadmin',
                                         target_name='changepw',
                                         kdc_options='0')

        expected_code = KPASSWD_INITIAL_FLAG_NEEDED
        expected_msg = b'Expected an initial ticket'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        # Change the password.
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Show that kpasswd accepts requests with a service ticket modified to set
    # the 'initial' flag.
    def test_kpasswd_initial(self):
        # Create an account for testing, and get a TGT.
        creds = self._get_creds()

        krbtgt_creds = self.get_krbtgt_creds()

        # Get a service ticket, and modify it to set the 'initial' flag.
        def get_ticket():
            tgt = self.get_tgt(creds, fresh=True)

            # Get a non-initial ticket to kpasswd.
            ticket = self.get_service_ticket(tgt,
                                             krbtgt_creds,
                                             service='kadmin',
                                             target_name='changepw',
                                             kdc_options='0',
                                             fresh=True)

            set_initial_flag = partial(self.modify_ticket_flag, flag='initial',
                                       value=True)

            checksum_keys = self.get_krbtgt_checksum_key()
            return self.modified_ticket(ticket,
                                        modify_fn=set_initial_flag,
                                        checksum_keys=checksum_keys)

        expected_code = KPASSWD_SUCCESS
        expected_msg = b'Password changed'

        ticket = get_ticket()

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        creds.update_password(new_password)
        ticket = get_ticket()

        # Change the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test that kpasswd rejects requests where the ticket is encrypted with a
    # key other than the krbtgt's.
    def test_kpasswd_wrong_key(self):
        # Create an account for testing.
        creds = self._get_creds()

        sname = self.get_kpasswd_sname()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=sname,
                              kdc_options='0')

        # Get a key belonging to the Administrator account.
        admin_creds = self.get_admin_creds()
        admin_key = self.TicketDecryptionKey_from_creds(admin_creds)
        self.assertIsNotNone(admin_key.kvno,
                             'a kvno is required to tell the DB '
                             'which key to look up.')
        checksum_keys = {
            krb5pac.PAC_TYPE_KDC_CHECKSUM: admin_key,
        }

        # Re-encrypt the ticket using the Administrator's key.
        ticket = self.modified_ticket(ticket,
                                      new_ticket_key=admin_key,
                                      checksum_keys=checksum_keys)

        # Set the sname of the ticket to that of the Administrator account.
        admin_sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                                names=['Administrator'])
        ticket.set_sname(admin_sname)

        expected_code = KPASSWD_HARDERROR
        expected_msg = b'gensec_update failed - NT_STATUS_LOGON_FAILURE\n'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        # Change the password.
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    def test_kpasswd_wrong_key_service(self):
        # Create an account for testing.
        creds = self.get_cached_creds(account_type=self.AccountType.COMPUTER,
                                      use_cache=False)

        sname = self.get_kpasswd_sname()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=sname,
                              kdc_options='0')

        # Get a key belonging to our account.
        our_key = self.TicketDecryptionKey_from_creds(creds)
        self.assertIsNotNone(our_key.kvno,
                             'a kvno is required to tell the DB '
                             'which key to look up.')
        checksum_keys = {
            krb5pac.PAC_TYPE_KDC_CHECKSUM: our_key,
        }

        # Re-encrypt the ticket using our key.
        ticket = self.modified_ticket(ticket,
                                      new_ticket_key=our_key,
                                      checksum_keys=checksum_keys)

        # Set the sname of the ticket to that of our account.
        username = creds.get_username()
        sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=username.split('/'))
        ticket.set_sname(sname)

        expected_code = KPASSWD_HARDERROR
        expected_msg = b'gensec_update failed - NT_STATUS_LOGON_FAILURE\n'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        # Change the password.
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)

    # Test that kpasswd rejects requests where the ticket is encrypted with a
    # key belonging to a server account other than the krbtgt.
    def test_kpasswd_wrong_key_server(self):
        # Create an account for testing.
        creds = self._get_creds()

        sname = self.get_kpasswd_sname()

        # Get an initial ticket to kpasswd.
        ticket = self.get_tgt(creds, sname=sname,
                              kdc_options='0')

        # Get a key belonging to the DC's account.
        dc_creds = self.get_dc_creds()
        dc_key = self.TicketDecryptionKey_from_creds(dc_creds)
        self.assertIsNotNone(dc_key.kvno,
                             'a kvno is required to tell the DB '
                             'which key to look up.')
        checksum_keys = {
            krb5pac.PAC_TYPE_KDC_CHECKSUM: dc_key,
        }

        # Re-encrypt the ticket using the DC's key.
        ticket = self.modified_ticket(ticket,
                                      new_ticket_key=dc_key,
                                      checksum_keys=checksum_keys)

        # Set the sname of the ticket to that of the DC's account.
        dc_username = dc_creds.get_username()
        dc_sname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                             names=dc_username.split('/'))
        ticket.set_sname(dc_sname)

        expected_code = KPASSWD_HARDERROR
        expected_msg = b'gensec_update failed - NT_STATUS_LOGON_FAILURE\n'

        # Set the password.
        new_password = generate_random_password(32, 32)
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.SET)

        # Change the password.
        self.kpasswd_exchange(ticket,
                              new_password,
                              expected_code,
                              expected_msg,
                              mode=self.KpasswdMode.CHANGE)


if __name__ == '__main__':
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()

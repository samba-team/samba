#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
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

from samba.tests.krb5.kdc_base_test import KDCBaseTest

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

global_asn1_print = False
global_hexdump = False


class RodcKerberosTests(KDCBaseTest):

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    # Ensure that an RODC correctly issues tickets signed with its krbtgt key
    # and including the RODCIdentifier.
    def test_rodc_ticket_signature(self):
        user_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={
                'allowed_replication': True,
                'revealed_to_rodc': True
            })
        target_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={
                'allowed_replication': True,
                'revealed_to_rodc': True
            })

        krbtgt_creds = self.get_rodc_krbtgt_creds()
        rodc_key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        # Get a TGT from the RODC.
        tgt = self.get_tgt(user_creds, to_rodc=True)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(tgt, rodc_key)

        # Get a service ticket from the RODC.
        service_ticket = self.get_service_ticket(tgt, target_creds,
                                                 to_rodc=True)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(service_ticket, rodc_key)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()

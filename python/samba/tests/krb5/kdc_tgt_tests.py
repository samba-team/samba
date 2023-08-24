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

global_asn1_print = False
global_hexdump = False


class KdcTgtTests(KDCBaseTest):
    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def test_ticket_signature(self):
        # Ensure that a DC correctly issues tickets signed with its krbtgt key.
        user_creds = self.get_client_creds()
        target_creds = self.get_service_creds()

        krbtgt_creds = self.get_krbtgt_creds()
        key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        # Get a TGT from the DC.
        tgt = self.get_tgt(user_creds)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(tgt, key, service_ticket=False)

        # Get a service ticket from the DC.
        service_ticket = self.get_service_ticket(tgt, target_creds)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(service_ticket, key, service_ticket=True,
                           expect_ticket_checksum=True)

    def test_full_signature(self):
        # Ensure that a DC correctly issues tickets signed with its krbtgt key.
        user_creds = self.get_client_creds()
        target_creds = self.get_service_creds()

        krbtgt_creds = self.get_krbtgt_creds()
        key = self.TicketDecryptionKey_from_creds(krbtgt_creds)

        # Get a TGT from the DC.
        tgt = self.get_tgt(user_creds)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(tgt, key, service_ticket=False)

        # Get a service ticket from the DC.
        service_ticket = self.get_service_ticket(tgt, target_creds)

        # Ensure the PAC contains the expected checksums.
        self.verify_ticket(service_ticket, key, service_ticket=True,
                           expect_ticket_checksum=True,
                           expect_full_checksum=True)


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()

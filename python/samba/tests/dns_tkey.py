# Unix SMB/CIFS implementation.
# Copyright (C) Kai Blin  <kai@samba.org> 2011
# Copyright (C) Ralph Boehme  <slow@samba.org> 2016
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
import optparse
import samba.getopt as options
import samba.ndr as ndr
from samba.dcerpc import dns
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.tests.dns_base import DNSTKeyTest

parser = optparse.OptionParser("dns_tkey.py <server name> <server ip> [options]")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)

# This timeout only has relevance when testing against Windows
# Format errors tend to return patchy responses, so a timeout is needed.
parser.add_option("--timeout", type="int", dest="timeout",
                  help="Specify timeout for DNS requests")

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()
timeout = opts.timeout

if len(args) < 2:
    parser.print_usage()
    sys.exit(1)

server_name = args[0]
server_ip = args[1]


class TestDNSUpdates(DNSTKeyTest):
    def setUp(self):
        self.server = server_name
        self.server_ip = server_ip
        super().setUp()

    def test_tkey_gss_tsig(self):
        "test DNS TKEY handshake with gss-tsig"

        self.tkey_trans()

    def test_tkey_gss_microsoft_com(self):
        "test DNS TKEY handshake with gss.microsoft.com"

        self.tkey_trans(algorithm_name="gss.microsoft.com")

    def test_tkey_invalid_gss_TSIG(self):
        "test DNS TKEY handshake with invalid gss-TSIG"

        self.tkey_trans(algorithm_name="gss-TSIG",
                        expected_rcode=dns.DNS_RCODE_REFUSED)

    def test_tkey_invalid_gss_MICROSOFT_com(self):
        "test DNS TKEY handshake with invalid gss.MICROSOFT.com"

        self.tkey_trans(algorithm_name="gss.MICROSOFT.com",
                        expected_rcode=dns.DNS_RCODE_REFUSED)

    def test_update_wo_tsig(self):
        "test DNS update without TSIG record"

        p = self.make_update_request()
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_echoed_dns_error(p, response, response_p, dns.DNS_RCODE_REFUSED)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_bad_keyname(self):
        "test DNS update with a TSIG record with a bad keyname"

        self.tkey_trans()

        p = self.make_update_request()
        self.sign_packet(p, "badkey")
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_echoed_dns_error(p, response, response_p, dns.DNS_RCODE_REFUSED)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_bad_mac(self):
        "test DNS update with a TSIG record with a bad MAC"

        self.tkey_trans()

        p = self.make_update_request()
        self.bad_sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_echoed_dns_error(p, response, response_p, dns.DNS_RCODE_REFUSED)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_bad_algorithm(self):
        "test DNS update with a TSIG record with a bad algorithm"

        self.tkey_trans()

        algorithm_name = "gss-TSIG"
        p = self.make_update_request()
        mac = self.sign_packet(p, self.tkey['name'],
                               algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_echoed_dns_error(p, response, response_p, dns.DNS_RCODE_REFUSED)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_changed_algorithm1(self):
        "test DNS update with a TSIG record with a changed algorithm"

        algorithm_name = "gss-tsig"
        self.tkey_trans(algorithm_name=algorithm_name)

        # Now delete the record, it's most likely
        # a no-op as it should not be there if the test
        # runs the first time
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'], algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Now do an update with the algorithm_name
        # changed in the requests TSIG message.
        p = self.make_update_request()
        algorithm_name = "gss.microsoft.com"
        mac = self.sign_packet(p, self.tkey['name'],
                               algorithm_name=algorithm_name)
        algorithm_name = "gss-tsig"
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip,
                                                          allow_remaining=True)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record, with the original
        # algorithm_name used in the tkey exchange
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'], algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_changed_algorithm2(self):
        "test DNS update with a TSIG record with a changed algorithm"

        algorithm_name = "gss.microsoft.com"
        self.tkey_trans(algorithm_name=algorithm_name)

        # Now delete the record, it's most likely
        # a no-op as it should not be there if the test
        # runs the first time
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'], algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Now do an update with the algorithm_name
        # changed in the requests TSIG message.
        p = self.make_update_request()
        algorithm_name = "gss-tsig"
        mac = self.sign_packet(p, self.tkey['name'],
                               algorithm_name=algorithm_name)
        algorithm_name = "gss.microsoft.com"
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip,
                                                          allow_truncated=True)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        response_p_pack = ndr.ndr_pack(response)
        if len(response_p_pack) == len(response_p):
            self.verify_packet(response, response_p, mac)
        else:
            pass # Windows bug

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record, with the original
        # algorithm_name used in the tkey exchange
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'], algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_gss_tsig_tkey_req_additional(self):
        "test DNS update with correct gss-tsig record tkey req in additional"

        self.tkey_trans()

        p = self.make_update_request()
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # check it's gone
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_gss_tsig_tkey_req_answers(self):
        "test DNS update with correct gss-tsig record tsig req in answers"

        self.tkey_trans(tkey_req_in_answers=True)

        p = self.make_update_request()
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # check it's gone
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_gss_microsoft_com_tkey_req_additional(self):
        "test DNS update with correct gss.microsoft.com record tsig req in additional"

        algorithm_name = "gss.microsoft.com"
        self.tkey_trans(algorithm_name=algorithm_name)

        p = self.make_update_request()
        mac = self.sign_packet(p, self.tkey['name'],
                               algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'],
                               algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # check it's gone
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_gss_microsoft_com_tkey_req_answers(self):
        "test DNS update with correct gss.microsoft.com record tsig req in answers"

        algorithm_name = "gss.microsoft.com"
        self.tkey_trans(algorithm_name=algorithm_name,
                        tkey_req_in_answers=True)

        p = self.make_update_request()
        mac = self.sign_packet(p, self.tkey['name'],
                               algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'],
                               algorithm_name=algorithm_name)
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # check it's gone
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_windows(self):
        "test DNS update with correct TSIG record (follow Windows pattern)"

        p = self.make_update_request()

        rr_class = dns.DNS_QCLASS_IN
        ttl = 1200

        updates = []
        r = dns.res_rec()
        r.name = self.newrecname
        r.rr_type = dns.DNS_QTYPE_A
        r.rr_class = dns.DNS_QCLASS_ANY
        r.ttl = 0
        r.length = 0
        updates.append(r)
        r = dns.res_rec()
        r.name = self.newrecname
        r.rr_type = dns.DNS_QTYPE_AAAA
        r.rr_class = dns.DNS_QCLASS_ANY
        r.ttl = 0
        r.length = 0
        updates.append(r)
        r = dns.res_rec()
        r.name = self.newrecname
        r.rr_type = dns.DNS_QTYPE_A
        r.rr_class = rr_class
        r.ttl = ttl
        r.length = 0xffff
        r.rdata = "10.1.45.64"
        updates.append(r)
        p.nscount = len(updates)
        p.nsrecs = updates

        prereqs = []
        r = dns.res_rec()
        r.name = self.newrecname
        r.rr_type = dns.DNS_QTYPE_CNAME
        r.rr_class = dns.DNS_QCLASS_NONE
        r.ttl = 0
        r.length = 0
        prereqs.append(r)
        p.ancount = len(prereqs)
        p.answers = prereqs

        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_echoed_dns_error(p, response, response_p, dns.DNS_RCODE_REFUSED)

        self.tkey_trans()
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record
        delete_updates = []
        r = dns.res_rec()
        r.name = self.newrecname
        r.rr_type = dns.DNS_QTYPE_A
        r.rr_class = dns.DNS_QCLASS_NONE
        r.ttl = 0
        r.length = 0xffff
        r.rdata = "10.1.45.64"
        delete_updates.append(r)
        p = self.make_update_request(delete=True)
        p.nscount = len(delete_updates)
        p.nsrecs = delete_updates
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # check it's gone
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)

    def test_update_tsig_record_access_denied(self):
        """test DNS update with a TSIG record where the user does not have
        permissions to change the record"""

        self.tkey_trans()
        adm_tkey = self.tkey

        # First create the record as admin
        p = self.make_update_request()
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now update the same values as normal user
        # should work without error
        self.tkey_trans(creds=self.get_unpriv_creds())
        unpriv_tkey = self.tkey

        p = self.make_update_request()
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # Check the record is still around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now try to delete the record a normal user (should fail)
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_echoed_dns_error(p, response, response_p, dns.DNS_RCODE_REFUSED)

        # Check the record is still around
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_OK)

        # Now delete the record as admin
        self.tkey = adm_tkey
        p = self.make_update_request(delete=True)
        mac = self.sign_packet(p, self.tkey['name'])
        (response, response_p) = self.dns_transaction_udp(p, self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.verify_packet(response, response_p, mac)

        # check it's gone
        rcode = self.search_record(self.newrecname)
        self.assert_rcode_equals(rcode, dns.DNS_RCODE_NXDOMAIN)


TestProgram(module=__name__, opts=subunitopts)

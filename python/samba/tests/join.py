# Test joining as a DC and check the join was done right
#
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

import samba
import sys
import shutil
import os
from samba.tests.dns_base import DNSTest
from samba.join import dc_join
from samba.dcerpc import drsuapi, misc, dns

def get_logger(name="subunit"):
    """Get a logger object."""
    import logging
    logger = logging.getLogger(name)
    logger.addHandler(logging.StreamHandler(sys.stderr))
    return logger

class JoinTestCase(DNSTest):
    def setUp(self):
        super(JoinTestCase, self).setUp()
        self.server = samba.tests.env_get_var_value("SERVER")
        self.server_ip = samba.tests.env_get_var_value("SERVER_IP")
        self.lp = samba.tests.env_loadparm()
        self.creds = self.get_credentials()
        self.netbios_name = "jointest1"
        logger = get_logger()

        self.join_ctx = dc_join(server=self.server, creds=self.creds, lp=self.get_loadparm(),
                                netbios_name=self.netbios_name,
                                targetdir=self.tempdir,
                                domain=None, logger=logger,
                                dns_backend="SAMBA_INTERNAL")
        self.join_ctx.userAccountControl = (samba.dsdb.UF_SERVER_TRUST_ACCOUNT |
                                            samba.dsdb.UF_TRUSTED_FOR_DELEGATION)

        self.join_ctx.replica_flags |= (drsuapi.DRSUAPI_DRS_WRIT_REP |
                                        drsuapi.DRSUAPI_DRS_FULL_SYNC_IN_PROGRESS)
        self.join_ctx.domain_replica_flags = self.join_ctx.replica_flags
        self.join_ctx.secure_channel_type = misc.SEC_CHAN_BDC

        self.join_ctx.cleanup_old_join()

        self.join_ctx.force_all_ips = True

    def tearDown(self):
        try:
            paths = self.join_ctx.paths
        except AttributeError:
            paths = None

        if paths is not None:
            shutil.rmtree(paths.private_dir)
            shutil.rmtree(paths.state_dir)
            shutil.rmtree(os.path.join(self.tempdir, "etc"))
            shutil.rmtree(os.path.join(self.tempdir, "msg.lock"))
            os.unlink(os.path.join(self.tempdir, "names.tdb"))

        self.join_ctx.cleanup_old_join(force=True)

        super(JoinTestCase, self).tearDown()


    def test_join(self):

        self.join_ctx.do_join()

        "create a query packet containing one query record via TCP"
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        questions = []

        name = self.join_ctx.dnshostname
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        questions.append(q)

        # Get expected IPs
        IPs = samba.interface_ips(self.lp)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_tcp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)
        self.assertEquals(response.ancount, len(IPs))

        questions = []
        name = "%s._msdcs.%s" % (self.join_ctx.ntds_guid, self.join_ctx.dnsforest)
        q = self.make_name_question(name, dns.DNS_QTYPE_A, dns.DNS_QCLASS_IN)
        questions.append(q)

        self.finish_name_packet(p, questions)
        (response, response_packet) = self.dns_transaction_tcp(p, host=self.server_ip)
        self.assert_dns_rcode_equals(response, dns.DNS_RCODE_OK)
        self.assert_dns_opcode_equals(response, dns.DNS_OPCODE_QUERY)

        self.assertEquals(response.ancount, 1 + len(IPs))
        self.assertEquals(response.answers[0].rr_type, dns.DNS_QTYPE_CNAME)
        self.assertEquals(response.answers[0].rdata, self.join_ctx.dnshostname)
        self.assertEquals(response.answers[1].rr_type, dns.DNS_QTYPE_A)

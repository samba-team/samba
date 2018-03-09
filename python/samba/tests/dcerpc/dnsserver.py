# Unix SMB/CIFS implementation.
# Copyright (C) Amitay Isaacs <amitay@gmail.com> 2011
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
"""Tests for samba.dcerpc.dnsserver"""

import os
import ldb

from samba.auth import system_session
from samba.samdb import SamDB
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import dnsp, dnsserver, security
from samba.tests import RpcInterfaceTestCase, env_get_var_value
from samba.netcmd.dns import ARecord, AAAARecord, PTRRecord, CNameRecord, NSRecord, MXRecord, SRVRecord, TXTRecord
from samba import sd_utils, descriptor

class DnsserverTests(RpcInterfaceTestCase):

    @classmethod
    def setUpClass(cls):
        good_dns = ["SAMDOM.EXAMPLE.COM",
                    "1.EXAMPLE.COM",
                    "%sEXAMPLE.COM" % ("1."*100),
                    "EXAMPLE",
                    "\n.COM",
                    "!@#$%^&*()_",
                    "HIGH\xFFBYTE",
                    "@.EXAMPLE.COM",
                    "."]
        bad_dns = ["...",
                   ".EXAMPLE.COM",
                   ".EXAMPLE.",
                   "",
                   "SAMDOM..EXAMPLE.COM"]

        good_mx = ["SAMDOM.EXAMPLE.COM 65535"]
        bad_mx = []

        good_srv = ["SAMDOM.EXAMPLE.COM 65535 65535 65535"]
        bad_srv = []

        for bad_dn in bad_dns:
            bad_mx.append("%s 1" % bad_dn)
            bad_srv.append("%s 0 0 0" % bad_dn)
        for good_dn in good_dns:
            good_mx.append("%s 1" % good_dn)
            good_srv.append("%s 0 0 0" % good_dn)

        cls.good_records = {
            "A": ["192.168.0.1",
                  "255.255.255.255"],
            "AAAA": ["1234:5678:9ABC:DEF0:0000:0000:0000:0000",
                     "0000:0000:0000:0000:0000:0000:0000:0000",
                     "1234:5678:9ABC:DEF0:1234:5678:9ABC:DEF0",
                     "1234:1234:1234::",
                     "1234:1234:1234:1234:1234::",
                     "1234:5678:9ABC:DEF0::",
                     "0000:0000::0000",
                     "1234::5678:9ABC:0000:0000:0000:0000",
                     "::1",
                     "::",
                     "1:1:1:1:1:1:1:1"],
            "PTR": good_dns,
            "CNAME": good_dns,
            "NS": good_dns,
            "MX": good_mx,
            "SRV": good_srv,
            "TXT": ["text", "", "@#!", "\n"]
        }

        cls.bad_records = {
            "A": ["192.168.0.500",
                  "255.255.255.255/32"],
            "AAAA": ["GGGG:1234:5678:9ABC:0000:0000:0000:0000",
                     "0000:0000:0000:0000:0000:0000:0000:0000/1",
                     "AAAA:AAAA:AAAA:AAAA:G000:0000:0000:1234",
                     "1234:5678:9ABC:DEF0:1234:5678:9ABC:DEF0:1234",
                     "1234:5678:9ABC:DEF0:1234:5678:9ABC",
                     "1111::1111::1111"],
            "PTR": bad_dns,
            "CNAME": bad_dns,
            "NS": bad_dns,
            "MX": bad_mx,
            "SRV": bad_srv
        }

        # Because we use uint16_t for these numbers, we can't
        # actually create these records.
        invalid_mx = ["SAMDOM.EXAMPLE.COM -1",
                      "SAMDOM.EXAMPLE.COM 65536",
                      "%s 1" % "A"*256]
        invalid_srv = ["SAMDOM.EXAMPLE.COM 0 65536 0",
                       "SAMDOM.EXAMPLE.COM 0 0 65536",
                       "SAMDOM.EXAMPLE.COM 65536 0 0"]
        cls.invalid_records = {
            "MX": invalid_mx,
            "SRV": invalid_srv
        }

    def setUp(self):
        super(DnsserverTests, self).setUp()
        self.server = os.environ["DC_SERVER"]
        self.zone = env_get_var_value("REALM").lower()
        self.conn = dnsserver.dnsserver("ncacn_ip_tcp:%s[sign]" % (self.server),
                                        self.get_loadparm(),
                                        self.get_credentials())

        self.samdb = SamDB(url="ldap://%s" % os.environ["DC_SERVER_IP"],
                           lp = self.get_loadparm(),
                           session_info=system_session(),
                           credentials=self.get_credentials())


        self.custom_zone = "zone"
        zone_create_info = dnsserver.DNS_RPC_ZONE_CREATE_INFO_LONGHORN()
        zone_create_info.pszZoneName = self.custom_zone
        zone_create_info.dwZoneType = dnsp.DNS_ZONE_TYPE_PRIMARY
        zone_create_info.fAging = 0
        zone_create_info.fDsIntegrated = 1
        zone_create_info.fLoadExisting = 1
        zone_create_info.dwDpFlags = dnsserver.DNS_DP_DOMAIN_DEFAULT

        self.conn.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                   0,
                                   self.server,
                                   None,
                                   0,
                                   'ZoneCreate',
                                   dnsserver.DNSSRV_TYPEID_ZONE_CREATE,
                                   zone_create_info)

    def tearDown(self):
        self.conn.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                   0,
                                   self.server,
                                   self.custom_zone,
                                   0,
                                   'DeleteZoneFromDs',
                                   dnsserver.DNSSRV_TYPEID_NULL,
                                   None)
        super(DnsserverTests, self).tearDown()

    # This test fails against Samba (but passes against Windows),
    # because Samba does not return the record when we enum records.
    # Records can be given DNS_RANK_NONE when the zone they are in
    # does not have DNS_ZONE_TYPE_PRIMARY. Since such records can be
    # deleted, however, we do not consider this urgent to fix and
    # so this test is a knownfail.
    def test_rank_none(self):
        """
        See what happens when we set a record's rank to
        DNS_RANK_NONE.
        """

        record_str = "192.168.50.50"
        record_type_str = "A"
        self.add_record(self.custom_zone, "testrecord", record_type_str, record_str)

        dn, record = self.get_record_from_db(self.custom_zone, "testrecord")
        record.rank = 0 # DNS_RANK_NONE
        res = self.samdb.dns_replace_by_dn(dn, [record])
        if res is not None:
            self.fail("Unable to update dns record to have DNS_RANK_NONE.")

        self.assert_num_records(self.custom_zone, "testrecord", record_type_str)
        self.add_record(self.custom_zone, "testrecord", record_type_str, record_str, assertion=False)
        self.delete_record(self.custom_zone, "testrecord", record_type_str, record_str)
        self.assert_num_records(self.custom_zone, "testrecord", record_type_str, 0)

    def test_dns_tombstoned(self):
        """
        See what happens when we set a record to be tombstoned.
        """

        record_str = "192.168.50.50"
        record_type_str = "A"
        self.add_record(self.custom_zone, "testrecord", record_type_str, record_str)

        dn, record = self.get_record_from_db(self.custom_zone, "testrecord")
        record.wType = dnsp.DNS_TYPE_TOMBSTONE
        res = self.samdb.dns_replace_by_dn(dn, [record])
        if res is not None:
            self.fail("Unable to update dns record to be tombstoned.")

        self.assert_num_records(self.custom_zone, "testrecord", record_type_str)
        self.delete_record(self.custom_zone, "testrecord", record_type_str, record_str)
        self.assert_num_records(self.custom_zone, "testrecord", record_type_str, 0)

    def get_record_from_db(self, zone_name, record_name):
        """
        Returns (dn of record, record)
        """

        zones = self.samdb.search(base="DC=DomainDnsZones,%s" % self.samdb.get_default_basedn(), scope=ldb.SCOPE_SUBTREE,
                                  expression="(objectClass=dnsZone)",
                                  attrs=["cn"])

        zone_dn = None
        for zone in zones:
            if zone_name in str(zone.dn):
                zone_dn = zone.dn
                break

        if zone_dn is None:
            raise AssertionError("Couldn't find zone '%s'." % zone_name)

        records = self.samdb.search(base=zone_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectClass=dnsNode)",
                                    attrs=["dnsRecord"])

        for old_packed_record in records:
            if record_name in str(old_packed_record.dn):
                return (old_packed_record.dn, ndr_unpack(dnsp.DnssrvRpcRecord, old_packed_record["dnsRecord"][0]))

    def test_duplicate_matching(self):
        """
        Make sure that records which should be distinct from each other or duplicate
        to each other behave as expected.
        """

        distinct_dns = [("SAMDOM.EXAMPLE.COM",
                         "SAMDOM.EXAMPLE.CO",
                         "EXAMPLE.COM", "SAMDOM.EXAMPLE")]
        duplicate_dns = [("SAMDOM.EXAMPLE.COM", "samdom.example.com", "SAMDOM.example.COM"),
                         ("EXAMPLE.", "EXAMPLE")]

        # Every tuple has entries which should be considered duplicate to one another.
        duplicates = {
            "AAAA": [("AAAA::", "aaaa::"),
                     ("AAAA::", "AAAA:0000::"),
                     ("AAAA::", "AAAA:0000:0000:0000:0000:0000:0000:0000"),
                     ("AAAA::", "AAAA:0:0:0:0:0:0:0"),
                     ("0123::", "123::"),
                     ("::", "::0", "0000:0000:0000:0000:0000:0000:0000:0000")],
        }

        # Every tuple has entries which should be considered distinct from one another.
        distinct = {
            "A": [("192.168.1.0", "192.168.1.1", "192.168.2.0", "192.169.1.0", "193.168.1.0")],
            "AAAA": [("AAAA::1234:5678:9ABC", "::AAAA:1234:5678:9ABC"),
                     ("1000::", "::1000"),
                     ("::1", "::11", "::1111"),
                     ("1234::", "0234::")],
            "SRV": [("SAMDOM.EXAMPLE.COM 1 1 1", "SAMDOM.EXAMPLE.COM 1 1 0", "SAMDOM.EXAMPLE.COM 1 0 1",
                     "SAMDOM.EXAMPLE.COM 0 1 1", "SAMDOM.EXAMPLE.COM 2 1 0", "SAMDOM.EXAMPLE.COM 2 2 2")],
            "MX": [("SAMDOM.EXAMPLE.COM 1", "SAMDOM.EXAMPLE.COM 0")],
            "TXT": [("A RECORD", "B RECORD", "a record")]
        }

        for record_type_str in ("PTR", "CNAME", "NS"):
            distinct[record_type_str] = distinct_dns
            duplicates[record_type_str] = duplicate_dns

        for record_type_str in duplicates:
            for duplicate_tuple in duplicates[record_type_str]:
                # Attempt to add duplicates and make sure that all after the first fails
                self.add_record(self.custom_zone, "testrecord", record_type_str, duplicate_tuple[0])
                for record in duplicate_tuple:
                    self.add_record(self.custom_zone, "testrecord", record_type_str, record, assertion=False)
                    self.assert_num_records(self.custom_zone, "testrecord", record_type_str)
                self.delete_record(self.custom_zone, "testrecord", record_type_str, duplicate_tuple[0])

                # Repeatedly: add the first duplicate, and attempt to remove all of the others, making sure this succeeds
                for record in duplicate_tuple:
                    self.add_record(self.custom_zone, "testrecord", record_type_str, duplicate_tuple[0])
                    self.delete_record(self.custom_zone, "testrecord", record_type_str, record)

        for record_type_str in distinct:
            for distinct_tuple in distinct[record_type_str]:
                # Attempt to add distinct and make sure that they all succeed within a tuple
                i = 0
                for record in distinct_tuple:
                    i = i + 1
                    try:
                        self.add_record(self.custom_zone, "testrecord", record_type_str, record)
                        # All records should have been added.
                        self.assert_num_records(self.custom_zone, "testrecord", record_type_str, expected_num=i)
                    except AssertionError as e:
                        raise AssertionError("Failed to add %s, which should be distinct from all others in the set. "
                                             "Original error: %s\nDistinct set: %s." % (record, e, distinct_tuple))
                for record in distinct_tuple:
                    self.delete_record(self.custom_zone, "testrecord", record_type_str, record)
                    # CNAMEs should not have been added, since they conflict.
                    if record_type_str == 'CNAME':
                        continue

                # Add the first distinct and attempt to remove all of the others, making sure this fails
                # Windows fails this test. This is probably due to weird tombstoning behavior.
                self.add_record(self.custom_zone, "testrecord", record_type_str, distinct_tuple[0])
                for record in distinct_tuple:
                    if record == distinct_tuple[0]:
                        continue
                    try:
                        self.delete_record(self.custom_zone, "testrecord", record_type_str, record, assertion=False)
                    except AssertionError as e:
                        raise AssertionError("Managed to remove %s by attempting to remove %s. Original error: %s"
                                             % (distinct_tuple[0], record, e))
                self.delete_record(self.custom_zone, "testrecord", record_type_str, distinct_tuple[0])

    def test_accept_valid_commands(self):
        """
        Make sure that we can add, update and delete a variety
        of valid records.
        """
        for record_type_str in self.good_records:
            for record_str in self.good_records[record_type_str]:
                self.add_record(self.custom_zone, "testrecord", record_type_str, record_str)
                self.assert_num_records(self.custom_zone, "testrecord", record_type_str)
                self.delete_record(self.custom_zone, "testrecord", record_type_str, record_str)

    def test_reject_invalid_commands(self):
        """
        Make sure that we can't add a variety of invalid records,
        and that we can't update valid records to invalid ones.
        """
        num_failures = 0
        for record_type_str in self.bad_records:
            for record_str in self.bad_records[record_type_str]:
                # Attempt to add the bad record, which should fail. Then, attempt to query for and delete
                # it. Since it shouldn't exist, these should fail too.
                try:
                    self.add_record(self.custom_zone, "testrecord", record_type_str, record_str, assertion=False)
                    self.assert_num_records(self.custom_zone, "testrecord", record_type_str, expected_num=0)
                    self.delete_record(self.custom_zone, "testrecord", record_type_str, record_str, assertion=False)
                except AssertionError as e:
                    print(e)
                    num_failures = num_failures + 1

        # Also try to update valid records to invalid ones, making sure this fails
        for record_type_str in self.bad_records:
            for record_str in self.bad_records[record_type_str]:
                good_record_str = self.good_records[record_type_str][0]
                self.add_record(self.custom_zone, "testrecord", record_type_str, good_record_str)
                try:
                    self.add_record(self.custom_zone, "testrecord", record_type_str, record_str, assertion=False)
                except AssertionError as e:
                    print(e)
                    num_failures = num_failures + 1
                self.delete_record(self.custom_zone, "testrecord", record_type_str, good_record_str)

        self.assertTrue(num_failures == 0, "Failed to reject invalid commands. Total failures: %d." % num_failures)

    def test_add_duplicate_different_type(self):
        """
        Attempt to add some values which have the same name as
        existing ones, just a different type.
        """
        num_failures = 0
        for record_type_str_1 in self.good_records:
            record1 = self.good_records[record_type_str_1][0]
            self.add_record(self.custom_zone, "testrecord", record_type_str_1, record1)
            for record_type_str_2 in self.good_records:
                if record_type_str_1 == record_type_str_2:
                    continue

                record2 = self.good_records[record_type_str_2][0]

                has_a = record_type_str_1 == 'A' or record_type_str_2 == 'A'
                has_aaaa = record_type_str_1 == 'AAAA' or record_type_str_2 == 'AAAA'
                has_cname = record_type_str_1 == 'CNAME' or record_type_str_2 == 'CNAME'
                has_ptr = record_type_str_1 == 'PTR' or record_type_str_2 == 'PTR'
                has_mx = record_type_str_1 == 'MX' or record_type_str_2 == 'MX'
                has_srv = record_type_str_1 == 'SRV' or record_type_str_2 == 'SRV'
                has_txt = record_type_str_1 == 'TXT' or record_type_str_2 == 'TXT'

                # If we attempt to add any record except A or AAAA when we already have an NS record,
                # the add should fail.
                add_error_ok = False
                if record_type_str_1 == 'NS' and not has_a and not has_aaaa:
                    add_error_ok = True
                # If we attempt to add a CNAME when an A, PTR or MX record exists, the add should fail.
                if record_type_str_2 == 'CNAME' and (has_ptr or has_mx or has_a or has_aaaa):
                    add_error_ok = True
                # If we have a CNAME, adding an A, AAAA, SRV or TXT record should fail.
                # If we have an A, AAAA, SRV or TXT record, adding a CNAME should fail.
                if has_cname and (has_a or has_aaaa or has_srv or has_txt):
                    add_error_ok = True

                try:
                    self.add_record(self.custom_zone, "testrecord", record_type_str_2, record2)
                    if add_error_ok:
                        num_failures = num_failures + 1
                        print("Expected error when adding %s while a %s existed."
                              % (record_type_str_2, record_type_str_1))
                except AssertionError as e:
                    if not add_error_ok:
                        num_failures = num_failures + 1
                        print("Didn't expect error when adding %s while a %s existed."
                              % (record_type_str_2, record_type_str_1))

                if not add_error_ok:
                    # In the "normal" case, we expect the add to work and us to have one of each type of record afterwards.
                    expected_num_type_1 = 1
                    expected_num_type_2 = 1

                    # If we have an MX record, a PTR record should replace it when added.
                    # If we have a PTR record, an MX record should replace it when added.
                    if has_ptr and has_mx:
                        expected_num_type_1 = 0

                    # If we have a CNAME, SRV or TXT record, a PTR or MX record should replace it when added.
                    if (has_cname or has_srv or has_txt) and (record_type_str_2 == 'PTR' or record_type_str_2 == 'MX'):
                        expected_num_type_1 = 0

                    if (record_type_str_1 == 'NS' and (has_a or has_aaaa)):
                        expected_num_type_2 = 0

                    try:
                        self.assert_num_records(self.custom_zone, "testrecord", record_type_str_1, expected_num=expected_num_type_1)
                    except AssertionError as e:
                        num_failures = num_failures + 1
                        print("Expected %s %s records after adding a %s record and a %s record already existed."
                              % (expected_num_type_1, record_type_str_1, record_type_str_2, record_type_str_1))
                    try:
                        self.assert_num_records(self.custom_zone, "testrecord", record_type_str_2, expected_num=expected_num_type_2)
                    except AssertionError as e:
                        num_failures = num_failures + 1
                        print("Expected %s %s records after adding a %s record and a %s record already existed."
                              % (expected_num_type_2, record_type_str_2, record_type_str_2, record_type_str_1))

                try:
                    self.delete_record(self.custom_zone, "testrecord", record_type_str_2, record2)
                except AssertionError as e:
                    pass

            self.delete_record(self.custom_zone, "testrecord", record_type_str_1, record1)

        self.assertTrue(num_failures == 0, "Failed collision and replacement behavior. Total failures: %d." % num_failures)

    # Windows fails this test in the same way we do.
    def _test_cname(self):
        """
        Test some special properties of CNAME records.
        """

        # RFC 1912: When there is a CNAME record, there must not be any other records with the same alias
        cname_record = self.good_records["CNAME"][1]
        self.add_record(self.custom_zone, "testrecord", "CNAME", cname_record)

        for record_type_str in self.good_records:
            other_record = self.good_records[record_type_str][0]
            self.add_record(self.custom_zone, "testrecord", record_type_str, other_record, assertion=False)
            self.assert_num_records(self.custom_zone, "testrecord", record_type_str, expected_num=0)

        # RFC 2181: MX & NS records must not be allowed to point to a CNAME alias
        mx_record = "testrecord 1"
        ns_record = "testrecord"

        self.add_record(self.custom_zone, "mxrec", "MX", mx_record, assertion=False)
        self.add_record(self.custom_zone, "nsrec", "NS", ns_record, assertion=False)

        self.delete_record(self.custom_zone, "testrecord", "CNAME", cname_record)

    def test_add_duplicate_value(self):
        """
        Make sure that we can't add duplicate values of any type.
        """
        for record_type_str in self.good_records:
            record = self.good_records[record_type_str][0]

            self.add_record(self.custom_zone, "testrecord", record_type_str, record)
            self.add_record(self.custom_zone, "testrecord", record_type_str, record, assertion=False)
            self.assert_num_records(self.custom_zone, "testrecord", record_type_str)
            self.delete_record(self.custom_zone, "testrecord", record_type_str, record)

    def test_add_similar_value(self):
        """
        Attempt to add values with the same name and type in the same
        zone. This should work, and should result in both values
        existing (except with some types).
        """
        for record_type_str in self.good_records:
            for i in range(1, len(self.good_records[record_type_str])):
                record1 = self.good_records[record_type_str][i-1]
                record2 = self.good_records[record_type_str][i]

                if record_type_str == 'CNAME':
                    continue
                # We expect CNAME records to override one another, as
                # an alias can only map to one CNAME record.
                # Also, on Windows, when the empty string is added and
                # another record is added afterwards, the empty string
                # will be silently overridden by the new one, so it
                # fails this test for the empty string.
                expected_num = 1 if record_type_str == 'CNAME' else 2

                self.add_record(self.custom_zone, "testrecord", record_type_str, record1)
                self.add_record(self.custom_zone, "testrecord", record_type_str, record2)
                self.assert_num_records(self.custom_zone, "testrecord", record_type_str, expected_num=expected_num)
                self.delete_record(self.custom_zone, "testrecord", record_type_str, record1)
                self.delete_record(self.custom_zone, "testrecord", record_type_str, record2)

    def assert_record(self, zone, name, record_type_str, expected_record_str,
                      assertion=True, client_version=dnsserver.DNS_CLIENT_VERSION_LONGHORN):
        """
        Asserts whether or not the given record with the given type exists in the
        given zone.
        """
        try:
            _, result = self.query_records(zone, name, record_type_str)
        except RuntimeError as e:
            if assertion:
                raise AssertionError("Record '%s' of type '%s' was not present when it should have been."
                                     % (expected_record_str, record_type_str))
            else:
                return

        found = False
        for record in result.rec[0].records:
            if record.data == expected_record_str:
                found = True
                break

        if found and not assertion:
            raise AssertionError("Record '%s' of type '%s' was present when it shouldn't have been." % (expected_record_str, record_type_str))
        elif not found and assertion:
            raise AssertionError("Record '%s' of type '%s' was not present when it should have been." % (expected_record_str, record_type_str))

    def assert_num_records(self, zone, name, record_type_str, expected_num=1,
                           client_version=dnsserver.DNS_CLIENT_VERSION_LONGHORN):
        """
        Asserts that there are a given amount of records with the given type in
        the given zone.
        """
        try:
            _, result = self.query_records(zone, name, record_type_str)
            num_results = len(result.rec[0].records)
            if not num_results == expected_num:
                raise AssertionError("There were %d records of type '%s' with the name '%s' when %d were expected."
                                     % (num_results, record_type_str, name, expected_num))
        except RuntimeError:
            if not expected_num == 0:
                raise AssertionError("There were no records of type '%s' with the name '%s' when %d were expected."
                                     % (record_type_str, name, expected_num))

    def query_records(self, zone, name, record_type_str, client_version=dnsserver.DNS_CLIENT_VERSION_LONGHORN):
        return self.conn.DnssrvEnumRecords2(client_version,
                                            0,
                                            self.server,
                                            zone,
                                            name,
                                            None,
                                            self.record_type_int(record_type_str),
                                            dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA | dnsserver.DNS_RPC_VIEW_NO_CHILDREN,
                                            None,
                                            None)

    def record_obj_from_str(self, record_type_str, record_str):
        if record_type_str == 'A':
            return ARecord(record_str)
        elif record_type_str == 'AAAA':
            return AAAARecord(record_str)
        elif record_type_str == 'PTR':
            return PTRRecord(record_str)
        elif record_type_str == 'CNAME':
            return CNameRecord(record_str)
        elif record_type_str == 'NS':
            return NSRecord(record_str)
        elif record_type_str == 'MX':
            split = record_str.split(' ')
            return MXRecord(split[0], int(split[1]))
        elif record_type_str == 'SRV':
            split = record_str.split(' ')
            target = split[0]
            port = int(split[1])
            priority = int(split[2])
            weight = int(split[3])
            return SRVRecord(target, port, priority, weight)
        elif record_type_str == 'TXT':
            return TXTRecord(record_str)

    def record_type_int(self, record_type_str):
        if record_type_str == 'A':
            return dnsp.DNS_TYPE_A
        elif record_type_str == 'AAAA':
            return dnsp.DNS_TYPE_AAAA
        elif record_type_str == 'PTR':
            return dnsp.DNS_TYPE_PTR
        elif record_type_str == 'CNAME':
            return dnsp.DNS_TYPE_CNAME
        elif record_type_str == 'NS':
            return dnsp.DNS_TYPE_NS
        elif record_type_str == 'MX':
            return dnsp.DNS_TYPE_MX
        elif record_type_str == 'SRV':
            return dnsp.DNS_TYPE_SRV
        elif record_type_str == 'TXT':
            return dnsp.DNS_TYPE_TXT

    def add_record(self, zone, name, record_type_str, record_str,
                   assertion=True, client_version=dnsserver.DNS_CLIENT_VERSION_LONGHORN):
        """
        Attempts to add a map from the given name to a record of the given type,
        in the given zone.
        Also asserts whether or not the add was successful.
        This can also update existing records if they have the same name.
        """
        record = self.record_obj_from_str(record_type_str, record_str)
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = record

        try:
            self.conn.DnssrvUpdateRecord2(client_version,
                                          0,
                                          self.server,
                                          zone,
                                          name,
                                          add_rec_buf,
                                          None)
            if not assertion:
                raise AssertionError("Successfully added record '%s' of type '%s', which should have failed."
                                     % (record_str, record_type_str))
        except RuntimeError as e:
            if assertion:
                raise AssertionError("Failed to add record '%s' of type '%s', which should have succeeded. Error was '%s'."
                                     % (record_str, record_type_str, str(e)))

    def delete_record(self, zone, name, record_type_str, record_str,
                      assertion=True, client_version=dnsserver.DNS_CLIENT_VERSION_LONGHORN):
        """
        Attempts to delete a record with the given name, record and record type
        from the given zone.
        Also asserts whether or not the deletion was successful.
        """
        record = self.record_obj_from_str(record_type_str, record_str)
        del_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        del_rec_buf.rec = record

        try:
            self.conn.DnssrvUpdateRecord2(client_version,
                                                   0,
                                                   self.server,
                                                   zone,
                                                   name,
                                                   None,
                                                   del_rec_buf)
            if not assertion:
                raise AssertionError("Successfully deleted record '%s' of type '%s', which should have failed." % (record_str, record_type_str))
        except RuntimeError as e:
            if assertion:
                raise AssertionError("Failed to delete record '%s' of type '%s', which should have succeeded. Error was '%s'." % (record_str, record_type_str, str(e)))

    def test_query2(self):
        typeid, result = self.conn.DnssrvQuery2(dnsserver.DNS_CLIENT_VERSION_W2K,
                                                0,
                                                self.server,
                                                None,
                                                'ServerInfo')
        self.assertEquals(dnsserver.DNSSRV_TYPEID_SERVER_INFO_W2K, typeid)

        typeid, result = self.conn.DnssrvQuery2(dnsserver.DNS_CLIENT_VERSION_DOTNET,
                                                0,
                                                self.server,
                                                None,
                                                'ServerInfo')
        self.assertEquals(dnsserver.DNSSRV_TYPEID_SERVER_INFO_DOTNET, typeid)

        typeid, result = self.conn.DnssrvQuery2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                                0,
                                                self.server,
                                                None,
                                                'ServerInfo')
        self.assertEquals(dnsserver.DNSSRV_TYPEID_SERVER_INFO, typeid)

    def test_operation2(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        rev_zone = '1.168.192.in-addr.arpa'

        zone_create = dnsserver.DNS_RPC_ZONE_CREATE_INFO_LONGHORN()
        zone_create.pszZoneName = rev_zone
        zone_create.dwZoneType = dnsp.DNS_ZONE_TYPE_PRIMARY
        zone_create.fAllowUpdate = dnsp.DNS_ZONE_UPDATE_SECURE
        zone_create.fAging = 0
        zone_create.dwDpFlags = dnsserver.DNS_DP_DOMAIN_DEFAULT

        # Create zone
        self.conn.DnssrvOperation2(client_version,
                                    0,
                                    self.server,
                                    None,
                                    0,
                                    'ZoneCreate',
                                    dnsserver.DNSSRV_TYPEID_ZONE_CREATE,
                                    zone_create)

        request_filter = (dnsserver.DNS_ZONE_REQUEST_REVERSE |
                            dnsserver.DNS_ZONE_REQUEST_PRIMARY)
        _, zones = self.conn.DnssrvComplexOperation2(client_version,
                                                     0,
                                                     self.server,
                                                     None,
                                                     'EnumZones',
                                                     dnsserver.DNSSRV_TYPEID_DWORD,
                                                     request_filter)
        self.assertEquals(1, zones.dwZoneCount)

        # Delete zone
        self.conn.DnssrvOperation2(client_version,
                                    0,
                                    self.server,
                                    rev_zone,
                                    0,
                                    'DeleteZoneFromDs',
                                    dnsserver.DNSSRV_TYPEID_NULL,
                                    None)

        typeid, zones = self.conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server,
                                                            None,
                                                            'EnumZones',
                                                            dnsserver.DNSSRV_TYPEID_DWORD,
                                                            request_filter)
        self.assertEquals(0, zones.dwZoneCount)


    def test_complexoperation2(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        request_filter = (dnsserver.DNS_ZONE_REQUEST_FORWARD |
                            dnsserver.DNS_ZONE_REQUEST_PRIMARY)

        typeid, zones = self.conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server,
                                                            None,
                                                            'EnumZones',
                                                            dnsserver.DNSSRV_TYPEID_DWORD,
                                                            request_filter)
        self.assertEquals(dnsserver.DNSSRV_TYPEID_ZONE_LIST, typeid)
        self.assertEquals(3, zones.dwZoneCount)

        request_filter = (dnsserver.DNS_ZONE_REQUEST_REVERSE |
                            dnsserver.DNS_ZONE_REQUEST_PRIMARY)
        typeid, zones = self.conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server,
                                                            None,
                                                            'EnumZones',
                                                            dnsserver.DNSSRV_TYPEID_DWORD,
                                                            request_filter)
        self.assertEquals(dnsserver.DNSSRV_TYPEID_ZONE_LIST, typeid)
        self.assertEquals(0, zones.dwZoneCount)

    def test_enumrecords2(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        record_type = dnsp.DNS_TYPE_NS
        select_flags = (dnsserver.DNS_RPC_VIEW_ROOT_HINT_DATA |
                        dnsserver.DNS_RPC_VIEW_ADDITIONAL_DATA)
        _, roothints = self.conn.DnssrvEnumRecords2(client_version,
                                                    0,
                                                    self.server,
                                                    '..RootHints',
                                                    '.',
                                                    None,
                                                    record_type,
                                                    select_flags,
                                                    None,
                                                    None)
        self.assertEquals(14, roothints.count)  # 1 NS + 13 A records (a-m)

    def test_updaterecords2(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        record_type = dnsp.DNS_TYPE_A
        select_flags = dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA

        name = 'dummy'
        rec = ARecord('1.2.3.4')
        rec2 = ARecord('5.6.7.8')

        # Add record
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        self.conn.DnssrvUpdateRecord2(client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        name,
                                        add_rec_buf,
                                        None)

        _, result = self.conn.DnssrvEnumRecords2(client_version,
                                                 0,
                                                 self.server,
                                                 self.zone,
                                                 name,
                                                 None,
                                                 record_type,
                                                 select_flags,
                                                 None,
                                                 None)
        self.assertEquals(1, result.count)
        self.assertEquals(1, result.rec[0].wRecordCount)
        self.assertEquals(dnsp.DNS_TYPE_A, result.rec[0].records[0].wType)
        self.assertEquals('1.2.3.4', result.rec[0].records[0].data)

        # Update record
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec2
        del_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        del_rec_buf.rec = rec
        self.conn.DnssrvUpdateRecord2(client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        name,
                                        add_rec_buf,
                                        del_rec_buf)

        buflen, result = self.conn.DnssrvEnumRecords2(client_version,
                                                        0,
                                                        self.server,
                                                        self.zone,
                                                        name,
                                                        None,
                                                        record_type,
                                                        select_flags,
                                                        None,
                                                        None)
        self.assertEquals(1, result.count)
        self.assertEquals(1, result.rec[0].wRecordCount)
        self.assertEquals(dnsp.DNS_TYPE_A, result.rec[0].records[0].wType)
        self.assertEquals('5.6.7.8', result.rec[0].records[0].data)

        # Delete record
        del_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        del_rec_buf.rec = rec2
        self.conn.DnssrvUpdateRecord2(client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        name,
                                        None,
                                        del_rec_buf)

        self.assertRaises(RuntimeError, self.conn.DnssrvEnumRecords2,
                                        client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        name,
                                        None,
                                        record_type,
                                        select_flags,
                                        None,
                                        None)

    # The following tests do not pass against Samba because the owner and
    # group are not consistent with Windows, as well as some ACEs.
    #
    # The following ACE are also required for 2012R2:
    #
    # (OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)
    # (OA;OICI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)"
    #
    # [TPM + Allowed-To-Act-On-Behalf-Of-Other-Identity]
    def test_security_descriptor_msdcs_zone(self):
        """
        Make sure that security descriptors of the msdcs zone is
        as expected.
        """

        zones = self.samdb.search(base="DC=ForestDnsZones,%s" % self.samdb.get_default_basedn(),
                                  scope=ldb.SCOPE_SUBTREE,
                                  expression="(&(objectClass=dnsZone)(name=_msdcs*))",
                                  attrs=["nTSecurityDescriptor", "objectClass"])
        self.assertEqual(len(zones), 1)
        self.assertTrue("nTSecurityDescriptor" in zones[0])
        tmp = zones[0]["nTSecurityDescriptor"][0]
        utils = sd_utils.SDUtils(self.samdb)
        sd = ndr_unpack(security.descriptor, tmp)

        domain_sid = security.dom_sid(self.samdb.get_domain_sid())

        res = self.samdb.search(base=self.samdb.get_default_basedn(), scope=ldb.SCOPE_SUBTREE,
                                expression="(sAMAccountName=DnsAdmins)",
                                attrs=["objectSid"])

        dns_admin = str(ndr_unpack(security.dom_sid, res[0]['objectSid'][0]))

        packed_sd = descriptor.sddl2binary("O:SYG:BA" \
                                           "D:AI(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" \
                                           "(A;;CC;;;AU)" \
                                           "(A;;RPLCLORC;;;WD)" \
                                           "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
                                           "(A;CI;RPWPCRCCDCLCRCWOWDSDDTSW;;;ED)",
                                           domain_sid, {"DnsAdmins": dns_admin})
        expected_sd = descriptor.get_clean_sd(ndr_unpack(security.descriptor, packed_sd))

        diff = descriptor.get_diff_sds(expected_sd, sd, domain_sid)
        self.assertEqual(diff, '', "SD of msdcs zone different to expected.\n"
                         "Difference was:\n%s\nExpected: %s\nGot: %s" %
                         (diff, expected_sd.as_sddl(utils.domain_sid),
                          sd.as_sddl(utils.domain_sid)))

    def test_security_descriptor_forest_zone(self):
        """
        Make sure that security descriptors of forest dns zones are
        as expected.
        """
        forest_zone = "test_forest_zone"
        zone_create_info = dnsserver.DNS_RPC_ZONE_CREATE_INFO_LONGHORN()
        zone_create_info.dwZoneType = dnsp.DNS_ZONE_TYPE_PRIMARY
        zone_create_info.fAging = 0
        zone_create_info.fDsIntegrated = 1
        zone_create_info.fLoadExisting = 1

        zone_create_info.pszZoneName = forest_zone
        zone_create_info.dwDpFlags = dnsserver.DNS_DP_FOREST_DEFAULT

        self.conn.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                   0,
                                   self.server,
                                   None,
                                   0,
                                   'ZoneCreate',
                                   dnsserver.DNSSRV_TYPEID_ZONE_CREATE,
                                   zone_create_info)

        partition_dn = self.samdb.get_default_basedn()
        partition_dn.add_child("DC=ForestDnsZones")
        zones = self.samdb.search(base=partition_dn, scope=ldb.SCOPE_SUBTREE,
                                  expression="(name=%s)" % forest_zone,
                                  attrs=["nTSecurityDescriptor"])
        self.assertEqual(len(zones), 1)
        current_dn = zones[0].dn
        self.assertTrue("nTSecurityDescriptor" in zones[0])
        tmp = zones[0]["nTSecurityDescriptor"][0]
        utils = sd_utils.SDUtils(self.samdb)
        sd = ndr_unpack(security.descriptor, tmp)

        domain_sid = security.dom_sid(self.samdb.get_domain_sid())

        res = self.samdb.search(base=self.samdb.get_default_basedn(),
                                scope=ldb.SCOPE_SUBTREE,
                                expression="(sAMAccountName=DnsAdmins)",
                                attrs=["objectSid"])

        dns_admin = str(ndr_unpack(security.dom_sid, res[0]['objectSid'][0]))

        packed_sd = descriptor.sddl2binary("O:DAG:DA" \
                                           "D:AI(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" \
                                           "(A;;CC;;;AU)" \
                                           "(A;;RPLCLORC;;;WD)" \
                                           "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
                                           "(A;CI;RPWPCRCCDCLCRCWOWDSDDTSW;;;ED)",
                                           domain_sid, {"DnsAdmins": dns_admin})
        expected_sd = descriptor.get_clean_sd(ndr_unpack(security.descriptor, packed_sd))

        packed_msdns = descriptor.get_dns_forest_microsoft_dns_descriptor(domain_sid,
                                                                          {"DnsAdmins": dns_admin})
        expected_msdns_sd = descriptor.get_clean_sd(ndr_unpack(security.descriptor, packed_msdns))

        packed_part_sd = descriptor.get_dns_partition_descriptor(domain_sid)
        expected_part_sd = descriptor.get_clean_sd(ndr_unpack(security.descriptor,
                                                              packed_part_sd))
        try:
            msdns_dn = ldb.Dn(self.samdb, "CN=MicrosoftDNS,%s" % str(partition_dn))
            security_desc_dict = [(current_dn.get_linearized(),  expected_sd),
                                  (msdns_dn.get_linearized(), expected_msdns_sd),
                                  (partition_dn.get_linearized(), expected_part_sd)]

            for (key, sec_desc) in security_desc_dict:
                zones = self.samdb.search(base=key, scope=ldb.SCOPE_BASE,
                                          attrs=["nTSecurityDescriptor"])
                self.assertTrue("nTSecurityDescriptor" in zones[0])
                tmp = zones[0]["nTSecurityDescriptor"][0]
                utils = sd_utils.SDUtils(self.samdb)

                sd = ndr_unpack(security.descriptor, tmp)
                diff = descriptor.get_diff_sds(sec_desc, sd, domain_sid)

                self.assertEqual(diff, '', "Security descriptor of forest DNS zone with DN '%s' different to expected. Difference was:\n%s\nExpected: %s\nGot: %s"
                                 % (key, diff, sec_desc.as_sddl(utils.domain_sid), sd.as_sddl(utils.domain_sid)))

        finally:
            self.conn.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                       0,
                                       self.server,
                                       forest_zone,
                                       0,
                                       'DeleteZoneFromDs',
                                       dnsserver.DNSSRV_TYPEID_NULL,
                                       None)

    def test_security_descriptor_domain_zone(self):
        """
        Make sure that security descriptors of domain dns zones are
        as expected.
        """

        partition_dn = self.samdb.get_default_basedn()
        partition_dn.add_child("DC=DomainDnsZones")
        zones = self.samdb.search(base=partition_dn, scope=ldb.SCOPE_SUBTREE,
                                  expression="(name=%s)" % self.custom_zone,
                                  attrs=["nTSecurityDescriptor"])
        self.assertEqual(len(zones), 1)
        current_dn = zones[0].dn
        self.assertTrue("nTSecurityDescriptor" in zones[0])
        tmp = zones[0]["nTSecurityDescriptor"][0]
        utils = sd_utils.SDUtils(self.samdb)
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(utils.domain_sid)

        domain_sid = security.dom_sid(self.samdb.get_domain_sid())

        res = self.samdb.search(base=self.samdb.get_default_basedn(), scope=ldb.SCOPE_SUBTREE,
                                expression="(sAMAccountName=DnsAdmins)",
                                attrs=["objectSid"])

        dns_admin = str(ndr_unpack(security.dom_sid, res[0]['objectSid'][0]))

        packed_sd = descriptor.sddl2binary("O:DAG:DA" \
                                           "D:AI(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" \
                                           "(A;;CC;;;AU)" \
                                           "(A;;RPLCLORC;;;WD)" \
                                           "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
                                           "(A;CI;RPWPCRCCDCLCRCWOWDSDDTSW;;;ED)",
                                           domain_sid, {"DnsAdmins": dns_admin})
        expected_sd = descriptor.get_clean_sd(ndr_unpack(security.descriptor, packed_sd))

        packed_msdns = descriptor.get_dns_domain_microsoft_dns_descriptor(domain_sid,
                                                                          {"DnsAdmins": dns_admin})
        expected_msdns_sd = descriptor.get_clean_sd(ndr_unpack(security.descriptor, packed_msdns))

        packed_part_sd = descriptor.get_dns_partition_descriptor(domain_sid)
        expected_part_sd = descriptor.get_clean_sd(ndr_unpack(security.descriptor,
                                                              packed_part_sd))

        msdns_dn = ldb.Dn(self.samdb, "CN=MicrosoftDNS,%s" % str(partition_dn))
        security_desc_dict = [(current_dn.get_linearized(),  expected_sd),
                              (msdns_dn.get_linearized(), expected_msdns_sd),
                              (partition_dn.get_linearized(), expected_part_sd)]

        for (key, sec_desc) in security_desc_dict:
            zones = self.samdb.search(base=key, scope=ldb.SCOPE_BASE,
                                      attrs=["nTSecurityDescriptor"])
            self.assertTrue("nTSecurityDescriptor" in zones[0])
            tmp = zones[0]["nTSecurityDescriptor"][0]
            utils = sd_utils.SDUtils(self.samdb)

            sd = ndr_unpack(security.descriptor, tmp)
            diff = descriptor.get_diff_sds(sec_desc, sd, domain_sid)

            self.assertEqual(diff, '', "Security descriptor of domain DNS zone with DN '%s' different to expected. Difference was:\n%s\nExpected: %s\nGot: %s"
                             % (key, diff, sec_desc.as_sddl(utils.domain_sid), sd.as_sddl(utils.domain_sid)))

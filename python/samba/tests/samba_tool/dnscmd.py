# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@catalyst.net.nz>
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

import os
import ldb
import re

from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import dnsp
from samba.tests.samba_tool.base import SambaToolCmdTest
import time
from samba import dsdb_dns


class DnsCmdTestCase(SambaToolCmdTest):
    def setUp(self):
        super().setUp()

        self.dburl = "ldap://%s" % os.environ["SERVER"]
        self.creds_string = "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                          os.environ["DC_PASSWORD"])

        self.samdb = self.getSamDB("-H", self.dburl, self.creds_string)
        self.config_dn = str(self.samdb.get_config_basedn())

        self.testip = "192.168.0.193"
        self.testip2 = "192.168.0.194"

        self.addCleanup(self.deleteZone)
        self.addZone()

        # Note: SOA types don't work (and shouldn't), as we only have one zone per DNS record.

        good_dns = ["SAMDOM.EXAMPLE.COM",
                    "1.EXAMPLE.COM",
                    "%sEXAMPLE.COM" % ("1." * 100),
                    "EXAMPLE",
                    "!@#$%^&*()_",
                    "HIGH\xFFBYTE",
                    "@.EXAMPLE.COM",
                    "."]
        bad_dns = ["...",
                   ".EXAMPLE.COM",
                   ".EXAMPLE.",
                   "",
                   "SAMDOM..EXAMPLE.COM"]

        good_mx = ["SAMDOM.EXAMPLE.COM 65530",
                   "SAMDOM.EXAMPLE.COM     0"]
        bad_mx = ["SAMDOM.EXAMPLE.COM -1",
                  "SAMDOM.EXAMPLE.COM",
                  " ",
                  "SAMDOM.EXAMPLE.COM 1 1",
                  "SAMDOM.EXAMPLE.COM SAMDOM.EXAMPLE.COM"]

        good_srv = ["SAMDOM.EXAMPLE.COM 65530 65530 65530",
                    "SAMDOM.EXAMPLE.COM     1     1     1"]
        bad_srv = ["SAMDOM.EXAMPLE.COM 0 65536 0",
                   "SAMDOM.EXAMPLE.COM 0 0 65536",
                   "SAMDOM.EXAMPLE.COM 65536 0 0"]

        for bad_dn in bad_dns:
            bad_mx.append("%s 1" % bad_dn)
            bad_srv.append("%s 0 0 0" % bad_dn)
        for good_dn in good_dns:
            good_mx.append("%s 1" % good_dn)
            good_srv.append("%s 0 0 0" % good_dn)

        self.good_records = {
                "A":["192.168.0.1", "255.255.255.255"],
                "AAAA":["1234:5678:9ABC:DEF0:0000:0000:0000:0000",
                        "0000:0000:0000:0000:0000:0000:0000:0000",
                        "1234:5678:9ABC:DEF0:1234:5678:9ABC:DEF0",
                        "1234:1234:1234::",
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

        self.bad_records = {
                "A":["192.168.0.500",
                     "255.255.255.255/32"],
                "AAAA":["GGGG:1234:5678:9ABC:0000:0000:0000:0000",
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

    def resetZone(self):
        self.deleteZone()
        self.addZone()

    def addZone(self):
        self.zone = "zone"
        result, out, err = self.runsubcmd("dns",
                                          "zonecreate",
                                          os.environ["SERVER"],
                                          self.zone,
                                          self.creds_string)
        self.assertCmdSuccess(result, out, err)

    def deleteZone(self):
        result, out, err = self.runsubcmd("dns",
                                          "zonedelete",
                                          os.environ["SERVER"],
                                          self.zone,
                                          self.creds_string)
        self.assertCmdSuccess(result, out, err)

    def get_all_records(self, zone_name):
        zone_dn = (f"DC={zone_name},CN=MicrosoftDNS,DC=DomainDNSZones,"
                   f"{self.samdb.get_default_basedn()}")

        expression = "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))"

        nodes = self.samdb.search(base=zone_dn, scope=ldb.SCOPE_SUBTREE,
                                  expression=expression,
                                  attrs=["dnsRecord", "name"])

        record_map = {}
        for node in nodes:
            name = node["name"][0].decode()
            record_map[name] = list(node["dnsRecord"])

        return record_map

    def get_record_from_db(self, zone_name, record_name):
        zones = self.samdb.search(base="DC=DomainDnsZones,%s"
                                  % self.samdb.get_default_basedn(),
                                  scope=ldb.SCOPE_SUBTREE,
                                  expression="(objectClass=dnsZone)",
                                  attrs=["cn"])

        for zone in zones:
            if zone_name in str(zone.dn):
                zone_dn = zone.dn
                break

        records = self.samdb.search(base=zone_dn, scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectClass=dnsNode)",
                                    attrs=["dnsRecord"])

        for old_packed_record in records:
            if record_name in str(old_packed_record.dn):
                return (old_packed_record.dn,
                        ndr_unpack(dnsp.DnssrvRpcRecord,
                                   old_packed_record["dnsRecord"][0]))

    def test_rank_none(self):
        record_str = "192.168.50.50"
        record_type_str = "A"

        result, out, err = self.runsubcmd("dns", "add", os.environ["SERVER"],
                                          self.zone, "testrecord", record_type_str,
                                          record_str, self.creds_string)
        self.assertCmdSuccess(result, out, err,
                              "Failed to add record '%s' with type %s."
                              % (record_str, record_type_str))

        dn, record = self.get_record_from_db(self.zone, "testrecord")
        record.rank = 0  # DNS_RANK_NONE
        res = self.samdb.dns_replace_by_dn(dn, [record])
        if res is not None:
            self.fail("Unable to update dns record to have DNS_RANK_NONE.")

        errors = []

        # The record should still exist
        result, out, err = self.runsubcmd("dns", "query", os.environ["SERVER"],
                                          self.zone, "testrecord", record_type_str,
                                          self.creds_string)
        try:
            self.assertCmdSuccess(result, out, err,
                                  "Failed to query for a record"
                                  "which had DNS_RANK_NONE.")
            self.assertTrue("testrecord" in out and record_str in out,
                            "Query for a record which had DNS_RANK_NONE"
                            "succeeded but produced no resulting records.")
        except AssertionError:
            # Windows produces no resulting records
            pass

        # We should not be able to add a duplicate
        result, out, err = self.runsubcmd("dns", "add", os.environ["SERVER"],
                                          self.zone, "testrecord", record_type_str,
                                          record_str, self.creds_string)
        try:
            self.assertCmdFail(result, "Successfully added duplicate record"
                               "of one which had DNS_RANK_NONE.")
        except AssertionError as e:
            errors.append(e)

        # We should be able to delete it
        result, out, err = self.runsubcmd("dns", "delete", os.environ["SERVER"],
                                          self.zone, "testrecord", record_type_str,
                                          record_str, self.creds_string)
        try:
            self.assertCmdSuccess(result, out, err, "Failed to delete record"
                                  "which had DNS_RANK_NONE.")
        except AssertionError as e:
            errors.append(e)

        # Now the record should not exist
        result, out, err = self.runsubcmd("dns", "query", os.environ["SERVER"],
                                          self.zone, "testrecord",
                                          record_type_str, self.creds_string)
        try:
            self.assertCmdFail(result, "Successfully queried for deleted record"
                               "which had DNS_RANK_NONE.")
        except AssertionError as e:
            errors.append(e)

        if len(errors) > 0:
            err_str = "Failed appropriate behaviour with DNS_RANK_NONE:"
            for error in errors:
                err_str = err_str + "\n" + str(error)
            raise AssertionError(err_str)

    def test_accept_valid_commands(self):
        """
        For all good records, attempt to add, query and delete them.
        """
        num_failures = 0
        failure_msgs = []
        for dnstype in self.good_records:
            for record in self.good_records[dnstype]:
                try:
                    result, out, err = self.runsubcmd("dns", "add",
                                                      os.environ["SERVER"],
                                                      self.zone, "testrecord",
                                                      dnstype, record,
                                                      self.creds_string)
                    self.assertCmdSuccess(result, out, err, "Failed to add"
                                          "record %s with type %s."
                                          % (record, dnstype))

                    result, out, err = self.runsubcmd("dns", "query",
                                                      os.environ["SERVER"],
                                                      self.zone, "testrecord",
                                                      dnstype,
                                                      self.creds_string)
                    self.assertCmdSuccess(result, out, err, "Failed to query"
                                          "record %s with qualifier %s."
                                          % (record, dnstype))

                    result, out, err = self.runsubcmd("dns", "delete",
                                                      os.environ["SERVER"],
                                                      self.zone, "testrecord",
                                                      dnstype, record,
                                                      self.creds_string)
                    self.assertCmdSuccess(result, out, err, "Failed to remove"
                                          "record %s with type %s."
                                          % (record, dnstype))
                except AssertionError as e:
                    num_failures = num_failures + 1
                    failure_msgs.append(e)

        if num_failures > 0:
            for msg in failure_msgs:
                print(msg)
            self.fail("Failed to accept valid commands. %d total failures."
                      "Errors above." % num_failures)

    def test_reject_invalid_commands(self):
        """
        For all bad records, attempt to add them and update to them,
        making sure that both operations fail.
        """
        num_failures = 0
        failure_msgs = []

        # Add invalid records and make sure they fail to be added
        for dnstype in self.bad_records:
            for record in self.bad_records[dnstype]:
                try:
                    result, out, err = self.runsubcmd("dns", "add",
                                                      os.environ["SERVER"],
                                                      self.zone, "testrecord",
                                                      dnstype, record,
                                                      self.creds_string)
                    self.assertCmdFail(result, "Successfully added invalid"
                                       "record '%s' of type '%s'."
                                       % (record, dnstype))
                except AssertionError as e:
                    num_failures = num_failures + 1
                    failure_msgs.append(e)
                    self.resetZone()
                try:
                    result, out, err = self.runsubcmd("dns", "delete",
                                                      os.environ["SERVER"],
                                                      self.zone, "testrecord",
                                                      dnstype, record,
                                                      self.creds_string)
                    self.assertCmdFail(result, "Successfully deleted invalid"
                                       "record '%s' of type '%s' which"
                                       "shouldn't exist." % (record, dnstype))
                except AssertionError as e:
                    num_failures = num_failures + 1
                    failure_msgs.append(e)
                    self.resetZone()

        # Update valid records to invalid ones and make sure they
        # fail to be updated
        for dnstype in self.bad_records:
            for bad_record in self.bad_records[dnstype]:
                good_record = self.good_records[dnstype][0]

                try:
                    result, out, err = self.runsubcmd("dns", "add",
                                                      os.environ["SERVER"],
                                                      self.zone, "testrecord",
                                                      dnstype, good_record,
                                                      self.creds_string)
                    self.assertCmdSuccess(result, out, err, "Failed to add "
                                          "record '%s' with type %s."
                                          % (record, dnstype))

                    result, out, err = self.runsubcmd("dns", "update",
                                                      os.environ["SERVER"],
                                                      self.zone, "testrecord",
                                                      dnstype, good_record,
                                                      bad_record,
                                                      self.creds_string)
                    self.assertCmdFail(result, "Successfully updated valid "
                                       "record '%s' of type '%s' to invalid "
                                       "record '%s' of the same type."
                                       % (good_record, dnstype, bad_record))

                    result, out, err = self.runsubcmd("dns", "delete",
                                                      os.environ["SERVER"],
                                                      self.zone, "testrecord",
                                                      dnstype, good_record,
                                                      self.creds_string)
                    self.assertCmdSuccess(result, out, err, "Could not delete "
                                          "valid record '%s' of type '%s'."
                                          % (good_record, dnstype))
                except AssertionError as e:
                    num_failures = num_failures + 1
                    failure_msgs.append(e)
                    self.resetZone()

        if num_failures > 0:
            for msg in failure_msgs:
                print(msg)
            self.fail("Failed to reject invalid commands. %d total failures. "
                      "Errors above." % num_failures)

    def test_update_invalid_type(self):
        """Make sure that a record can't be updated to another type leaving
        the data the same, where that data would be incompatible with
        the new type. This is not always enforced at the C level.

        We don't try with all types, because many types are compatible
        in their representations (e.g. A records could be TXT or CNAME
        records; PTR record values are exactly the same as CNAME
        record values, etc).
        """
        dnstypes = ('A', 'AAAA', 'SRV')
        for dnstype1 in dnstypes:
            record1 = self.good_records[dnstype1][0]
            result, out, err = self.runsubcmd("dns", "add",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              dnstype1, record1,
                                              self.creds_string)
            self.assertCmdSuccess(result, out, err, "Failed to add "
                                  "record %s with type %s."
                                  % (record1, dnstype1))

            for dnstype2 in dnstypes:
                if dnstype1 == dnstype2:
                    continue

                record2 = self.good_records[dnstype2][0]

                # Check both ways: Give the current type and try to update,
                # and give the new type and try to update.
                result, out, err = self.runsubcmd("dns", "update",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype1, record1,
                                                  record2, self.creds_string)
                self.assertCmdFail(result, "Successfully updated record '%s' "
                                   "to '%s', even though the latter is of "
                                   "type '%s' where '%s' was expected."
                                   % (record1, record2, dnstype2, dnstype1))

                result, out, err = self.runsubcmd("dns", "update",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype2, record1, record2,
                                                  self.creds_string)
                self.assertCmdFail(result, "Successfully updated record "
                                   "'%s' to '%s', even though the former "
                                   "is of type '%s' where '%s' was expected."
                                   % (record1, record2, dnstype1, dnstype2))

    def test_update_valid_type(self):
        for dnstype in self.good_records:
            for record in self.good_records[dnstype]:
                result, out, err = self.runsubcmd("dns", "add",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype, record,
                                                  self.creds_string)
                self.assertCmdSuccess(result, out, err, "Failed to add "
                                      "record %s with type %s."
                                      % (record, dnstype))

                if record == '.' and dnstype != 'TXT':
                    # This will fail because the update finds a match
                    # for "." that is actually "" (in
                    # dns_record_match()), then uses the "" record in
                    # a call to dns_to_dnsp_convert() which calls
                    # dns_name_check() which rejects "" as a bad DNS
                    # name. Maybe FIXME, maybe not.
                    continue

                # Update the record to be the same.
                result, out, err = self.runsubcmd("dns", "update",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype, record, record,
                                                  self.creds_string)
                self.assertCmdSuccess(result, out, err,
                                      "Could not update record "
                                      "'%s' to be exactly the same." % record)

                result, out, err = self.runsubcmd("dns", "delete",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype, record,
                                                  self.creds_string)
                self.assertCmdSuccess(result, out, err, "Could not delete "
                                      "valid record '%s' of type '%s'."
                                      % (record, dnstype))

        for record in self.good_records["SRV"]:
            result, out, err = self.runsubcmd("dns", "add",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              "SRV", record,
                                              self.creds_string)
            self.assertCmdSuccess(result, out, err, "Failed to add "
                                  "record %s with type 'SRV'." % record)

            split = record.split()
            new_bit = str(int(split[3]) + 1)
            new_record = '%s %s %s %s' % (split[0], split[1], split[2], new_bit)

            result, out, err = self.runsubcmd("dns", "update",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              "SRV", record,
                                              new_record, self.creds_string)
            self.assertCmdSuccess(result, out, err, "Failed to update record "
                                  "'%s' of type '%s' to '%s'."
                                  % (record, "SRV", new_record))

            result, out, err = self.runsubcmd("dns", "query",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              "SRV", self.creds_string)
            self.assertCmdSuccess(result, out, err, "Failed to query for "
                                  "record '%s' of type '%s'."
                                  % (new_record, "SRV"))

            result, out, err = self.runsubcmd("dns", "delete",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              "SRV", new_record,
                                              self.creds_string)
            self.assertCmdSuccess(result, out, err, "Could not delete "
                                  "valid record '%s' of type '%s'."
                                  % (new_record, "SRV"))

        # Since 'dns update' takes the current value as a parameter, make sure
        # we can't enter the wrong current value for a given record.
        for dnstype in self.good_records:
            if len(self.good_records[dnstype]) < 3:
                continue  # Not enough records of this type to do this test

            used_record = self.good_records[dnstype][0]
            unused_record = self.good_records[dnstype][1]
            new_record = self.good_records[dnstype][2]

            result, out, err = self.runsubcmd("dns", "add",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              dnstype, used_record,
                                              self.creds_string)
            self.assertCmdSuccess(result, out, err, "Failed to add record %s "
                                  "with type %s." % (used_record, dnstype))

            result, out, err = self.runsubcmd("dns", "update",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              dnstype, unused_record,
                                              new_record,
                                              self.creds_string)
            self.assertCmdFail(result, "Successfully updated record '%s' "
                               "from '%s' to '%s', even though the given "
                               "source record is incorrect."
                               % (used_record, unused_record, new_record))

    def test_invalid_types(self):
        result, out, err = self.runsubcmd("dns", "add",
                                          os.environ["SERVER"],
                                          self.zone, "testrecord",
                                          "SOA", "test",
                                          self.creds_string)
        self.assertCmdFail(result, "Successfully added record of type SOA, "
                           "when this type should not be available.")
        self.assertTrue("type SOA is not supported" in err,
                        "Invalid error message '%s' when attempting to "
                        "add record of type SOA." % err)

    def test_add_overlapping_different_type(self):
        """
        Make sure that we can add an entry with the same name as an existing one but a different type.
        """

        i = 0
        for dnstype1 in self.good_records:
            record1 = self.good_records[dnstype1][0]
            for dnstype2 in self.good_records:
                # Only do some subset of dns types, otherwise it takes a long time.
                i += 1
                if i % 4 != 0:
                    continue

                if dnstype1 == dnstype2:
                    continue

                record2 = self.good_records[dnstype2][0]

                result, out, err = self.runsubcmd("dns", "add",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype1, record1,
                                                  self.creds_string)
                self.assertCmdSuccess(result, out, err, "Failed to add record "
                                      "'%s' of type '%s'." % (record1, dnstype1))

                result, out, err = self.runsubcmd("dns", "add",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype2, record2,
                                                  self.creds_string)
                self.assertCmdSuccess(result, out, err, "Failed to add record "
                                      "'%s' of type '%s' when a record '%s' "
                                      "of type '%s' with the same name exists."
                                      % (record1, dnstype1, record2, dnstype2))

                result, out, err = self.runsubcmd("dns", "query",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype1, self.creds_string)
                self.assertCmdSuccess(result, out, err, "Failed to query for "
                                      "record '%s' of type '%s' when a new "
                                      "record '%s' of type '%s' with the same "
                                      "name was added."
                                      % (record1, dnstype1, record2, dnstype2))

                result, out, err = self.runsubcmd("dns", "query",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype2, self.creds_string)
                self.assertCmdSuccess(result, out, err, "Failed to query "
                                      "record '%s' of type '%s' which should "
                                      "have been added with the same name as "
                                      "record '%s' of type '%s'."
                                      % (record2, dnstype2, record1, dnstype1))

                result, out, err = self.runsubcmd("dns", "delete",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype1, record1,
                                                  self.creds_string)
                self.assertCmdSuccess(result, out, err, "Failed to delete "
                                      "record '%s' of type '%s'."
                                      % (record1, dnstype1))

                result, out, err = self.runsubcmd("dns", "delete",
                                                  os.environ["SERVER"],
                                                  self.zone, "testrecord",
                                                  dnstype2, record2,
                                                  self.creds_string)
                self.assertCmdSuccess(result, out, err, "Failed to delete "
                                      "record '%s' of type '%s'."
                                      % (record2, dnstype2))

    def test_query_deleted_record(self):
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       "testrecord", "A", self.testip, self.creds_string)
        self.runsubcmd("dns", "delete", os.environ["SERVER"], self.zone,
                       "testrecord", "A", self.testip, self.creds_string)

        result, out, err = self.runsubcmd("dns", "query",
                                          os.environ["SERVER"],
                                          self.zone, "testrecord",
                                          "A", self.creds_string)
        self.assertCmdFail(result)

    def test_add_duplicate_record(self):
        for record_type in self.good_records:
            result, out, err = self.runsubcmd("dns", "add",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              record_type,
                                              self.good_records[record_type][0],
                                              self.creds_string)
            self.assertCmdSuccess(result, out, err)
            result, out, err = self.runsubcmd("dns", "add",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              record_type,
                                              self.good_records[record_type][0],
                                              self.creds_string)
            self.assertCmdFail(result)
            # Now we repeat the second add with --allow-existing,
            # which should not complain.
            result, out, err = self.runsubcmd("dns", "add",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              record_type,
                                              self.good_records[record_type][0],
                                              self.creds_string,
                                              "--allow-existing",
                                              catch_error=True)
            self.assertCmdSuccess(result, out, err)
            self.assertIn("Record already exists", out)

            result, out, err = self.runsubcmd("dns", "query",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              record_type, self.creds_string)
            self.assertCmdSuccess(result, out, err)
            result, out, err = self.runsubcmd("dns", "delete",
                                              os.environ["SERVER"],
                                              self.zone, "testrecord",
                                              record_type,
                                              self.good_records[record_type][0],
                                              self.creds_string)
            self.assertCmdSuccess(result, out, err)

    def test_remove_deleted_record(self):
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       "testrecord", "A", self.testip, self.creds_string)
        self.runsubcmd("dns", "delete", os.environ["SERVER"], self.zone,
                       "testrecord", "A", self.testip, self.creds_string)

        # Attempting to delete a record that has already been deleted or has never existed should fail
        result, out, err = self.runsubcmd("dns", "delete",
                                          os.environ["SERVER"],
                                          self.zone, "testrecord",
                                          "A", self.testip, self.creds_string)
        self.assertCmdFail(result)
        result, out, err = self.runsubcmd("dns", "query",
                                          os.environ["SERVER"],
                                          self.zone, "testrecord",
                                          "A", self.creds_string)
        self.assertCmdFail(result)
        result, out, err = self.runsubcmd("dns", "delete",
                                          os.environ["SERVER"],
                                          self.zone, "testrecord2",
                                          "A", self.testip, self.creds_string)
        self.assertCmdFail(result)

    def test_cleanup_record(self):
        """
        Test dns cleanup command is working fine.
        """

        # add a A record
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'testa', "A", self.testip, self.creds_string)

        # the above A record points to this host
        dnshostname = '{0}.{1}'.format('testa', self.zone.lower())

        # add a CNAME record points to above host
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'testcname', "CNAME", dnshostname, self.creds_string)

        # add a NS record
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'testns', "NS", dnshostname, self.creds_string)

        # add a PTR record points to above host
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'testptr', "PTR", dnshostname, self.creds_string)

        # add a SRV record points to above host
        srv_record = "{0} 65530 65530 65530".format(dnshostname)
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'testsrv', "SRV", srv_record, self.creds_string)

        # cleanup record for this dns host
        self.runsubcmd("dns", "cleanup", os.environ["SERVER"],
                       dnshostname, self.creds_string)

        # all records should be marked as dNSTombstoned
        for record_name in ['testa', 'testcname', 'testns', 'testptr', 'testsrv']:

            records = self.samdb.search(
                base="DC=DomainDnsZones,{0}".format(self.samdb.get_default_basedn()),
                scope=ldb.SCOPE_SUBTREE,
                expression="(&(objectClass=dnsNode)(name={0}))".format(record_name),
                attrs=["dNSTombstoned"])

            self.assertEqual(len(records), 1)
            for record in records:
                self.assertEqual(str(record['dNSTombstoned']), 'TRUE')

    def test_cleanup_record_no_A_record(self):
        """
        Test dns cleanup command works with no A record.
        """

        # add a A record
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'notesta', "A", self.testip, self.creds_string)

        # the above A record points to this host
        dnshostname = '{0}.{1}'.format('testa', self.zone.lower())

        # add a CNAME record points to above host
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'notestcname', "CNAME", dnshostname, self.creds_string)

        # add a NS record
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'notestns', "NS", dnshostname, self.creds_string)

        # add a PTR record points to above host
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'notestptr', "PTR", dnshostname, self.creds_string)

        # add a SRV record points to above host
        srv_record = "{0} 65530 65530 65530".format(dnshostname)
        self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                       'notestsrv', "SRV", srv_record, self.creds_string)

        # Remove the initial A record (leading to hanging references)
        self.runsubcmd("dns", "delete", os.environ["SERVER"], self.zone,
                       'notesta', "A", self.testip, self.creds_string)

        # cleanup record for this dns host
        self.runsubcmd("dns", "cleanup", os.environ["SERVER"],
                       dnshostname, self.creds_string)

        # all records should be marked as dNSTombstoned
        for record_name in ['notestcname', 'notestns', 'notestptr', 'notestsrv']:

            records = self.samdb.search(
                base="DC=DomainDnsZones,{0}".format(self.samdb.get_default_basedn()),
                scope=ldb.SCOPE_SUBTREE,
                expression="(&(objectClass=dnsNode)(name={0}))".format(record_name),
                attrs=["dNSTombstoned"])

            self.assertEqual(len(records), 1)
            for record in records:
                self.assertEqual(str(record['dNSTombstoned']), 'TRUE')

    def test_cleanup_multi_srv_record(self):
        """
        Test dns cleanup command for multi-valued SRV record.

        Steps:
        - Add 2 A records host1 and host2
        - Add a SRV record srv1 and points to both host1 and host2
        - Run cleanup command for host1
        - Check records for srv1, data for host1 should be gone and host2 is kept.
        """

        hosts = ['host1', 'host2']  # A record names
        srv_name = 'srv1'

        # add A records
        for host in hosts:
            self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                           host, "A", self.testip, self.creds_string)

            # the above A record points to this host
            dnshostname = '{0}.{1}'.format(host, self.zone.lower())

            # add a SRV record points to above host
            srv_record = "{0} 65530 65530 65530".format(dnshostname)
            self.runsubcmd("dns", "add", os.environ["SERVER"], self.zone,
                           srv_name, "SRV", srv_record, self.creds_string)

        records = self.samdb.search(
            base="DC=DomainDnsZones,{0}".format(self.samdb.get_default_basedn()),
            scope=ldb.SCOPE_SUBTREE,
            expression="(&(objectClass=dnsNode)(name={0}))".format(srv_name),
            attrs=['dnsRecord'])
        # should have 2 records here
        self.assertEqual(len(records[0]['dnsRecord']), 2)

        # cleanup record for dns host1
        dnshostname1 = 'host1.{0}'.format(self.zone.lower())
        self.runsubcmd("dns", "cleanup", os.environ["SERVER"],
                       dnshostname1, self.creds_string)

        records = self.samdb.search(
            base="DC=DomainDnsZones,{0}".format(self.samdb.get_default_basedn()),
            scope=ldb.SCOPE_SUBTREE,
            expression="(&(objectClass=dnsNode)(name={0}))".format(srv_name),
            attrs=['dnsRecord', 'dNSTombstoned'])

        # dnsRecord for host1 should be deleted
        self.assertEqual(len(records[0]['dnsRecord']), 1)

        # unpack data
        dns_record_bin = records[0]['dnsRecord'][0]
        dns_record_obj = ndr_unpack(dnsp.DnssrvRpcRecord, dns_record_bin)

        # dnsRecord for host2 is still there and is the only one
        dnshostname2 = 'host2.{0}'.format(self.zone.lower())
        self.assertEqual(dns_record_obj.data.nameTarget, dnshostname2)

        # assert that the record isn't spuriously tombstoned
        self.assertTrue('dNSTombstoned' not in records[0] or
                        str(records[0]['dNSTombstoned']) == 'FALSE')

    def test_dns_wildcards(self):
        """
        Ensure that DNS wild card entries can be added deleted and queried
        """
        num_failures = 0
        failure_msgs = []
        records = [("*.", "MISS", "A", "1.1.1.1"),
                   ("*.SAMDOM", "MISS.SAMDOM", "A", "1.1.1.2")]
        for (name, miss, dnstype, record) in records:
            try:
                result, out, err = self.runsubcmd("dns", "add",
                                                  os.environ["SERVER"],
                                                  self.zone, name,
                                                  dnstype, record,
                                                  self.creds_string)
                self.assertCmdSuccess(
                    result,
                    out,
                    err,
                    ("Failed to add record %s (%s) with type %s."
                     % (name, record, dnstype)))

                result, out, err = self.runsubcmd("dns", "query",
                                                  os.environ["SERVER"],
                                                  self.zone, name,
                                                  dnstype,
                                                  self.creds_string)
                self.assertCmdSuccess(
                    result,
                    out,
                    err,
                    ("Failed to query record %s with qualifier %s."
                     % (record, dnstype)))

                # dns tool does not perform dns wildcard search if the name
                # does not match
                result, out, err = self.runsubcmd("dns", "query",
                                                  os.environ["SERVER"],
                                                  self.zone, miss,
                                                  dnstype,
                                                  self.creds_string)
                self.assertCmdFail(
                    result,
                    ("Failed to query record %s with qualifier %s."
                     % (record, dnstype)))

                result, out, err = self.runsubcmd("dns", "delete",
                                                  os.environ["SERVER"],
                                                  self.zone, name,
                                                  dnstype, record,
                                                  self.creds_string)
                self.assertCmdSuccess(
                    result,
                    out,
                    err,
                    ("Failed to remove record %s with type %s."
                     % (record, dnstype)))
            except AssertionError as e:
                num_failures = num_failures + 1
                failure_msgs.append(e)

        if num_failures > 0:
            for msg in failure_msgs:
                print(msg)
            self.fail("Failed to accept valid commands. %d total failures."
                      "Errors above." % num_failures)

    def test_serverinfo(self):
        for v in ['w2k', 'dotnet', 'longhorn']:
            result, out, err = self.runsubcmd("dns",
                                              "serverinfo",
                                              "--client-version", v,
                                              os.environ["SERVER"],
                                              self.creds_string)
            self.assertCmdSuccess(result,
                                  out,
                                  err,
                                  "Failed to print serverinfo with "
                                  "client version %s" % v)
            self.assertTrue(out != '')

    def test_zoneinfo(self):
        result, out, err = self.runsubcmd("dns",
                                          "zoneinfo",
                                          os.environ["SERVER"],
                                          self.zone,
                                          self.creds_string)
        self.assertCmdSuccess(result,
                              out,
                              err,
                              "Failed to print zoneinfo")
        self.assertTrue(out != '')

    def test_zoneoptions_aging(self):
        for options, vals, error in (
                (['--aging=1'], {'fAging': 'TRUE'}, False),
                (['--aging=0'], {'fAging': 'FALSE'}, False),
                (['--aging=-1'], {'fAging': 'FALSE'}, True),
                (['--aging=2'], {}, True),
                (['--aging=2', '--norefreshinterval=1'], {}, True),
                (['--aging=1', '--norefreshinterval=1'],
                 {'fAging': 'TRUE', 'dwNoRefreshInterval': '1'}, False),
                (['--aging=1', '--norefreshinterval=0'],
                 {'fAging': 'TRUE', 'dwNoRefreshInterval': '0'}, False),
                (['--aging=0', '--norefreshinterval=99', '--refreshinterval=99'],
                 {'fAging': 'FALSE',
                  'dwNoRefreshInterval': '99',
                  'dwRefreshInterval': '99'}, False),
                (['--aging=0', '--norefreshinterval=-99', '--refreshinterval=99'],
                 {}, True),
                (['--refreshinterval=9999999'], {}, True),
                (['--norefreshinterval=9999999'], {}, True),
                ):
            result, out, err = self.runsubcmd("dns",
                                              "zoneoptions",
                                              os.environ["SERVER"],
                                              self.zone,
                                              self.creds_string,
                                              *options)
            if error:
                self.assertCmdFail(result, "zoneoptions should fail")
            else:
                self.assertCmdSuccess(result,
                                      out,
                                      err,
                                      "zoneoptions shouldn't fail")


            info_r, info_out, info_err = self.runsubcmd("dns",
                                                        "zoneinfo",
                                                        os.environ["SERVER"],
                                                        self.zone,
                                                        self.creds_string)

            self.assertCmdSuccess(info_r,
                                  info_out,
                                  info_err,
                                  "zoneinfo shouldn't fail after zoneoptions")

            info = {k: v for k, v in re.findall(r'^\s*(\w+)\s*:\s*(\w+)\s*$',
                                                info_out,
                                                re.MULTILINE)}
            for k, v in vals.items():
                self.assertIn(k, info)
                self.assertEqual(v, info[k])


    def ldap_add_node_with_records(self, name, records):
        dn = (f"DC={name},DC={self.zone},CN=MicrosoftDNS,DC=DomainDNSZones,"
              f"{self.samdb.get_default_basedn()}")

        dns_records = []
        for r in records:
            rec = dnsp.DnssrvRpcRecord()
            rec.wType = r.get('wType', dnsp.DNS_TYPE_A)
            rec.rank = dnsp.DNS_RANK_ZONE
            rec.dwTtlSeconds = 900
            rec.dwTimeStamp = r.get('dwTimeStamp', 0)
            rec.data = r.get('data', '10.10.10.10')
            dns_records.append(ndr_pack(rec))

        msg = ldb.Message.from_dict(self.samdb,
                                    {'dn': dn,
                                     "objectClass": ["top", "dnsNode"],
                                     'dnsRecord': dns_records
                                    })
        self.samdb.add(msg)

    def get_timestamp_map(self):
        re_wtypes = (dnsp.DNS_TYPE_A,
                     dnsp.DNS_TYPE_AAAA,
                     dnsp.DNS_TYPE_TXT)

        t = time.time()
        now = dsdb_dns.unix_to_dns_timestamp(int(t))

        records = self.get_all_records(self.zone)
        tsmap = {}
        for k, recs in records.items():
            m = []
            tsmap[k] = m
            for rec in recs:
                r = ndr_unpack(dnsp.DnssrvRpcRecord, rec)
                timestamp = r.dwTimeStamp
                if abs(timestamp - now) < 3:
                    timestamp = 'nowish'

                if r.wType in re_wtypes:
                    m.append(('R', timestamp))
                else:
                    m.append(('-', timestamp))

        return tsmap


    def test_zoneoptions_mark_records(self):
        self.maxDiff = 10000
        # We need a number of records to work with, so we'll use part
        # of our known good records list, using three different names
        # to test the regex. All these records will be static.
        for dnstype in self.good_records:
            for record in self.good_records[dnstype][:2]:
                self.runsubcmd("dns", "add",
                               os.environ["SERVER"],
                               self.zone, "frobitz",
                               dnstype, record,
                               self.creds_string)
                self.runsubcmd("dns", "add",
                               os.environ["SERVER"],
                               self.zone, "weergly",
                               dnstype, record,
                               self.creds_string)
                self.runsubcmd("dns", "add",
                               os.environ["SERVER"],
                               self.zone, "snizle",
                               dnstype, record,
                               self.creds_string)

        # and we also want some that aren't static, and some mixed
        # static/dynamic records.
        # timestamps are in hours since 1601; now ~= 3.7 million
        for ts in (0, 100, 10 ** 6, 10 ** 7):
            name = f"ts-{ts}"
            self.ldap_add_node_with_records(name, [{"dwTimeStamp": ts}])

        recs = []
        for ts in (0, 100, 10 ** 6, 10 ** 7):
            addr = f'10.{(ts >> 16) & 255}.{(ts >> 8) & 255}.{ts & 255}'
            recs.append({"dwTimeStamp": ts, "data": addr})

        self.ldap_add_node_with_records("ts-multi", recs)

        # get the state of ALL records.
        # then we make assertions about the diffs, keeping track of
        # the current state.

        tsmap = self.get_timestamp_map()



        for options, diff, output_substrings, error in (
                # --mark-old-records-static
                # --mark-records-static-regex
                # --mark-records-dynamic-regex
                (
                    ['--mark-old-records-static=1971-13-04'],
                    {},
                    [],
                    "bad date"
                ),
                (
                    # using --dry-run, should be no change, but output.
                    ['--mark-old-records-static=1971-03-04', '--dry-run'],
                    {},
                    [
                        "would make 1/1 records static on ts-1000000.zone.",
                        "would make 1/1 records static on ts-100.zone.",
                        "would make 2/4 records static on ts-multi.zone.",
                    ],
                    False
                ),
                (
                    # timestamps < ~ 3.25 million are now static
                    ['--mark-old-records-static=1971-03-04'],
                    {
                        'ts-100': [('R', 0)],
                        'ts-1000000': [('R', 0)],
                        'ts-multi': [('R', 0), ('R', 0), ('R', 0), ('R', 10000000)]
                    },
                    [
                        "made 1/1 records static on ts-1000000.zone.",
                        "made 1/1 records static on ts-100.zone.",
                        "made 2/4 records static on ts-multi.zone.",
                    ],
                    False
                ),
                (
                    # no change, old records already static
                    ['--mark-old-records-static=1972-03-04'],
                    {},
                    [],
                    False
                ),
                (
                    # no change, samba-tool added records already static
                    ['--mark-records-static-regex=sniz'],
                    {},
                    [],
                    False
                ),
                (
                    # snizle has 2 A, 2 AAAA, 10 fancy, and 2 TXT records, in
                    # that order.
                    # the A, AAAA, and TXT records should be dynamic
                    ['--mark-records-dynamic-regex=sniz'],
                    {'snizle': [('R', 'nowish'),
                                ('R', 'nowish'),
                                ('R', 'nowish'),
                                ('R', 'nowish'),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('R', 'nowish'),
                                ('R', 'nowish')]
                    },
                    ['made 6/16 records dynamic on snizle.zone.'],
                    False
                ),
                (
                    # This regex should catch snizle, weergly, and ts-*
                    # but we're doing dry-run so no change
                    ['--mark-records-dynamic-regex=[sw]', '-n'],
                    {},
                    ['would make 3/4 records dynamic on ts-multi.zone.',
                     'would make 1/1 records dynamic on ts-0.zone.',
                     'would make 1/1 records dynamic on ts-1000000.zone.',
                     'would make 6/16 records dynamic on weergly.zone.',
                     'would make 1/1 records dynamic on ts-100.zone.'
                    ],
                    False
                ),
                (
                    # This regex should catch snizle and frobitz
                    # but snizle has already been changed.
                    ['--mark-records-dynamic-regex=z'],
                    {'frobitz': [('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('R', 'nowish'),
                                 ('R', 'nowish')]
                    },
                    ['made 6/16 records dynamic on frobitz.zone.'],
                    False
                ),
                (
                    # This regex should catch snizle, frobitz, and
                    # ts-multi. Note that the 1e7 ts-multi record is
                    # already dynamic and doesn't change.
                    ['--mark-records-dynamic-regex=[i]'],
                    {'ts-multi': [('R', 'nowish'),
                                  ('R', 'nowish'),
                                  ('R', 'nowish'),
                                  ('R', 10000000)]
                    },
                    ['made 3/4 records dynamic on ts-multi.zone.'],
                    False
                ),
                (
                    # matches no records
                    ['--mark-records-dynamic-regex=^aloooooo[qw]+'],
                    {},
                    [],
                    False
                ),
                (
                    # This should be an error, as only one --mark-*
                    # argument is allowed at a time
                    ['--mark-records-dynamic-regex=.',
                     '--mark-records-static-regex=.',
                    ],
                    {},
                    [],
                    True
                ),
                (
                    # This should also be an error
                    ['--mark-old-records-static=1997-07-07',
                     '--mark-records-static-regex=.',
                    ],
                    {},
                    [],
                    True
                ),
                (
                    # This should not be an error. --aging and refresh
                    # options can be mixed with --mark ones.
                    ['--mark-old-records-static=1997-07-07',
                     '--aging=0',
                    ],
                    {},
                    ['Set Aging to 0'],
                    False
                ),
                (
                    # This regex should catch weergly, but all the
                    # records are already static,
                    ['--mark-records-static-regex=wee'],
                    {},
                    [],
                    False
                ),
                (
                    # Make frobitz static again.
                    ['--mark-records-static-regex=obi'],
                    {'frobitz': [('R', 0),
                                 ('R', 0),
                                 ('R', 0),
                                 ('R', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('R', 0),
                                 ('R', 0)]
                    },
                    ['made 6/16 records static on frobitz.zone.'],
                    False
                ),
                (
                    # would make almost everything static, but --dry-run
                    ['--mark-old-records-static=2222-03-04', '--dry-run'],
                    {},
                    [
                        'would make 6/16 records static on snizle.zone.',
                        'would make 3/4 records static on ts-multi.zone.'
                    ],
                    False
                ),
                (
                    # make everything static
                    ['--mark-records-static-regex=.'],
                     {'snizle': [('R', 0),
                                 ('R', 0),
                                 ('R', 0),
                                 ('R', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('R', 0),
                                 ('R', 0)],
                      'ts-10000000': [('R', 0)],
                      'ts-multi': [('R', 0), ('R', 0), ('R', 0), ('R', 0)]
                     },
                    [
                        'made 4/4 records static on ts-multi.zone.',
                        'made 1/1 records static on ts-10000000.zone.',
                        'made 6/16 records static on snizle.zone.',
                    ],
                    False
                ),
                (
                    # make everything dynamic that can be
                    ['--mark-records-dynamic-regex=.'],
                    {'frobitz': [('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('R', 'nowish'),
                                 ('R', 'nowish')],
                     'snizle': [('R', 'nowish'),
                                ('R', 'nowish'),
                                ('R', 'nowish'),
                                ('R', 'nowish'),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('-', 0),
                                ('R', 'nowish'),
                                ('R', 'nowish')],
                     'ts-0': [('R', 'nowish')],
                     'ts-100': [('R', 'nowish')],
                     'ts-1000000': [('R', 'nowish')],
                     'ts-10000000': [('R', 'nowish')],
                     'ts-multi': [('R', 'nowish'),
                                  ('R', 'nowish'),
                                  ('R', 'nowish'),
                                  ('R', 'nowish')],
                     'weergly': [('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('R', 'nowish'),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('-', 0),
                                 ('R', 'nowish'),
                                 ('R', 'nowish')]
                    },
                    [
                        'made 4/4 records dynamic on ts-multi.zone.',
                        'made 6/16 records dynamic on snizle.zone.',
                        'made 1/1 records dynamic on ts-0.zone.',
                        'made 1/1 records dynamic on ts-1000000.zone.',
                        'made 1/1 records dynamic on ts-10000000.zone.',
                        'made 1/1 records dynamic on ts-100.zone.',
                        'made 6/16 records dynamic on frobitz.zone.',
                        'made 6/16 records dynamic on weergly.zone.',
                    ],
                    False
                ),
            ):
            result, out, err = self.runsubcmd("dns",
                                              "zoneoptions",
                                              os.environ["SERVER"],
                                              self.zone,
                                              self.creds_string,
                                              *options)
            if error:
                self.assertCmdFail(result, f"zoneoptions should fail ({error})")
            else:
                self.assertCmdSuccess(result,
                                      out,
                                      err,
                                      "zoneoptions shouldn't fail")

            new_tsmap = self.get_timestamp_map()

            # same keys, always
            self.assertEqual(sorted(new_tsmap), sorted(tsmap))
            changes = {}
            for k in tsmap:
                if tsmap[k] != new_tsmap[k]:
                    changes[k] = new_tsmap[k]

            self.assertEqual(diff, changes)

            for s in output_substrings:
                self.assertIn(s, out)
            tsmap = new_tsmap

    def test_zonecreate_dns_domain_directory_partition(self):
        zone = "test-dns-domain-dp-zone"
        dns_dp_opt = "--dns-directory-partition=domain"

        result, out, err = self.runsubcmd("dns",
                                          "zonecreate",
                                          os.environ["SERVER"],
                                          zone,
                                          self.creds_string,
                                          dns_dp_opt)
        self.assertCmdSuccess(result,
                              out,
                              err,
                              "Failed to create zone with "
                              "--dns-directory-partition option")
        self.assertTrue('Zone %s created successfully' % zone in out,
                        "Unexpected output: %s")

        result, out, err = self.runsubcmd("dns",
                                          "zoneinfo",
                                          os.environ["SERVER"],
                                          zone,
                                          self.creds_string)
        self.assertCmdSuccess(result, out, err)
        self.assertTrue("DNS_DP_DOMAIN_DEFAULT" in out,
                        "Missing DNS_DP_DOMAIN_DEFAULT flag")

        result, out, err = self.runsubcmd("dns",
                                          "zonedelete",
                                          os.environ["SERVER"],
                                          zone,
                                          self.creds_string)
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete zone in domain DNS directory "
                              "partition")
        result, out, err = self.runsubcmd("dns",
                                          "zonelist",
                                          os.environ["SERVER"],
                                          self.creds_string)
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete zone in domain DNS directory "
                              "partition")
        self.assertTrue(zone not in out,
                        "Deleted zone still exists")

    def test_zonecreate_dns_forest_directory_partition(self):
        zone = "test-dns-forest-dp-zone"
        dns_dp_opt = "--dns-directory-partition=forest"

        result, out, err = self.runsubcmd("dns",
                                          "zonecreate",
                                          os.environ["SERVER"],
                                          zone,
                                          self.creds_string,
                                          dns_dp_opt)
        self.assertCmdSuccess(result,
                              out,
                              err,
                              "Failed to create zone with "
                              "--dns-directory-partition option")
        self.assertTrue('Zone %s created successfully' % zone in out,
                        "Unexpected output: %s")

        result, out, err = self.runsubcmd("dns",
                                          "zoneinfo",
                                          os.environ["SERVER"],
                                          zone,
                                          self.creds_string)
        self.assertCmdSuccess(result, out, err)
        self.assertTrue("DNS_DP_FOREST_DEFAULT" in out,
                        "Missing DNS_DP_FOREST_DEFAULT flag")

        result, out, err = self.runsubcmd("dns",
                                          "zonedelete",
                                          os.environ["SERVER"],
                                          zone,
                                          self.creds_string)
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete zone in forest DNS directory "
                              "partition")

        result, out, err = self.runsubcmd("dns",
                                          "zonelist",
                                          os.environ["SERVER"],
                                          self.creds_string)
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete zone in forest DNS directory "
                              "partition")
        self.assertTrue(zone not in out,
                        "Deleted zone still exists")

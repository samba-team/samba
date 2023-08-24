# Unix SMB/CIFS implementation.
# Copyright (C) Kai Blin  <kai@samba.org> 2011
# Copyright (C) Catalyst.NET 2021
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
from samba import dsdb
from samba import dsdb_dns
from samba.ndr import ndr_unpack, ndr_pack
from samba.samdb import SamDB
from samba.auth import system_session
import ldb
from samba import credentials
from samba.dcerpc import dns, dnsp, dnsserver
from samba.dnsserver import TXTRecord, ARecord
from samba.dnsserver import ipv6_normalise
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba import werror, WERRORError
from samba.tests.dns_base import DNSTest
import samba.getopt as options
import optparse
import time
from samba.colour import c_RED, c_GREEN, c_DARK_YELLOW

parser = optparse.OptionParser(
    "dns_aging.py <server name> <server ip> [options]")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)


# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()
if len(args) < 2:
    parser.print_usage()
    sys.exit(1)

LP = sambaopts.get_loadparm()
CREDS = credopts.get_credentials(LP)
SERVER_NAME = args[0]
SERVER_IP = args[1]
CREDS.set_krb_forwardable(credentials.NO_KRB_FORWARDABLE)

DOMAIN = CREDS.get_realm().lower()

# Unix time start, in DNS timestamp (24 * 365.25 * 369)
# These are ballpark extremes for the timestamp.
DNS_TIMESTAMP_1970 = 3234654
DNS_TIMESTAMP_2101 = 4383000
DNS_TIMESTAMP_1981 = 3333333  # a middling timestamp

IPv4_ADDR = "127.0.0.33"
IPv6_ADDR = "::1"
IPv4_ADDR_2 = "127.0.0.66"
IPv6_ADDR_2 = "1::1"


def get_samdb():
    return SamDB(url=f"ldap://{SERVER_IP}",
                 lp=LP,
                 session_info=system_session(),
                 credentials=CREDS)


def get_file_samdb():
    # For Samba only direct file access, needed for the tombstoning functions.
    # (For Windows, we instruct it to tombstone over RPC).
    return SamDB(url=LP.samdb_url(),
                 lp=LP,
                 session_info=system_session(),
                 credentials=CREDS)


def get_rpc():
    return dnsserver.dnsserver(f"ncacn_ip_tcp:{SERVER_IP}[sign]", LP, CREDS)


def create_zone(name, rpc=None, aging=True):
    if rpc is None:
        rpc = get_rpc()
    z = dnsserver.DNS_RPC_ZONE_CREATE_INFO_LONGHORN()
    z.pszZoneName = name
    z.dwZoneType = dnsp.DNS_ZONE_TYPE_PRIMARY
    z.fAging = int(bool(aging))
    z.dwDpFlags = dnsserver.DNS_DP_DOMAIN_DEFAULT
    z.fDsIntegrated = 1
    z.fLoadExisting = 1
    z.fAllowUpdate = dnsp.DNS_ZONE_UPDATE_UNSECURE
    rpc.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                         0,
                         SERVER_IP,
                         None,
                         0,
                         'ZoneCreate',
                         dnsserver.DNSSRV_TYPEID_ZONE_CREATE,
                         z)


def delete_zone(name, rpc=None):
    if rpc is None:
        rpc = get_rpc()
    rpc.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                         0,
                         SERVER_IP,
                         name,
                         0,
                         'DeleteZoneFromDs',
                         dnsserver.DNSSRV_TYPEID_NULL,
                         None)


def txt_s_list(txt):
    """Construct a txt record string list, which is a fiddly matter."""
    if isinstance(txt, str):
        txt = [txt]
    s_list = dnsp.string_list()
    s_list.count = len(txt)
    s_list.str = txt
    return s_list


def make_txt_record(txt):
    r = dns.txt_record()
    r.txt = txt_s_list(txt)
    return r


def copy_rec(rec):
    copy = dnsserver.DNS_RPC_RECORD()
    copy.wType = rec.wType
    copy.dwFlags = rec.dwFlags
    copy.dwSerial = rec.dwSerial
    copy.dwTtlSeconds = rec.dwTtlSeconds
    copy.data = rec.data
    copy.dwTimeStamp = rec.dwTimeStamp
    return copy


def guess_wtype(data):
    if isinstance(data, list):
        data = make_txt_record(data)
        return (data, dnsp.DNS_TYPE_TXT)
    if ":" in data:
        return (data, dnsp.DNS_TYPE_AAAA)
    return (data, dnsp.DNS_TYPE_A)


class TestDNSAging(DNSTest):
    """Probe DNS aging and scavenging, using LDAP and RPC to set and test
    the timestamps behind DNS's back."""
    server = SERVER_NAME
    server_ip = SERVER_IP
    creds = CREDS

    def setUp(self):
        super().setUp()
        self.rpc_conn = get_rpc()
        self.samdb = get_samdb()

        # We always have a zone of our own named after the test function.
        self.zone = self.id().rsplit('.', 1)[1]
        self.addCleanup(delete_zone, self.zone, self.rpc_conn)
        try:
            create_zone(self.zone, self.rpc_conn)
        except WERRORError as e:
            if e.args[0] != werror.WERR_DNS_ERROR_ZONE_ALREADY_EXISTS:
                raise
            print(f"zone {self.zone} already exists")

        # Though we set this in create_zone(), that doesn't work on
        # Windows, so we repeat again here.
        self.set_zone_int_params(AllowUpdate=dnsp.DNS_ZONE_UPDATE_UNSECURE)

        self.zone_dn = (f"DC={self.zone},CN=MicrosoftDNS,DC=DomainDNSZones,"
                        f"{self.samdb.get_default_basedn()}")

    def set_zone_int_params(self, zone=None, **kwargs):
        """Keyword arguments set parameters on the zone. e.g.:

            self.set_zone_int_params(Aging=1,
                                     RefreshInterval=222)

        See [MS-DNSP] 3.1.1.2.1 "DNS Zone Integer Properties" for names.
        """
        if zone is None:
            zone = self.zone
        for key, val in kwargs.items():
            name_param = dnsserver.DNS_RPC_NAME_AND_PARAM()
            name_param.dwParam = val
            name_param.pszNodeName = key
            try:
                self.rpc_conn.DnssrvOperation2(
                    dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                    0,
                    SERVER_IP,
                    zone,
                    0,
                    'ResetDwordProperty',
                    dnsserver.DNSSRV_TYPEID_NAME_AND_PARAM,
                    name_param)
            except WERRORError as e:
                self.fail(str(e))

    def rpc_replace(self, name, old=None, new=None):
        """Replace a DNS_RPC_RECORD or DNS_RPC_RECORD_BUF"""
        # wrap our recs, if necessary
        if isinstance(new, dnsserver.DNS_RPC_RECORD):
            rec = new
            new = dnsserver.DNS_RPC_RECORD_BUF()
            new.rec = rec

        if isinstance(old, dnsserver.DNS_RPC_RECORD):
            rec = old
            old = dnsserver.DNS_RPC_RECORD_BUF()
            old.rec = rec

        try:
            self.rpc_conn.DnssrvUpdateRecord2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                SERVER_IP,
                self.zone,
                name,
                new,
                old)
        except WERRORError as e:
            self.fail(f"could not replace record ({e})")

    def get_unique_txt_record(self, name, txt):
        """Get the TXT record on Name with value txt, asserting that there is
        only one."""
        if isinstance(txt, str):
            txt = [txt]
        recs = self.ldap_get_records(name)

        match = None
        for r in recs:
            if r.wType != dnsp.DNS_TYPE_TXT:
                continue
            txt2 = [x for x in r.data.str]
            if txt2 == txt:
                self.assertIsNone(match)
                match = r
        return match

    def get_unique_ip_record(self, name, addr, wtype=None):
        """Get an A or AAAA record on name with the matching data."""
        if wtype is None:
            addr, wtype = guess_wtype(addr)

        recs = self.ldap_get_records(name)

        # We need to use the internal dns_record_match because not all
        # forms always match on strings (e.g. IPv6)
        rec = dnsp.DnssrvRpcRecord()
        rec.wType = wtype
        rec.data = addr

        match = None
        for r in recs:
            if dsdb_dns.records_match(r, rec):
                self.assertIsNone(match)
                match = r
        return match

    def dns_query(self, name, qtype=dns.DNS_QTYPE_ALL):
        """make a query, which might help Windows notice LDAP changes"""
        p = self.make_name_packet(dns.DNS_OPCODE_QUERY)
        fullname = "%s.%s" % (name, self.zone)
        q = self.make_name_question(fullname, qtype, dns.DNS_QCLASS_IN)
        self.finish_name_packet(p, [q])
        r, rp = self.dns_transaction_udp(p, host=SERVER_IP)

        return r

    def dns_update_non_text(self, name,
                            data,
                            wtype=None,
                            qclass=dns.DNS_QCLASS_IN):
        if wtype is None:
            data, wtype = guess_wtype(data)

        if qclass == dns.DNS_QCLASS_IN:
            ttl = 123
        else:
            ttl = 0

        fullname = "%s.%s" % (name, self.zone)
        p = self.make_name_packet(dns.DNS_OPCODE_UPDATE)
        u = self.make_name_question(self.zone,
                                    dns.DNS_QTYPE_SOA,
                                    dns.DNS_QCLASS_IN)
        self.finish_name_packet(p, [u])

        r = dns.res_rec()
        r.name = fullname
        r.rr_type = wtype
        r.rr_class = qclass
        r.ttl = ttl
        if data is not None:
            r.length = 0xffff
            r.rdata = data
        else:
            r.length = 0

        p.nscount = 1
        p.nsrecs = [r]

        (code, response) = self.dns_transaction_udp(p, host=SERVER_IP)
        self.assert_dns_rcode_equals(code, dns.DNS_RCODE_OK)
        return response

    def dns_delete(self, name, data, wtype=None):
        return self.dns_update_non_text(name,
                                        data,
                                        wtype,
                                        qclass=dns.DNS_QCLASS_NONE)

    def dns_delete_type(self, name, wtype):
        return self.dns_update_non_text(name,
                                        None,
                                        wtype,
                                        qclass=dns.DNS_QCLASS_ANY)

    def dns_update_record(self, name, txt, ttl=900):
        if isinstance(txt, str):
            txt = [txt]
        p = self.make_txt_update(name, txt, self.zone, ttl=ttl)
        (code, response) = self.dns_transaction_udp(p, host=SERVER_IP)
        if code.operation & dns.DNS_RCODE == dns.DNS_RCODE_REFUSED:
            # sometimes you might forget this
            print("\n\ngot DNS_RCODE_REFUSED\n")
            print("Are you running this in the fl2003 environment?\n")
            print("try `SELFTEST_TESTENV='fl2003dc:local' make testenv`\n\n")

        self.assert_dns_rcode_equals(code, dns.DNS_RCODE_OK)
        return self.get_unique_txt_record(name, txt)

    def rpc_update_record(self, name, txt, **kwargs):
        """Add the record that self.dns_update_record() would add, via the
        dnsserver RPC pipe.

        As with DNS update, if the record already exists, we replace it.
        """
        if isinstance(txt, str):
            txt = [txt]

        old = TXTRecord(txt)
        rec = TXTRecord(txt)
        for k, v in kwargs.items():
            setattr(rec, k, v)

        try:
            self.rpc_replace(name, old, rec)
        except AssertionError as e:
            # we have caught and wrapped the WERRor inside
            if 'WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST' not in str(e):
                raise
            self.rpc_replace(name, None, rec)

        return self.get_unique_txt_record(name, txt)

    def rpc_delete_txt(self, name, txt):
        if isinstance(txt, str):
            txt = [txt]
        old = TXTRecord(txt)
        self.rpc_replace(name, old, None)

    def get_one_node(self, name):
        expr = f"(&(objectClass=dnsNode)(name={name}))"
        nodes = self.samdb.search(base=self.zone_dn,
                                  scope=ldb.SCOPE_SUBTREE,
                                  expression=expr,
                                  attrs=["dnsRecord", "dNSTombstoned", "name"])

        if len(nodes) > 1:
            self.fail(
                f"expected 0 or 1 dnsNodes for {name}, found {len(nodes)}")

        if len(nodes) == 0:
            return None
        return nodes[0]

    def ldap_get_records(self, name):
        node = self.get_one_node(name)
        if node is None:
            return []

        records = node.get('dnsRecord')
        return [ndr_unpack(dnsp.DnssrvRpcRecord, r) for r in records]

    def ldap_get_non_tombstoned_records(self, name):
        all_records = self.ldap_get_records(name)
        records = []
        for r in all_records:
            if r.wType != dnsp.DNS_TYPE_TOMBSTONE:
                records.append(r)
        return records

    def assert_tombstoned(self, name, tombstoned=True, timestamp=None):
        # If run with tombstoned=False, assert it isn't tombstoned
        # (and has no traces of tombstone). Otherwise assert it has
        # all the necessary bits.
        #
        # with timestamp=<non-zero number of hours>, we assert that
        # the nttime timestamp is about that time.
        #
        # with timestamp=None, we assert it is within a century or so.
        #
        # with timestamp=False (or 0), we don't assert on it.

        node = self.get_one_node(name)
        if node is None:
            self.fail(f"no node named {name}")

        dnsts = node.get("dNSTombstoned")
        if dnsts is None:
            is_tombstoned = False
        else:
            self.assertEqual(len(dnsts), 1)
            if dnsts[0] == b'TRUE':
                is_tombstoned = True
            else:
                is_tombstoned = False

        if tombstoned != is_tombstoned:
            if is_tombstoned:
                self.fail(f"{name} is tombstoned")
            else:
                self.fail(f"{name} is not tombstoned")

        recs = self.ldap_get_records(name)
        if is_tombstoned:
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0].wType, dnsp.DNS_TYPE_TOMBSTONE)
            if timestamp is None:
                self.assert_nttime_in_hour_range(recs[0].data)
            elif timestamp:
                self.assert_nttime_in_hour_range(recs[0].data,
                                                 timestamp - 3,
                                                 timestamp + 3)

        else:
            for r in recs:
                self.assertNotEqual(recs[0].wType, dnsp.DNS_TYPE_TOMBSTONE)

    def ldap_replace_records(self, name, records):
        # We use raw ldap to avoid the "helpfulness" of dsdb_dns.replace()

        dn = f'DC={name},{self.zone_dn}'

        msg = ldb.Message.from_dict(self.samdb,
                                    {'dn': dn,
                                     'dnsRecord': [ndr_pack(r) for r in records]
                                    },
                                    ldb.FLAG_MOD_REPLACE)

        try:
            self.samdb.modify(msg)
        except ldb.LdbError as e:
            if 'LDAP_NO_SUCH_OBJECT' not in e.args[1]:
                raise
            # We need to do an add
            msg["objectClass"] = ["top", "dnsNode"]
            msg["dnsRecord"].set_flags(ldb.FLAG_MOD_ADD)
            self.samdb.add(msg)

    def ldap_update_core(self, name, wtype, data, **kwargs):
        """This one is not TXT specific."""
        records = self.ldap_get_records(name)

        # default values
        rec = dnsp.DnssrvRpcRecord()
        rec.wType = wtype
        rec.rank = dnsp.DNS_RANK_ZONE
        rec.dwTtlSeconds = 900
        rec.dwSerial = 110
        rec.dwTimeStamp = 0
        rec.data = data

        # override defaults, as required
        for k, v in kwargs.items():
            setattr(rec, k, v)

        for i, r in enumerate(records[:]):
            if dsdb_dns.records_match(r, rec):
                records[i] = rec
                break
        else:  # record not found
            records.append(rec)

        self.ldap_replace_records(name, records)
        return rec

    def ldap_update_record(self, name, txt, **kwargs):
        """Add the record that self.dns_update_record() would add, via ldap,
        thus allowing us to set additional dnsRecord features like
        dwTimestamp.
        """
        rec = self.ldap_update_core(name,
                                    dnsp.DNS_TYPE_TXT,
                                    txt_s_list(txt),
                                    **kwargs)

        recs = self.ldap_get_records(name)
        match = None
        for r in recs:
            if r.wType != rec.wType:
                continue
            if r.data.str == rec.data.str:
                self.assertIsNone(match, f"duplicate records for {name}")
                match = r
        self.assertEqual(match.rank, rec.rank & 255)
        self.assertEqual(match.dwTtlSeconds, rec.dwTtlSeconds)
        self.assert_timestamps_equal(match.dwTimeStamp, rec.dwTimeStamp)
        return match

    def ldap_delete_record(self, name, data, wtype=dnsp.DNS_TYPE_TXT):
        rec = dnsp.DnssrvRpcRecord()
        if wtype == dnsp.DNS_TYPE_TXT:
            data = txt_s_list(data)

        rec.wType = wtype
        rec.data = data
        records = self.ldap_get_records(name)
        for i, r in enumerate(records[:]):
            if dsdb_dns.records_match(r, rec):
                del records[i]
                break
        else:
            self.fail(f"record {data} not found")

        self.ldap_replace_records(name, records)

    def add_ip_record(self, name, addr, wtype=None, **kwargs):
        if wtype is None:
            addr, wtype = guess_wtype(addr)
        rec = self.ldap_update_core(name,
                                    wtype,
                                    addr,
                                    **kwargs)

        recs = self.ldap_get_records(name)
        match = None
        for r in recs:
            if dsdb_dns.records_match(r, rec):
                self.assertIsNone(match, f"duplicate records for {name}")
                match = r
        self.assertEqual(match.rank, rec.rank & 255)
        self.assertEqual(match.dwTtlSeconds, rec.dwTtlSeconds)
        self.assert_timestamps_equal(match.dwTimeStamp, rec.dwTimeStamp)
        return match

    def ldap_modify_timestamps(self, name, delta):
        records = self.ldap_get_records(name)
        for rec in records:
            rec.dwTimeStamp += delta
        self.ldap_replace_records(name, records)

    def get_rpc_records(self, name, dns_type=None):
        if dns_type is None:
            dns_type = dnsp.DNS_TYPE_ALL
        select_flags = dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA
        buflen, res = self.rpc_conn.DnssrvEnumRecords2(
            dnsserver.DNS_CLIENT_VERSION_LONGHORN,
            0,
            SERVER_IP,
            self.zone,
            name,
            None,
            dns_type,
            select_flags,
            None,
            None)
        recs = []
        if not res or res.count == 0:
            return []
        for rec in res.rec:
            recs.extend(rec.records)
        return recs

    def dns_tombstone(self, name,
                      epoch_hours=DNS_TIMESTAMP_1981,
                      epoch_nttime=None):
        dn = f'DC={name},{self.zone_dn}'
        r = dnsp.DnssrvRpcRecord()
        r.wType = dnsp.DNS_TYPE_TOMBSTONE
        # r.dwTimeStamp is a 32 bit value in hours, and r.data is an
        # NTTIME (100 nanosecond intervals), both in the 1601 epoch. A
        # tombstone will have both, but expiration calculations use
        # the r.data NTTIME EntombedTime timestamp (see [MS-DNSP]).
        r.dwTimeStamp = epoch_hours
        if epoch_nttime is None:
            r.data = epoch_hours * 3600 * 10 * 1000 * 1000
        else:
            r.data = epoch_nttime

        msg = ldb.Message.from_dict(self.samdb,
                                    {'dn': dn,
                                     'dnsRecord': [ndr_pack(r)],
                                     'dnsTombstoned': 'TRUE'
                                    },
                                    ldb.FLAG_MOD_REPLACE)
        try:
            self.samdb.modify(msg)
        except ldb.LdbError as e:
            if 'LDAP_NO_SUCH_OBJECT' not in e.args[1]:
                raise
            # We need to do an add
            msg["objectClass"] = ["top", "dnsNode"]
            self.samdb.add(msg)

    def set_aging(self, enable=False):
        self.set_zone_int_params(Aging=int(bool(enable)))

    def assert_timestamp_in_ballpark(self, rec):
        self.assertGreater(rec.dwTimeStamp, DNS_TIMESTAMP_1970)
        self.assertLess(rec.dwTimeStamp, DNS_TIMESTAMP_2101)

    def assert_nttime_in_hour_range(self, t,
                                    hour_min=DNS_TIMESTAMP_1970,
                                    hour_max=DNS_TIMESTAMP_2101):
        t //= int(3600 * 1e7)
        self.assertGreater(t, hour_min)
        self.assertLess(t, hour_max)

    def assert_soon_after(self, timestamp, reference):
        """Assert that a timestamp is the same or very slightly higher than a
        reference timestamp.

        Typically we expect the timestamps to be identical, unless an
        hour has clicked over since the reference was taken. However
        we allow one more hour in case it happens during a daylight
        savings transition or something.
        """
        if hasattr(timestamp, 'dwTimeStamp'):
            timestamp = timestamp.dwTimeStamp
        if hasattr(reference, 'dwTimeStamp'):
            reference = reference.dwTimeStamp

        diff = timestamp - reference
        days = abs(diff / 24.0)

        if diff < 0:
            msg = f"timestamp is {days} days ({abs(diff)} hours) before reference"
        elif diff > 2:
            msg = f"timestamp is {days} days ({diff} hours) after reference"
        else:
            return
        raise AssertionError(msg)

    def assert_timestamps_equal(self, ts1, ts2):
        """Just like assertEqual(), but tells us the difference, not the
        absolute values. e.g:

        self.assertEqual(a, b)
        AssertionError: 3685491 != 3685371

        self.assert_timestamps_equal(a, b)
        AssertionError: -120 (first is 5.0 days earlier than second)

        Also, we turn a record into a timestamp if we need
        """
        if hasattr(ts1, 'dwTimeStamp'):
            ts1 = ts1.dwTimeStamp
        if hasattr(ts2, 'dwTimeStamp'):
            ts2 = ts2.dwTimeStamp

        if ts1 == ts2:
            return

        diff = ts1 - ts2
        days = abs(diff / 24.0)
        if ts1 == 0 or ts2 == 0:
            # when comparing to zero we don't want the number of days.
            msg = f"timestamp {ts1} != {ts2}"
        elif diff > 0:
            msg = f"{ts1} is {days} days ({diff} hours) after {ts2}"
        else:
            msg = f"{ts1} is {days} days ({abs(diff)} hours) before {ts2}"

        raise AssertionError(msg)

    def test_update_timestamps_aging_off_then_on(self):
        # we will add a record with aging off
        # it will have the current timestamp
        self.set_aging(False)
        name = 'timestamp-now'
        name2 = 'timestamp-eightdays'

        rec = self.dns_update_record(name, [name])
        start_time = rec.dwTimeStamp
        self.assert_timestamp_in_ballpark(rec)
        # alter the timestamp -8 days using RPC
        # with aging turned off, we expect no change
        # when aging is on, we expect change
        eight_days_ago = start_time - 8 * 24
        rec = self.ldap_update_record(name2, [name2],
                                      dwTimeStamp=eight_days_ago)

        self.assert_timestamps_equal(rec.dwTimeStamp, eight_days_ago)

        # if aging was on, this would change
        rec = self.dns_update_record(name2, [name2])
        self.assert_timestamps_equal(rec.dwTimeStamp, eight_days_ago)

        self.set_aging(True)
        rec = self.dns_update_record(name2, [name2])
        self.assertGreaterEqual(rec.dwTimeStamp, start_time)

    def test_rpc_update_timestamps(self):
        # RPC always sets timestamps to zero on Windows.
        self.set_aging(False)
        name = 'timestamp-now'

        rec = self.dns_update_record(name, [name])
        start_time = rec.dwTimeStamp
        self.assert_timestamp_in_ballpark(rec)
        # attempt to alter the timestamp to something close by.
        eight_days_ago = start_time - 8 * 24
        rec = self.rpc_update_record(name, [name],
                                     dwTimeStamp=eight_days_ago)
        self.assertEqual(rec.dwTimeStamp, 0)

        # try again, with aging on
        self.set_aging(True)
        rec = self.rpc_update_record(name, [name],
                                     dwTimeStamp=eight_days_ago)
        self.assertEqual(rec.dwTimeStamp, 0)

        # now that the record is static, a dns update won't change it
        rec = self.dns_update_record(name, [name])
        self.assertEqual(rec.dwTimeStamp, 0)

        # but another record on the same node will behave normally
        # i.e. the node is not static, the record is.
        name2 = 'timestamp-eightdays'
        rec = self.dns_update_record(name2, [name2])
        self.assert_soon_after(rec.dwTimeStamp,
                               start_time)

    def get_txt_timestamps(self, name, *txts):
        records = self.ldap_get_records(name)

        ret = []
        for t in txts:
            for r in records:
                t2 = [x for x in r.data.str]
                if t == t2:
                    ret.append(r.dwTimeStamp)
        return ret

    def test_update_aging_disabled_2(self):
        # With aging disabled, Windows updates the timestamps of all
        # records when one is updated.
        name = 'test'
        txt1 = ['test txt']
        txt2 = ['test', 'txt2']
        txt3 = ['test', 'txt3']

        self.set_aging(False)

        current_time = self.dns_update_record(name, txt1).dwTimeStamp

        six_days_ago = current_time - 6 * 24
        eight_days_ago = current_time - 8 * 24
        fifteen_days_ago = current_time - 15 * 24
        hundred_days_ago = current_time - 100 * 24
        thousand_days_ago = current_time - 1000 * 24

        for timestamp in (current_time,
                          six_days_ago,
                          eight_days_ago,
                          fifteen_days_ago,
                          hundred_days_ago,
                          thousand_days_ago):
            # wind back
            self.ldap_update_record(name, txt1, dwTimeStamp=timestamp)
            self.assertEqual(self.get_txt_timestamps(name, txt1), [timestamp])

            # no change here
            update_timestamp = self.dns_update_record(name, txt1).dwTimeStamp
            self.assert_timestamps_equal(update_timestamp, timestamp)

        # adding a fresh record
        for timestamp in (current_time,
                          six_days_ago,
                          eight_days_ago,
                          fifteen_days_ago,
                          hundred_days_ago,
                          thousand_days_ago,
                          100000,
                          100):
            # wind back
            timestamp1 = self.ldap_update_record(
                name,
                txt1,
                dwTimeStamp=timestamp).dwTimeStamp
            self.assert_timestamps_equal(timestamp1, timestamp)

            self.dns_update_record(name, txt2)
            timestamps = self.get_txt_timestamps(name, txt1, txt2)
            self.assertEqual(timestamps, [timestamp, current_time])

            self.ldap_delete_record(name, txt2)
            timestamps = self.get_txt_timestamps(name, txt1)
            self.assertEqual(timestamps, [timestamp])

        # add record 2.
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        for timestamp in (current_time,
                          six_days_ago,
                          eight_days_ago,
                          fifteen_days_ago,
                          hundred_days_ago,
                          thousand_days_ago,
                          100000,
                          100):
            # wind back
            self.ldap_update_record(name, txt1, dwTimeStamp=timestamp)
            timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
            self.assert_timestamps_equal(timestamp1, timestamp)

            timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
            # txt1 timestamp is now current time
            timestamps = self.get_txt_timestamps(name, txt1, txt2)
            self.assertEqual(timestamps, [timestamp, current_time])

        # with 3 records, no change
        for timestamp in (current_time,
                          six_days_ago,
                          eight_days_ago,
                          fifteen_days_ago,
                          hundred_days_ago,
                          thousand_days_ago,
                          100000,
                          10):
            # wind back
            self.ldap_update_record(name, txt1, dwTimeStamp=timestamp)
            self.ldap_update_record(name, txt2, dwTimeStamp=timestamp)
            self.ldap_update_record(name, txt3, dwTimeStamp=(timestamp + 30))
            timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
            self.assert_timestamps_equal(timestamp3, timestamp + 30)

            self.dns_update_record(name, txt2).dwTimeStamp
            timestamps = self.get_txt_timestamps(name, txt1, txt2, txt3)
            self.assertEqual(timestamps, [timestamp,
                                          timestamp,
                                          timestamp + 30])

        # with 3 records, one of which is static
        # first we set the updatee's timestamp to a recognisable number
        self.ldap_update_record(name, txt2, dwTimeStamp=999999)
        for timestamp in (current_time,
                          six_days_ago,
                          eight_days_ago,
                          fifteen_days_ago,
                          hundred_days_ago,
                          thousand_days_ago,
                          100000,
                          10):
            # wind back
            self.ldap_update_record(name, txt1, dwTimeStamp=0)
            self.ldap_update_record(name, txt3, dwTimeStamp=(timestamp - 9))
            timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
            self.assert_timestamps_equal(timestamp3, timestamp - 9)

            self.dns_update_record(name, txt2)
            timestamps = self.get_txt_timestamps(name, txt1, txt2, txt3)
            self.assertEqual(timestamps, [0,
                                          999999,
                                          timestamp - 9])

        # with 3 records, updating one which is static
        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        for timestamp in (current_time,
                          six_days_ago,
                          eight_days_ago,
                          fifteen_days_ago,
                          hundred_days_ago,
                          thousand_days_ago,
                          100000,
                          10):
            # wind back
            self.ldap_update_record(name, txt1, dwTimeStamp=0)
            self.ldap_update_record(name, txt2, dwTimeStamp=0)
            self.ldap_update_record(name, txt3, dwTimeStamp=(timestamp + 30))
            timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
            self.assert_timestamps_equal(timestamp3, timestamp + 30)

            self.dns_update_record(name, txt2).dwTimeStamp
            timestamps = self.get_txt_timestamps(name, txt1, txt2, txt3)
            self.assertEqual(timestamps, [0,
                                          0,
                                          timestamp + 30])

        # with 3 records, after the static nodes have been replaced
        self.ldap_update_record(name, txt1, dwTimeStamp=777777)
        self.ldap_update_record(name, txt2, dwTimeStamp=888888)
        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        for timestamp in (current_time,
                          six_days_ago,
                          eight_days_ago,
                          fifteen_days_ago,
                          hundred_days_ago,
                          thousand_days_ago,
                          100000,
                          10):
            # wind back
            self.ldap_update_record(name, txt3, dwTimeStamp=(timestamp))
            timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
            self.assert_timestamps_equal(timestamp3, timestamp)

            self.dns_update_record(name, txt2)
            timestamps = self.get_txt_timestamps(name, txt1, txt2, txt3)
            self.assertEqual(timestamps, [777777,
                                          888888,
                                          timestamp])

    def _test_update_aging_disabled_n_days_ago(self, n_days):
        name = 'test'
        txt1 = ['1']
        txt2 = ['2']

        self.set_aging(False)
        current_time = self.dns_update_record(name, txt1).dwTimeStamp

        # rewind timestamp using ldap
        self.ldap_modify_timestamps(name, n_days * -24)
        n_days_ago = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assertGreater(current_time, n_days_ago)

        # no change when updating this record
        update_timestamp = self.dns_update_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(update_timestamp, n_days_ago)

        # add another record, which should have the current timestamp
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        # get the original record timestamp. NOW it matches current_time
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, timestamp2)

        # let's repeat that, this time with txt2 existing
        self.ldap_update_record(name, txt1, dwTimeStamp=n_days_ago)

        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, n_days_ago)

        # this update is not an add
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        # now timestamp1 is not changed
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, n_days_ago)

        # delete record2, try again
        self.ldap_delete_record(name, txt2)
        self.ldap_update_record(name, txt1, dwTimeStamp=n_days_ago)

        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, n_days_ago)

        # here we are re-adding the deleted record
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp

        # It gets weird HERE.
        # note how the SIBLING of the deleted, re-added record differs
        # from the sibling of freshly added record, depending on the
        # time difference.
        if n_days <= 7:
            self.assert_timestamps_equal(timestamp1, n_days_ago)
        else:
            self.assert_timestamps_equal(timestamp1, timestamp2)

        # re-timestamp record2, try again
        self.ldap_update_record(name, txt2, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, txt1, dwTimeStamp=n_days_ago)

        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, n_days_ago)

        # no change
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_timestamps_equal(timestamp2, n_days_ago)
        # also no change
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, timestamp2)

        # let's introduce another record
        txt3 = ['3']
        self.ldap_update_record(name, txt2, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, txt1, dwTimeStamp=n_days_ago)

        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        self.assert_soon_after(timestamp3, current_time)

        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp

        if n_days <= 7:
            self.assert_timestamps_equal(timestamp1, n_days_ago)
        else:
            self.assert_timestamps_equal(timestamp1, timestamp3)

        self.assert_timestamps_equal(timestamp2, timestamp3)

        self.ldap_delete_record(name, txt3)
        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        self.assert_soon_after(timestamp3, current_time)
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp

        if n_days <= 7:
            self.assert_timestamps_equal(timestamp1, n_days_ago)
        else:
            self.assert_timestamps_equal(timestamp1, timestamp3)

        self.assert_timestamps_equal(timestamp2, timestamp3)

        # and here we'll make txt3 static
        txt4 = ['4']

        # and here we'll make txt1 static
        self.ldap_update_record(name, txt1, dwTimeStamp=0)
        self.ldap_update_record(name, txt2, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, txt3, dwTimeStamp=n_days_ago)
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        timestamp4 = self.dns_update_record(name, txt4).dwTimeStamp

        self.assertEqual(timestamp1, 0)
        self.assert_timestamps_equal(timestamp2, n_days_ago)
        self.assert_timestamps_equal(timestamp3, n_days_ago)
        self.assert_soon_after(timestamp4, current_time)

    def test_update_aging_disabled_in_no_refresh_window(self):
        self._test_update_aging_disabled_n_days_ago(4)

    def test_update_aging_disabled_on_no_refresh_boundary(self):
        self._test_update_aging_disabled_n_days_ago(7)

    def test_update_aging_disabled_in_refresh_window(self):
        self._test_update_aging_disabled_n_days_ago(9)

    def test_update_aging_disabled_beyond_refresh_window(self):
        self._test_update_aging_disabled_n_days_ago(16)

    def test_update_aging_disabled_in_eighteenth_century(self):
        self._test_update_aging_disabled_n_days_ago(100000)

    def test_update_aging_disabled_static(self):
        name = 'test'
        txt1 = ['1']
        txt2 = ['2']

        self.set_aging(False)

        current_time = self.dns_update_record(name, txt1).dwTimeStamp
        self.ldap_update_record(name, txt1, dwTimeStamp=0)

        # no change when updating this record
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        self.assertEqual(timestamp1, 0)

        # add another record, which should have the current timestamp
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_soon_after(timestamp1, current_time)

        # let's repeat that, this time with txt2 existing
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        # delete record2, try again
        self.ldap_delete_record(name, txt2)
        self.ldap_update_record(name, txt1, dwTimeStamp=0)
        # no change when updating this record
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        self.assertEqual(timestamp1, 0)

        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assertEqual(timestamp2, 0)

        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assertEqual(timestamp1, 0)
        # re-timestamp record2, try again
        self.ldap_update_record(name, txt2, dwTimeStamp=1)
        self.ldap_update_record(name, txt1, dwTimeStamp=0)
        # no change when updating this record
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_timestamps_equal(timestamp2, 1)

    def test_update_aging_disabled(self):
        # With aging disabled, Windows updates the timestamps of all
        # records when one is updated.
        name = 'test'
        txt1 = ['test txt']
        txt2 = ['test', 'txt2']
        txt3 = ['test', 'txt3']
        minus_6 = -6 * 24
        minus_8 = -8 * 24

        self.set_aging(False)

        current_time = self.dns_update_record(name, txt1).dwTimeStamp

        # rewind timestamp using ldap
        self.ldap_modify_timestamps(name, minus_6)
        after_mod = self.get_unique_txt_record(name, txt1)
        six_days_ago = after_mod.dwTimeStamp
        self.assert_timestamps_equal(six_days_ago, current_time + minus_6)

        # no change
        update_timestamp = self.dns_update_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(update_timestamp, six_days_ago)

        self.check_query_txt(name, txt1, zone=self.zone)

        # another record
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        # without aging, timestamp1 is changed!!
        self.assert_timestamps_equal(timestamp1, timestamp2)

        # Set both records back to 8 days ago.
        self.ldap_modify_timestamps(name, minus_8)

        eight_days_ago = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(eight_days_ago, current_time + minus_8)

        update2 = self.dns_update_record(name, txt2)

        # Without aging on, an update should not change the timestamps.
        self.assert_timestamps_equal(update2.dwTimeStamp, eight_days_ago)
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, eight_days_ago)

        # Add another txt record. The new record should have the now
        # timestamp, and drag the others up with it.
        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        self.assert_soon_after(timestamp3, current_time)
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, timestamp3)
        self.assert_timestamps_equal(timestamp2, timestamp3)

        hundred_days_ago = current_time - 100 * 24
        thousand_days_ago = current_time - 1000 * 24
        record = self.ldap_update_record(name, txt1,
                                         dwTimeStamp=hundred_days_ago)
        self.assert_timestamps_equal(record.dwTimeStamp, hundred_days_ago)
        record = self.ldap_update_record(name, txt2,
                                         dwTimeStamp=thousand_days_ago)
        self.assert_timestamps_equal(record.dwTimeStamp, thousand_days_ago)

        # update 3, will others change (because beyond RefreshInterval)? yes.
        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp3, current_time)
        self.assert_timestamps_equal(timestamp1, hundred_days_ago)
        self.assert_timestamps_equal(timestamp2, thousand_days_ago)

        fifteen_days_ago = current_time - 15 * 24
        self.ldap_update_record(name, txt3, dwTimeStamp=fifteen_days_ago)

        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        # DNS update has no effect because all records are old
        self.assert_timestamps_equal(timestamp2, thousand_days_ago)
        self.assert_timestamps_equal(timestamp1, hundred_days_ago)
        self.assert_timestamps_equal(timestamp3, fifteen_days_ago)

        # Does update of old record affect timestamp of refreshable record? No.
        self.ldap_update_record(name, txt3, dwTimeStamp=eight_days_ago)
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        # DNS update has no effect because all records are old
        self.assert_timestamps_equal(timestamp2, thousand_days_ago)
        self.assert_timestamps_equal(timestamp1, hundred_days_ago)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        # RPC zeros timestamp, after which updates won't change it.
        # BUT it refreshes all others!
        self.rpc_update_record(name, txt2)

        timestamp2 = self.dns_update_record(name, txt3).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        self.assertEqual(timestamp2, 0)
        self.assert_soon_after(timestamp1, current_time)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

    def test_update_aging_enabled(self):
        name = 'test'
        txt1 = ['test txt']
        txt2 = ['test', 'txt2']
        txt3 = ['test', 'txt3']
        txt4 = ['4']

        self.set_aging(True)

        current_time = self.dns_update_record(name, txt2).dwTimeStamp

        six_days_ago = current_time - 6 * 24
        eight_days_ago = current_time - 8 * 24
        fifteen_days_ago = current_time - 15 * 24
        hundred_days_ago = current_time - 100 * 24

        self.ldap_update_record(name, txt1, dwTimeStamp=six_days_ago)

        # with or without aging, a delta of -6 days does not affect
        # timestamps, because dwNoRefreshInterval is 7 days.
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp

        self.assert_timestamps_equal(timestamp1, six_days_ago)
        self.assert_soon_after(timestamp2, current_time)

        self.ldap_update_record(name, txt3, dwTimeStamp=eight_days_ago)
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        # update 1, what happens to 2 and 3? Nothing?
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, six_days_ago)
        self.assert_soon_after(timestamp2, current_time)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        # now set 1 to 8 days, and we should see changes
        self.ldap_update_record(name, txt1, dwTimeStamp=eight_days_ago)

        # update 1, what happens to 2 and 3? Nothing?
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assert_soon_after(timestamp1, current_time)
        self.assert_soon_after(timestamp2, current_time)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        # next few ones use these numbers
        self.ldap_update_record(name, txt1, dwTimeStamp=fifteen_days_ago)
        self.ldap_update_record(name, txt2, dwTimeStamp=six_days_ago)
        self.ldap_update_record(name, txt3, dwTimeStamp=eight_days_ago)

        # change even though 1 is outside the window
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assert_soon_after(timestamp1, current_time)
        self.assert_timestamps_equal(timestamp2, six_days_ago)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        # reset 1
        self.ldap_update_record(name, txt1, dwTimeStamp=fifteen_days_ago)

        # no change, because 2 is outside the window
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, fifteen_days_ago)
        self.assert_timestamps_equal(timestamp2, six_days_ago)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        # 3 changes, others do not
        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, fifteen_days_ago)
        self.assert_timestamps_equal(timestamp2, six_days_ago)
        self.assert_soon_after(timestamp3, current_time)

        # reset 3 to 100 days
        self.ldap_update_record(name, txt3, dwTimeStamp=hundred_days_ago)

        # 3 changes, others do not
        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, fifteen_days_ago)
        self.assert_timestamps_equal(timestamp2, six_days_ago)
        self.assert_soon_after(timestamp3, current_time)

        # reset 1 and 3 to 8 days. does update of 1 affect 3?
        self.ldap_update_record(name, txt1, dwTimeStamp=eight_days_ago)
        self.ldap_update_record(name, txt3, dwTimeStamp=eight_days_ago)

        # 1 changes, others do not
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assert_soon_after(timestamp1, current_time)
        self.assert_timestamps_equal(timestamp2, six_days_ago)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        # Try an RPC update, zeroing 1 --> what happens to 3?
        timestamp1 = self.rpc_update_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assertEqual(timestamp1, 0)
        self.assert_timestamps_equal(timestamp2, six_days_ago)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        # with 2 and 3 at 8 days, does static record change things?
        self.ldap_update_record(name, txt2, dwTimeStamp=eight_days_ago)
        # 2 changes, but to zero!
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, 0)
        self.assert_timestamps_equal(timestamp2, 0)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)

        self.ldap_update_record(name, txt2, dwTimeStamp=six_days_ago)
        self.ldap_update_record(name, txt1, dwTimeStamp=3000000)
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, 3000000)

        # dns update remembers that node is static, even with no
        # static records.
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        self.assertEqual(timestamp1, 0)

        # Add another txt record. The new record should have the now
        # timestamp, and the others should remain unchanged.
        # BUT somehow record 1 is static!?
        timestamp4 = self.dns_update_record(name, txt4).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, 0)
        self.assert_timestamps_equal(timestamp2, six_days_ago)
        self.assert_timestamps_equal(timestamp3, eight_days_ago)
        self.assert_timestamps_equal(timestamp4, 0)

    def _test_update_aging_enabled_n_days_ago(self, n_days):
        name = 'test'
        txt1 = ['1']
        txt2 = ['2']
        delta = n_days * -24

        self.set_aging(True)
        current_time = self.dns_update_record(name, txt1).dwTimeStamp

        # rewind timestamp using ldap
        self.ldap_modify_timestamps(name, delta)
        n_days_ago = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assertGreater(current_time, n_days_ago)

        # update changes timestamp depending on time.
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        if n_days <= 7:
            self.assert_timestamps_equal(timestamp1, n_days_ago)
        else:
            self.assert_soon_after(timestamp1, current_time)

        # add another record, which should have the current timestamp
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        # first record should not have changed
        timestamp1_b = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, timestamp1_b)

        # let's repeat that, this time with txt2 existing
        self.ldap_update_record(name, txt1, dwTimeStamp=n_days_ago)

        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, timestamp1_b)

        # this update is not an add. record 2 is already up-to-date
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        # now timestamp1 is not changed
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, timestamp1_b)

        # delete record2, try again
        self.ldap_delete_record(name, txt2)
        self.ldap_update_record(name, txt1, dwTimeStamp=n_days_ago)

        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        if n_days <= 7:
            self.assert_timestamps_equal(timestamp1, n_days_ago)
        else:
            self.assert_soon_after(timestamp1, current_time)

        # here we are re-adding the deleted record
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_soon_after(timestamp2, current_time)

        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp

        # It gets weird HERE.
        # note how the SIBLING of the deleted, re-added record differs
        # from the sibling of freshly added record, depending on the
        # time difference.
        if n_days <= 7:
            self.assert_timestamps_equal(timestamp1, n_days_ago)
        else:
            self.assert_timestamps_equal(timestamp1, timestamp2)

        # re-timestamp record2, try again
        self.ldap_update_record(name, txt2, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, txt1, dwTimeStamp=n_days_ago)

        # this should make no difference
        timestamp1_b = self.dns_update_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, timestamp1_b)

        # no change
        timestamp2 = self.dns_update_record(name, txt2).dwTimeStamp
        self.assert_timestamps_equal(timestamp2, timestamp1)
        # also no change
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, timestamp2)

        # let's introduce another record
        txt3 = ['3']
        self.ldap_update_record(name, txt2, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, txt1, dwTimeStamp=n_days_ago)

        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        self.assert_soon_after(timestamp3, current_time)

        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp

        self.assert_timestamps_equal(timestamp1, n_days_ago)
        self.assert_timestamps_equal(timestamp2, n_days_ago)

        self.ldap_delete_record(name, txt3)
        timestamp3 = self.dns_update_record(name, txt3).dwTimeStamp
        self.assert_soon_after(timestamp3, current_time)
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp

        self.assert_timestamps_equal(timestamp1, n_days_ago)
        self.assert_timestamps_equal(timestamp2, n_days_ago)

        txt4 = ['4']

        # Because txt1 is static, txt4 is static
        self.ldap_update_record(name, txt1, dwTimeStamp=0)
        self.ldap_update_record(name, txt2, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, txt3, dwTimeStamp=n_days_ago)
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        timestamp4 = self.dns_update_record(name, txt4).dwTimeStamp

        self.assert_timestamps_equal(timestamp1, 0)
        self.assert_timestamps_equal(timestamp2, n_days_ago)
        self.assert_timestamps_equal(timestamp3, n_days_ago)
        self.assert_timestamps_equal(timestamp4, 0)

        longer_ago = n_days_ago // 2

        # remove all static records.
        self.ldap_delete_record(name, txt4)
        self.ldap_update_record(name, txt1, dwTimeStamp=longer_ago)
        self.ldap_update_record(name, txt2, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, txt3, dwTimeStamp=n_days_ago)
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, longer_ago)

        timestamp4 = self.dns_update_record(name, txt4).dwTimeStamp
        timestamp2 = self.get_unique_txt_record(name, txt2).dwTimeStamp
        timestamp3 = self.get_unique_txt_record(name, txt3).dwTimeStamp
        timestamp1 = self.get_unique_txt_record(name, txt1).dwTimeStamp

        # Here, although there is no record from which to get the zero
        # timestamp, record 4 does it anyway.
        self.assert_timestamps_equal(timestamp1, longer_ago)
        self.assert_timestamps_equal(timestamp2, n_days_ago)
        self.assert_timestamps_equal(timestamp3, n_days_ago)
        self.assert_timestamps_equal(timestamp4, 0)

        # and now record 1 wants to be static.
        self.ldap_update_record(name, txt4, dwTimeStamp=longer_ago)
        timestamp4 = self.get_unique_txt_record(name, txt4).dwTimeStamp
        self.assert_timestamps_equal(timestamp4, longer_ago)
        timestamp1 = self.dns_update_record(name, txt1).dwTimeStamp
        timestamp4 = self.get_unique_txt_record(name, txt4).dwTimeStamp
        self.assert_timestamps_equal(timestamp1, 0)
        self.assert_timestamps_equal(timestamp4, longer_ago)

    def test_update_aging_enabled_in_no_refresh_window(self):
        self._test_update_aging_enabled_n_days_ago(4)

    def test_update_aging_enabled_on_no_refresh_boundary(self):
        self._test_update_aging_enabled_n_days_ago(7)

    def test_update_aging_enabled_in_refresh_window(self):
        self._test_update_aging_enabled_n_days_ago(9)

    def test_update_aging_enabled_beyond_refresh_window(self):
        self._test_update_aging_enabled_n_days_ago(16)

    def test_update_aging_enabled_in_eighteenth_century(self):
        self._test_update_aging_enabled_n_days_ago(100000)

    def test_update_static_stickiness(self):
        name = 'test'
        A = ['A']
        B = ['B']
        C = ['C']
        D = ['D']

        self.set_aging(False)
        self.dns_update_record(name, A).dwTimeStamp
        self.ldap_update_record(name, B, dwTimeStamp=0)
        self.dns_update_record(name, B)
        self.dns_update_record(name, C)
        ctime = self.get_unique_txt_record(name, C).dwTimeStamp
        self.assertEqual(ctime, 0)
        btime = self.get_unique_txt_record(name, B).dwTimeStamp
        self.assertEqual(btime, 0)

        self.ldap_replace_records(name, [])

        self.dns_update_record(name, D)
        dtime = self.get_unique_txt_record(name, D).dwTimeStamp
        self.assertEqual(dtime, 0)

    def _test_update_timestamp_weirdness(self, n_days, aging=True):
        name = 'test'
        A = ['A']
        B = ['B']

        self.set_aging(aging)

        current_time = self.dns_update_record(name, A).dwTimeStamp

        # rewind timestamp using ldap
        self.ldap_modify_timestamps(name, n_days * -24)
        n_days_ago = self.get_unique_txt_record(name, A).dwTimeStamp
        time_A = self.dns_update_record(name, A).dwTimeStamp
        # that dns_update should have reset the timestamp ONLY if
        # aging is on and the old timestamp is > noRefresh period (7
        # days)
        if n_days > 7 and aging:
            self.assert_soon_after(time_A, current_time)
        else:
            self.assert_timestamps_equal(time_A, n_days_ago)

        # add another record, which should have the current timestamp
        time_B = self.dns_update_record(name, B).dwTimeStamp
        self.assert_soon_after(time_B, current_time)

        time_A = self.get_unique_txt_record(name, A).dwTimeStamp
        if aging and n_days <= 7:
            self.assert_timestamps_equal(time_A, n_days_ago)
        else:
            self.assert_soon_after(time_A, current_time)

        # delete B, try again
        self.ldap_delete_record(name, B)
        self.ldap_update_record(name, A, dwTimeStamp=n_days_ago)

        time_A = self.dns_update_record(name, A).dwTimeStamp

        # here we are re-adding the deleted record
        time_B = self.dns_update_record(name, B).dwTimeStamp
        self.assert_soon_after(time_B, current_time)

        time_A = self.get_unique_txt_record(name, A).dwTimeStamp
        return n_days_ago, time_A, time_B

    def test_update_timestamp_weirdness_no_refresh_no_aging(self):
        n_days_ago, time_A, time_B = \
            self._test_update_timestamp_weirdness(5, False)
        # the timestamp of the SIBLING of the deleted, re-added record
        # differs from the sibling of freshly added record.
        self.assert_timestamps_equal(time_A, n_days_ago)

    def test_update_timestamp_weirdness_no_refresh_aging(self):
        n_days_ago, time_A, time_B = \
            self._test_update_timestamp_weirdness(5, True)
        # the timestamp of the SIBLING of the deleted, re-added record
        # differs from the sibling of freshly added record.
        self.assert_timestamps_equal(time_A, n_days_ago)

    def test_update_timestamp_weirdness_refresh_no_aging(self):
        n_days_ago, time_A, time_B = \
            self._test_update_timestamp_weirdness(9, False)
        self.assert_timestamps_equal(time_A, time_B)

    def test_update_timestamp_weirdness_refresh_aging(self):
        n_days_ago, time_A, time_B = \
            self._test_update_timestamp_weirdness(9, True)
        self.assert_timestamps_equal(time_A, time_B)

    def test_aging_refresh(self):
        name, txt = 'agingtest', ['test txt']
        no_refresh = 200
        refresh = 160
        self.set_zone_int_params(NoRefreshInterval=no_refresh,
                                 RefreshInterval=refresh,
                                 Aging=1)
        before_mod = self.dns_update_record(name, txt)
        start_time = before_mod.dwTimeStamp

        # go back 86 hours, which is in the no-refresh time (but
        # wouldn't be if we had stuck to the default of 168).
        self.ldap_modify_timestamps(name, -170)
        rec = self.dns_update_record(name, txt)
        self.assert_timestamps_equal(rec.dwTimeStamp,
                                     start_time - 170)

        # back to -202 hours, into the refresh zone
        # the update should reset the timestamp to now.
        self.ldap_modify_timestamps(name, -32)
        rec = self.dns_update_record(name, txt)
        self.assert_soon_after(rec.dwTimeStamp, start_time)

        # back to -362 hours, beyond the end of the refresh period.
        # Actually nothing changes at this time -- we can still
        # refresh, but the record is liable for scavenging.
        self.ldap_modify_timestamps(name, -160)
        rec = self.dns_update_record(name, txt)
        self.assert_soon_after(rec.dwTimeStamp, start_time)

    def test_add_no_timestamp(self):
        # check zero timestamp is implicit
        self.set_aging(True)
        rec = self.ldap_update_record('ldap', 'test')
        self.assertEqual(rec.dwTimeStamp, 0)
        rec = self.rpc_update_record('rpc', 'test')
        self.assertEqual(rec.dwTimeStamp, 0)

    def test_add_zero_timestamp(self):
        rec = self.ldap_update_record('ldap', 'test', dwTimeStamp=0)
        self.assertEqual(rec.dwTimeStamp, 0)
        rec = self.rpc_update_record('rpc', 'test', dwTimeStamp=0)
        self.assertEqual(rec.dwTimeStamp, 0)

    def test_add_update_timestamp(self):
        # LDAP can change timestamp, RPC can't
        rec = self.ldap_update_record('ldap', 'test', dwTimeStamp=123456)
        self.assertEqual(rec.dwTimeStamp, 123456)
        rec = self.rpc_update_record('rpc', 'test', dwTimeStamp=123456)
        self.assertEqual(rec.dwTimeStamp, 0)
        # second time is a different code path (add vs update)
        rec = self.rpc_update_record('rpc', 'test', dwTimeStamp=123456)
        self.assertEqual(rec.dwTimeStamp, 0)
        # RPC update the one with timestamp, zeroing it.
        rec = self.rpc_update_record('ldap', 'test', dwTimeStamp=123456)
        self.assertEqual(rec.dwTimeStamp, 0)

    def test_add_update_ttl(self):
        # RPC *can* set dwTtlSeconds.
        rec = self.ldap_update_record('ldap', 'test',
                                      dwTtlSeconds=1234)
        self.assertEqual(rec.dwTtlSeconds, 1234)
        rec = self.rpc_update_record('rpc', 'test', dwTtlSeconds=1234)
        self.assertEqual(rec.dwTtlSeconds, 1234)
        # does update work like add?
        rec = self.rpc_update_record('rpc', 'test', dwTtlSeconds=4321)
        self.assertEqual(rec.dwTtlSeconds, 4321)
        rec = self.rpc_update_record('ldap', 'test', dwTtlSeconds=5678)
        self.assertEqual(rec.dwTtlSeconds, 5678)

    def test_add_update_ttl_serial(self):
        # when setting dwTtlSeconds, what happens to serial number?
        rec = self.ldap_update_record('ldap', 'test',
                                      dwTtlSeconds=1234,
                                      dwSerial=123)
        self.assertEqual(rec.dwTtlSeconds, 1234)
        self.assertEqual(rec.dwSerial, 123)
        rec = self.rpc_update_record('rpc', 'test', dwTtlSeconds=1234)
        self.assertEqual(rec.dwTtlSeconds, 1234)
        serial = rec.dwSerial
        self.assertLess(serial, 4)
        rec = self.rpc_update_record('rpc', 'test', dwTtlSeconds=4321)
        self.assertEqual(rec.dwTtlSeconds, 4321)
        self.assertEqual(rec.dwSerial, serial + 1)
        rec = self.rpc_update_record('ldap', 'test', dwTtlSeconds=5678)
        self.assertEqual(rec.dwTtlSeconds, 5678)
        self.assertEqual(rec.dwSerial, 124)

    def test_add_update_dwFlags(self):
        # dwFlags splits into rank and flags.
        # according to [MS-DNSP] 2.3.2.2, flags MUST be zero
        rec = self.ldap_update_record('ldap', 'test', flags=22222, rank=222)
        self.assertEqual(rec.flags, 22222)
        self.assertEqual(rec.rank, 222)

        rec = self.rpc_update_record('ldap', 'test', dwFlags=3333333)
        # rank != 3333333 & 0xff == 213
        self.assertEqual(rec.rank, 240)    # RPC fixes rank
        self.assertEqual(rec.flags, 0)

        self.assertRaises(OverflowError,
                          self.ldap_update_record,
                          'ldap', 'test', flags=777777777, rank=777)

        # reset to no default (rank overflows)
        rec = self.ldap_update_record('ldap', 'test', flags=7777, rank=777)
        self.assertEqual(rec.flags, 7777)
        self.assertEqual(rec.rank, 9)

        # DNS update zeros flags, sets rank to 240 (RANK_ZONE)
        rec = self.dns_update_record('ldap', 'test', ttl=999)
        self.assertEqual(rec.flags, 0)
        self.assertEqual(rec.rank, 240)

        rec = self.rpc_update_record('ldap', 'test', dwFlags=321)
        self.assertEqual(rec.flags, 0)
        self.assertEqual(rec.rank, 240)

        # RPC adding a new record: fixed rank, zero flags
        rec = self.rpc_update_record('ldap', 'test 2', dwFlags=12345)
        self.assertEqual(rec.rank, 240)
        self.assertEqual(rec.flags, 0)

    def test_add_update_dwReserved(self):
        # RPC does not change dwReserved.
        rec = self.ldap_update_record('ldap', 'test', dwReserved=54321)
        self.assertEqual(rec.dwReserved, 54321)
        rec = self.rpc_update_record('rpc', 'test', dwReserved=54321)
        self.assertEqual(rec.dwReserved, 0)
        rec = self.rpc_update_record('rpc', 'test', dwReserved=54321)
        self.assertEqual(rec.dwReserved, 0)
        rec = self.rpc_update_record('ldap', 'test', dwReserved=12345)
        self.assertEqual(rec.dwReserved, 54321)

    def test_add_update_dwSerial(self):
        # On Windows the RPC record ends up with serial 2, on Samba
        # serial 3. Rather than knownfail this, we accept anything
        # below 4 (for now).
        rec = self.ldap_update_record('ldap', 'test', dwSerial=123)
        self.assertEqual(rec.dwSerial, 123)
        rec = self.rpc_update_record('rpc', 'test', dwSerial=123)
        self.assertLess(rec.dwSerial, 4)
        rec = self.rpc_update_record('rpc', 'test', dwSerial=123)
        self.assertLess(rec.dwSerial, 4)
        rec = self.dns_update_record('rpc', 'test')
        self.assertLess(rec.dwSerial, 4)
        rec = self.dns_update_record('dns-0', 'test')
        self.assertLess(rec.dwSerial, 5)

        rec = self.dns_update_record('ldap', 'test')
        self.assertEqual(rec.dwSerial, 123)
        rec = self.rpc_update_record('ldap', 'test', dwSerial=123)
        self.assertEqual(rec.dwSerial, 123)
        rec = self.ldap_update_record('ldap', 'test', dwSerial=12)
        self.assertEqual(rec.dwSerial, 12)
        # when we dns-updated ldap/test, we alerted Windows to 123 as
        # a high water mark for the zone. (even though we have since
        # dropped the serial to 12, 123 is the base serial for new
        # records).
        rec = self.dns_update_record('dns', 'test')
        self.assertEqual(rec.dwSerial, 124)
        rec = self.dns_update_record('dns2', 'test')
        self.assertEqual(rec.dwSerial, 125)
        rec = self.rpc_update_record('rpc2', 'test')
        self.assertEqual(rec.dwSerial, 126)
        rec = self.dns_update_record('dns', 'test 2')
        self.assertEqual(rec.dwSerial, 127)

    def test_add_update_dwSerial_2(self):
        # On Samba the RPC update resets the serial to a low number,
        # while Windows leaves it high.
        rec = self.ldap_update_record('ldap', 'test', dwSerial=123)
        self.assertEqual(rec.dwSerial, 123)
        rec = self.rpc_update_record('ldap', 'test', dwSerial=321)
        self.assertEqual(rec.dwSerial, 123)
        rec = self.dns_update_record('ldap', 'test')
        self.assertEqual(rec.dwSerial, 123)

    def test_rpc_update_disparate_types(self):
        """Can we use update to replace a TXT with an AAAA?"""
        name = 'x'
        old = TXTRecord("x")
        new = ARecord("127.0.0.111")
        self.rpc_replace(name, None, old)
        recs = self.ldap_get_records(name)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].wType, old.wType)

        self.rpc_replace(name, old, new)
        recs = self.ldap_get_records(name)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].wType, new.wType)

    def test_add_update_many(self):
        # Samba fails often in this set, but we want to see how it
        # goes further down, so we print the problems and defer the
        # failure.
        failures = 0
        total = 0

        def _defer_wrap(f):
            def _defer(*args):
                nonlocal failures, total
                total += 1
                try:
                    f(*args)
                except self.failureException as e:
                    from traceback import format_stack
                    print(f"{format_stack()[-2]} {e}\n")
                    failures += 1
            return _defer

        defer_assertEqual = _defer_wrap(self.assertEqual)
        defer_assert_timestamp_in_ballpark = \
            _defer_wrap(self.assert_timestamp_in_ballpark)

        self.set_aging(False)
        rec = self.ldap_update_record('ldap', 'test',
                                      version=11,
                                      rank=22,
                                      flags=33,
                                      dwSerial=44,
                                      dwTtlSeconds=55,
                                      dwReserved=66,
                                      dwTimeStamp=77)

        self.assertEqual(rec.version, 5)  # disobeys request
        self.assertEqual(rec.rank, 22)
        self.assertEqual(rec.flags, 33)
        self.assertEqual(rec.dwSerial, 44)
        self.assertEqual(rec.dwTtlSeconds, 55)
        self.assertEqual(rec.dwReserved, 66)
        self.assertEqual(rec.dwTimeStamp, 77)
        # DNS updates first
        rec = self.dns_update_record('ldap', 'test', ttl=999)
        self.assertEqual(rec.version, 5)
        self.assertEqual(rec.rank, 240)          # rank gets fixed by DNS update
        defer_assertEqual(rec.flags, 0)          # flags gets fixed
        defer_assertEqual(rec.dwSerial, 45)      # serial increments
        self.assertEqual(rec.dwTtlSeconds, 999)  # TTL set
        defer_assertEqual(rec.dwReserved, 0)     # reserved fixed
        defer_assert_timestamp_in_ballpark(rec)  # changed on Windows ?!

        self.set_aging(True)
        rec = self.dns_update_record('ldap', 'test', ttl=1111)
        self.assertEqual(rec.version, 5)
        self.assertEqual(rec.rank, 240)
        defer_assertEqual(rec.flags, 0)
        defer_assertEqual(rec.dwSerial, 46)
        self.assertEqual(rec.dwTtlSeconds, 1111)  # TTL set
        defer_assertEqual(rec.dwReserved, 0)
        self.assert_timestamp_in_ballpark(rec)

        # RPC update
        rec = self.rpc_update_record('ldap', 'test',
                                     version=111,
                                     dwFlags=333,
                                     dwSerial=444,
                                     dwTtlSeconds=555,
                                     dwReserved=666,
                                     dwTimeStamp=777)

        self.assertEqual(rec.version, 5)         # no change
        self.assertEqual(rec.rank, 240)          # no change
        defer_assertEqual(rec.flags, 0)           # no change
        defer_assertEqual(rec.dwSerial, 47)       # Serial increments
        self.assertEqual(rec.dwTtlSeconds, 555)  # TTL set
        defer_assertEqual(rec.dwReserved, 0)      # no change
        self.assertEqual(rec.dwTimeStamp, 0)     # timestamp zeroed

        # RPC update, using default values
        rec = self.rpc_update_record('ldap', 'test')
        self.assertEqual(rec.version, 5)
        self.assertEqual(rec.rank, 240)
        defer_assertEqual(rec.flags, 0)
        defer_assertEqual(rec.dwSerial, 48)       # serial increments
        self.assertEqual(rec.dwTtlSeconds, 900)  # TTL changed
        defer_assertEqual(rec.dwReserved, 0)
        self.assertEqual(rec.dwTimeStamp, 0)

        self.set_aging(False)
        rec = self.dns_update_record('ldap', 'test', ttl=888)
        self.assertEqual(rec.version, 5)
        self.assertEqual(rec.rank, 240)
        defer_assertEqual(rec.flags, 0)
        defer_assertEqual(rec.dwSerial, 49)       # serial increments
        self.assertEqual(rec.dwTtlSeconds, 888)  # TTL set
        defer_assertEqual(rec.dwReserved, 0)
        self.assertEqual(rec.dwTimeStamp, 0)     # timestamp stays zero

        if failures:
            self.fail(f"failed {failures}/{total} deferred assertions")

    def test_static_record_dynamic_update(self):
        """Add a static record, then a dynamic record.
        The dynamic record should have a timestamp set."""
        name = 'test'
        txt = ['static txt']
        txt2 = ['dynamic txt']
        self.set_aging(True)
        rec = self.ldap_update_record(name, txt, dwTimeStamp=0)
        rec2 = self.dns_update_record(name, txt2)
        self.assert_timestamp_in_ballpark(rec2)
        ts2 = rec2.dwTimeStamp
        # update the first record. It should stay static (timestamp 0)
        rec = self.dns_update_record(name, txt)
        self.assertEqual(rec.dwTimeStamp, 0)
        # and rec2 should be unchanged.
        self.assertEqual(rec2.dwTimeStamp, ts2)

    def test_dynamic_record_static_update(self):
        name = 'agingtest'
        txt1 = ['dns update before']
        txt2 = ['ldap update']
        txt3 = ['dns update after']
        self.set_aging(True)

        self.dns_update_record(name, txt1)
        self.ldap_update_record(name, txt2)
        self.dns_update_record(name, txt3)

        recs = self.get_rpc_records(name)
        for r in recs:
            d = [x.str for x in r.data.str]
            if d == txt1:
                self.assertNotEqual(r.dwTimeStamp, 0)
            elif d == txt2:
                self.assertEqual(r.dwTimeStamp, 0)
            elif d == txt3:
                self.assertNotEqual(r.dwTimeStamp, 0)

    def test_tombstone_in_hours_and_nttime(self):
        # Until now Samba has measured tombstone timestamps in hours,
        # not ten-millionths of a second. After now, we want Samba to
        # handle both.

        nh, oh, nn, on, on0, onf, nn0, nnf, _1601 = 'abcdefgij'
        now_hours = dsdb_dns.unix_to_dns_timestamp(int(time.time()))
        old_hours = now_hours - 24 * 90
        now_nttime = dsdb_dns.dns_timestamp_to_nt_time(now_hours)
        old_nttime = dsdb_dns.dns_timestamp_to_nt_time(old_hours)
        # calculations on hours might be based on the lower 32 bits,
        # so we test with these forced to extremes (the maximum change
        # is 429 seconds in NTTIME).
        old_nttime0 = old_nttime & 0xffffffff00000000
        old_nttimef = old_nttime | 0xffffffff
        now_nttime0 = now_nttime & 0xffffffff00000000
        now_nttimef = now_nttime | 0xffffffff
        self.dns_tombstone(nh, epoch_nttime=now_hours)
        self.dns_tombstone(oh, epoch_nttime=old_hours)
        self.dns_tombstone(nn, epoch_nttime=now_nttime)
        self.dns_tombstone(on, epoch_nttime=old_nttime)
        self.dns_tombstone(nn0, epoch_nttime=now_nttime0)
        self.dns_tombstone(nnf, epoch_nttime=now_nttimef)
        self.dns_tombstone(on0, epoch_nttime=old_nttime0)
        self.dns_tombstone(onf, epoch_nttime=old_nttimef)
        # this is our (arbitrary) threshold that will make us think in
        # NTTIME, not hours.
        self.dns_tombstone(_1601, epoch_nttime=(10 * 1000 * 1000 + 1))

        try:
            file_samdb = get_file_samdb()
        except ldb.LdbError as e:
            raise AssertionError(
                f"failing because '{e}': this is Windows?") from None
        dsdb._dns_delete_tombstones(file_samdb)

        # nh and nn should not be deleted
        for name in nh, nn, nn0, nnf:
            recs = self.ldap_get_records(name)
            self.assertEqual(len(recs), 1)
            self.assert_tombstoned(name, timestamp=False)

        # oh and on should be GONE
        for name in oh, on, on0, onf, _1601:
            recs = self.ldap_get_records(name)
            self.assertEqual(len(recs), 0)

    def test_dns_query_for_tombstoned_results(self):
        # This one fails on Windows, because the dns cache holds B
        # after it has been tombstoned behind its back.
        A = 'a'
        B = 'b'
        self.dns_tombstone(A)
        self.assert_tombstoned(A)
        r = self.dns_query(A, qtype=dns.DNS_QTYPE_TXT)
        self.assertEqual(r.ancount, 0)

        self.dns_update_record(B, B)
        self.dns_tombstone(B)
        self.assert_tombstoned(B)
        r = self.dns_query(B, qtype=dns.DNS_QTYPE_TXT)
        self.assertEqual(r.ancount, 0)

    def test_basic_scavenging(self):
        # NOTE: This one fails on Windows, because the RPC call to
        # prompt scavenging is not immediate. On Samba, in the
        # testenv, we don't have the RPC call but we can connect to
        # the database directly.

        # just to be sure we have the right limits.
        self.set_zone_int_params(NoRefreshInterval=168,
                                 RefreshInterval=168,
                                 Aging=1)

        ts1, ts2, ts3, ts4, ts5, ts6 = ('1', '2', '3', '4', '5', '6')
        self.dns_update_record(ts1, ts1)
        self.dns_update_record(ts2, ts2)
        # ts2 is tombstoned and timestamped in 1981
        self.dns_tombstone(ts2)
        # ts3 is tombstoned and timestamped in the future
        self.dns_tombstone(ts3, epoch_hours=(DNS_TIMESTAMP_2101 - 1))
        # ts4 is tombstoned and timestamped in the past
        self.dns_tombstone(ts4, epoch_hours=1111111)
        # ts5 is tombstoned in the past and timestamped in the future
        self.dns_tombstone(ts5, epoch_hours=5555555, epoch_nttime=int(1e10))

        # ts2 and ts3 should now be tombstoned.
        self.assert_tombstoned(ts2)
        self.assert_tombstoned(ts3)

        # let's un-tombstone ts2
        # ending up with dnsTombstoned: FALSE in Samba
        # and no dNSTombstoned in Windows.
        self.dns_update_record(ts2, "ts2 untombstoned")
        ts2_node = self.get_one_node(ts2)
        ts2_tombstone = ts2_node.get("dNSTombstoned")
        if ts2_tombstone is not None:
            self.assertEqual(ts2_tombstone[0], b"FALSE")

        self.assert_tombstoned(ts2, tombstoned=False)

        r = self.dns_update_record(ts6, ts6)

        # put some records into the death zone.
        self.ldap_modify_timestamps(ts1, -15 * 24)
        self.ldap_modify_timestamps(ts2, -14 * 24 - 2)
        self.ldap_modify_timestamps(ts6, -14 * 24 + 2)

        # ts1 will be saved by this record
        self.dns_update_record(ts1, "another record")

        try:
            # Tell the server to clean-up records.
            # This is how it *should* work on Windows:
            self.rpc_conn.DnssrvOperation2(
                dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                0,
                SERVER_IP,
                None,
                0,
                "StartScavenging",
                dnsserver.DNSSRV_TYPEID_NULL,
                None)
            # Samba won't get here (NOT_IMPLEMENTED error)
            # wait for Windows to do its cleanup.
            time.sleep(2)
        except WERRORError as e:
            if e.args[0] == werror.WERR_CALL_NOT_IMPLEMENTED:
                # This is the Samba way, talking to the file directly,
                # as if we were the server process. The direct
                # connection is needed because the tombstoning search
                # involves a magic system only filter.
                file_samdb = get_file_samdb()
                dsdb._scavenge_dns_records(file_samdb)
                dsdb._dns_delete_tombstones(file_samdb)
            else:
                raise

        # Now what we should have:
        # ts1: alive: the old record is deleted, the new one not.
        # ts2: tombstoned
        # ts3: tombstoned
        # ts4: deleted. gone.
        # ts5: deleted. timestamp affects tombstoning, but not deletion.
        # ts6: alive
        #
        # We order our assertions to make the windows test
        # fail as late as possible (on ts4, ts5, ts2).
        r = self.get_unique_txt_record(ts1, ["another record"])
        self.assertIsNotNone(r)
        r = self.get_unique_txt_record(ts6, [ts6])
        self.assertIsNotNone(r)

        self.assert_tombstoned(ts3)

        n = self.get_one_node(ts4)
        self.assertIsNone(n)
        n = self.get_one_node(ts5)
        self.assertIsNone(n)

        self.assert_tombstoned(ts2)

    def test_samba_scavenging(self):
        # We expect this one to fail on Windows, because scavenging
        # and tombstoning cannot be performed on demand.

        try:
            file_samdb = get_file_samdb()
        except ldb.LdbError as e:
            raise AssertionError(
                f"failing because '{e}': this is Windows?") from None

        # let's try different limits.
        self.set_zone_int_params(NoRefreshInterval=30,
                                 RefreshInterval=20,
                                 Aging=1)

        now = dsdb_dns.unix_to_dns_timestamp(int(time.time()))

        A, B, C, D = 'ABCD'
        # A has current time
        # B has safe, non-updateable time
        # C has safe time
        # D is scavengeable
        atime = self.dns_update_record(A, A).dwTimeStamp
        btime = self.ldap_update_record(B, B, dwTimeStamp=now-20).dwTimeStamp
        ctime = self.ldap_update_record(C, C, dwTimeStamp=now-40).dwTimeStamp
        dtime = self.ldap_update_record(D, D, dwTimeStamp=now-60).dwTimeStamp
        self.assert_soon_after(atime, now)
        self.assert_timestamps_equal(btime, now-20)
        self.assert_timestamps_equal(ctime, now-40)
        self.assert_timestamps_equal(dtime, now-60)

        dsdb._scavenge_dns_records(file_samdb)

        # D should be gone (tombstoned)
        r = self.get_unique_txt_record(D, D)
        self.assertIsNone(r)
        r = self.dns_query(D, qtype=dns.DNS_QTYPE_TXT)
        self.assertEqual(r.ancount, 0)
        recs = self.ldap_get_records(D)
        self.assertEqual(len(recs), 1)
        self.assert_tombstoned(recs[0])

        # others unchanged.
        atime = self.get_unique_txt_record(A, A).dwTimeStamp
        btime = self.get_unique_txt_record(B, B).dwTimeStamp
        ctime = self.get_unique_txt_record(C, C).dwTimeStamp
        self.assert_soon_after(atime, now)
        self.assert_timestamps_equal(btime, now-20)
        self.assert_timestamps_equal(ctime, now-40)

        btime = self.dns_update_record(B, B).dwTimeStamp
        ctime = self.dns_update_record(C, C).dwTimeStamp
        self.assert_timestamps_equal(btime, now-40)
        self.assert_soon_after(ctime, now)

        # after this, D *should* still be a tombstone, because its
        # tombstone timestamp is not very old.
        dsdb._dns_delete_tombstones(file_samdb)
        recs = self.ldap_get_records(D)
        self.assertEqual(len(recs), 1)
        self.assert_tombstoned(recs[0])

        # Let's delete C using rpc, and ensure it survives dns_delete_tombstones
        self.rpc_delete_txt(C, C)
        recs = self.ldap_get_records(C)
        self.assertEqual(len(recs), 1)
        self.assert_tombstoned(recs[0])
        dsdb._dns_delete_tombstones(file_samdb)
        recs = self.ldap_get_records(C)
        self.assertEqual(len(recs), 1)
        self.assert_tombstoned(recs[0])

        # now let's wind A and B back to either side of the two week
        # threshold. A should survive, B should not.
        self.dns_tombstone(A, (now - 166))
        self.dns_tombstone(B, (now - 170))
        dsdb._dns_delete_tombstones(file_samdb)

        recs = self.ldap_get_records(A)
        self.assertEqual(len(recs), 1)
        self.assert_tombstoned(recs[0])

        recs = self.ldap_get_records(B)
        self.assertEqual(len(recs), 0)

    def _test_A_and_AAAA_records(self, A, B, a_days, b_days, aging):
        self.set_aging(aging)

        name = 'aargh'
        now = dsdb_dns.unix_to_dns_timestamp(int(time.time()))
        a_initial = now - 24 * a_days
        b_initial = now - 24 * b_days

        self.dns_update_non_text(name, A)
        self.ldap_modify_timestamps(name, a_days * -24)

        rec_a = self.get_unique_ip_record(name, A)
        rec_b = self.add_ip_record(name, B, dwTimeStamp=b_initial)

        self.assert_timestamps_equal(rec_a, a_initial)
        self.assert_timestamps_equal(rec_b, b_initial)

        # touch the A record.
        self.dns_update_non_text(name, A)

        # check the A timestamp, depending on norefresh
        rec_a = self.get_unique_ip_record(name, A)
        if aging and a_days > 7:
            time_a = now
            self.assert_soon_after(rec_a, now)
        elif a_days > 7:
            # when we have NO aging and are in the refresh window, the
            # timestamp now reads as a_initial, but will become now
            # after we manipulate B for a bit.
            time_a = now
            self.assert_timestamps_equal(rec_a, a_initial)
        else:
            time_a = a_initial
            self.assert_timestamps_equal(rec_a, a_initial)

        # B timestamp should be unchanged?
        rec_b = self.get_unique_ip_record(name, B)
        self.assert_timestamps_equal(rec_b, b_initial)

        # touch the B record.
        self.dns_update_non_text(name, B)

        # check the B timestamp
        rec_b = self.get_unique_ip_record(name, B)
        if not aging:
            self.windows_variation(
                self.assert_soon_after, rec_b, now,
                msg="windows updates non-aging, samba does not")
        else:
            self.assert_soon_after(rec_b, now)

        # rewind B
        rec_b = self.add_ip_record(name, B, dwTimeStamp=b_initial)

        # NOW rec A might have changed! with no aging, and out of refresh.
        rec_a = self.get_unique_ip_record(name, A)
        self.assert_timestamps_equal(rec_a, time_a)

        self.dns_update_non_text(name, A)

        rec_a = self.get_unique_ip_record(name, B)
        self.assert_timestamps_equal(rec_b, b_initial)

        # now delete A
        _, wtype = guess_wtype(A)
        self.ldap_delete_record(name, A, wtype=wtype)

        # re-add it
        self.dns_update_non_text(name, A)

        rec_a = self.get_unique_ip_record(name, A)
        self.assert_soon_after(rec_a, now)

        rec_b = self.get_unique_ip_record(name, B)
        self.assert_timestamps_equal(rec_b, b_initial)

    def test_A_5_days_AAAA_5_days_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 5, 5, aging=True)

    def test_A_5_days_AAAA_5_days_no_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 5, 5, aging=False)

    def test_A_5_days_AAAA_10_days_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 5, 10, aging=True)

    def test_A_5_days_AAAA_10_days_no_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 5, 10, aging=False)

    def test_A_10_days_AAAA_5_days_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 10, 5, aging=True)

    def test_A_10_days_AAAA_5_days_no_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 10, 5, aging=False)

    def test_A_10_days_AAAA_9_days_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 10, 9, aging=True)

    def test_A_9_days_AAAA_10_days_no_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 9, 10, aging=False)

    def test_A_20_days_AAAA_2_days_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 20, 2, aging=True)

    def test_A_6_days_AAAA_40_days_no_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv6_ADDR, 6, 40, aging=False)

    def test_A_5_days_A_5_days_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv4_ADDR_2, 5, 5, aging=True)

    def test_A_5_days_A_10_days_no_aging(self):
        self._test_A_and_AAAA_records(IPv4_ADDR, IPv4_ADDR_2, 5, 10, aging=False)

    def test_AAAA_5_days_AAAA_6_days_aging(self):
        self._test_A_and_AAAA_records(IPv6_ADDR, IPv6_ADDR_2, 5, 6, aging=True)

    def test_AAAA_5_days_AAAA_6_days_no_aging(self):
        self._test_A_and_AAAA_records(IPv6_ADDR, IPv6_ADDR_2, 5, 6, aging=False)

    def _test_multi_records_delete(self, aging):
        # Batch deleting a type doesn't update other types timestamps.
        self.set_aging(aging)

        name = 'aargh'
        now = dsdb_dns.unix_to_dns_timestamp(int(time.time()))

        back_5_days = now - 5 * 24
        back_10_days = now - 10 * 24
        back_25_days = now - 25 * 24

        ip4s = {
            '1.1.1.1': now,
            '2.2.2.2': back_5_days,
            '3.3.3.3': back_10_days,
        }
        ip6s = {
            '::1': now,
            '::2': back_5_days,
            '::3': back_25_days,
        }

        txts = {
            '1': now,
            '2': back_5_days,
            '3': back_25_days,
        }

        # For windows, if we don't DNS update something, it won't know
        # there's anything.
        self.dns_update_record(name, '3')

        for k, v in ip4s.items():
            r = self.add_ip_record(name, k, wtype=dns.DNS_QTYPE_A, dwTimeStamp=v)

        for k, v in ip6s.items():
            r = self.add_ip_record(name, k, wtype=dns.DNS_QTYPE_AAAA, dwTimeStamp=v)

        for k, v in txts.items():
            r = self.ldap_update_record(name, k, dwTimeStamp=v)

        self.dns_delete_type(name, dnsp.DNS_TYPE_A)

        r = self.dns_query(name, dns.DNS_QTYPE_A)
        self.assertEqual(r.ancount, 0)

        r = self.dns_query(name, dns.DNS_QTYPE_TXT)
        self.assertEqual(r.ancount, 3)
        rset = set(x.rdata.txt.str[0] for x in r.answers)
        self.assertEqual(rset, set(txts))

        r = self.dns_query(name, dns.DNS_QTYPE_AAAA)
        self.assertEqual(r.ancount, 3)
        rset = set(ipv6_normalise(x.rdata) for x in r.answers)
        self.assertEqual(rset, set(ip6s))

        recs = self.ldap_get_records(name)
        self.assertEqual(len(recs), 6)
        for r in recs:
            if r.wType == dns.DNS_QTYPE_AAAA:
                k = ipv6_normalise(r.data)
                expected = ip6s[k]
            elif r.wType == dns.DNS_QTYPE_TXT:
                k = r.data.str[0]
                expected = txts[k]
            else:
                self.fail(f"unexpected wType {r.wType}")

            self.assert_timestamps_equal(r.dwTimeStamp, expected)

    def test_multi_records_delete_aging(self):
        self._test_multi_records_delete(True)

    def test_multi_records_delete_no_aging(self):
        self._test_multi_records_delete(False)

    def _test_dns_delete_times(self, n_days, aging=True):
        # In these tests, Windows replaces the records with
        # tombstones, while Samba just removes them. Both are
        # reasonable approaches (there is no reanimation pathway for
        # tombstones), but this means self.ldap_get_records() gets
        # different numbers for each. So we use
        # self.ldap_get_non_tombstoned_record().
        name = 'test'
        A = ['A']
        B = ['B']
        C = ['C']
        D = ['D']
        self.set_aging(aging)
        now = dsdb_dns.unix_to_dns_timestamp(int(time.time()))
        n_days_ago = max(now - n_days * 24, 0)

        self.dns_update_record(name, A)
        self.ldap_update_record(name, A, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, B, dwTimeStamp=n_days_ago)
        self.ldap_update_record(name, C, dwTimeStamp=n_days_ago)
        self.dns_update_record(name, D)
        r = self.dns_query(name, dns.DNS_QTYPE_TXT)
        rset = set(x.rdata.txt.str[0] for x in r.answers)
        self.assertEqual(rset, set('ABCD'))

        atime = self.get_unique_txt_record(name, A).dwTimeStamp
        btime = self.get_unique_txt_record(name, B).dwTimeStamp
        ctime = self.get_unique_txt_record(name, C).dwTimeStamp
        dtime = self.get_unique_txt_record(name, D).dwTimeStamp
        recs = self.ldap_get_records(name)
        self.assertEqual(len(recs), 4)
        r = self.dns_query(name, dns.DNS_QTYPE_TXT)
        rset = set(x.rdata.txt.str[0] for x in r.answers)
        self.assertEqual(rset, set('ABCD'))

        self.dns_delete(name, D)
        self.assert_timestamps_equal(atime, self.get_unique_txt_record(name, A))
        self.assert_timestamps_equal(btime, self.get_unique_txt_record(name, B))
        self.assert_timestamps_equal(ctime, self.get_unique_txt_record(name, C))
        recs = self.ldap_get_non_tombstoned_records(name)
        self.assertEqual(len(recs), 3)
        r = self.dns_query(name, dns.DNS_QTYPE_TXT)
        rset = set(x.rdata.txt.str[0] for x in r.answers)
        self.assertEqual(rset, set('ABC'))

        self.rpc_delete_txt(name, C)
        self.assert_timestamps_equal(atime, self.get_unique_txt_record(name, A))
        self.assert_timestamps_equal(btime, self.get_unique_txt_record(name, B))
        recs = self.ldap_get_non_tombstoned_records(name)
        self.assertEqual(len(recs), 2)
        r = self.dns_query(name, dns.DNS_QTYPE_TXT)
        rset = set(x.rdata.txt.str[0] for x in r.answers)
        self.assertEqual(rset, set('AB'))

        self.dns_delete(name, A)
        self.assert_timestamps_equal(btime, self.get_unique_txt_record(name, B))
        recs = self.ldap_get_records(name)
        self.assertEqual(len(recs), 1)
        r = self.dns_query(name, dns.DNS_QTYPE_TXT)
        rset = set(x.rdata.txt.str[0] for x in r.answers)
        self.assertEqual(rset, {'B'})

        self.dns_delete(name, B)
        recs = self.ldap_get_non_tombstoned_records(name)
        # Windows leaves the node with zero records. Samba ends up
        # with a tombstone.
        self.assertEqual(len(recs), 0)
        r = self.dns_query(name, dns.DNS_QTYPE_TXT)
        rset = set(x.rdata.txt.str[0] for x in r.answers)
        self.assertEqual(len(rset), 0)

    def test_dns_delete_times_5_days_aging(self):
        self._test_dns_delete_times(5, True)

    def test_dns_delete_times_11_days_aging(self):
        self._test_dns_delete_times(11, True)

    def test_dns_delete_times_366_days_aging(self):
        self._test_dns_delete_times(366, True)

    def test_dns_delete_times_static_aging(self):
        self._test_dns_delete_times(1e10, True)

    def test_dns_delete_times_5_days_no_aging(self):
        self._test_dns_delete_times(5, False)

    def test_dns_delete_times_11_days_no_aging(self):
        self._test_dns_delete_times(11, False)

    def test_dns_delete_times_366_days_no_aging(self):
        self._test_dns_delete_times(366, False)

    def test_dns_delete_times_static_no_aging(self):
        self._test_dns_delete_times(1e10, False)

    def _test_dns_delete_simple(self, a_days, b_days, aging=True, touch=False):
        # Here we show that with aging enabled, the timestamp of
        # sibling records is *not* modified when a record is deleted.
        #
        # With aging disabled, it *is* modified, if the dns server has
        # seen it updated before ldap set the time (that is, probably
        # the dns server overwrites AD). This happens even if AD
        # thinks the record is static.
        name = 'test'
        A = ['A']
        B = ['B']
        self.set_aging(aging)
        now = dsdb_dns.unix_to_dns_timestamp(int(time.time()))
        a_days_ago = max(now - a_days * 24, 0)
        b_days_ago = max(now - b_days * 24, 0)

        if touch:
            self.dns_update_record(name, A)
            self.dns_update_record(name, B)

        self.ldap_update_record(name, A, dwTimeStamp=a_days_ago)
        self.ldap_update_record(name, B, dwTimeStamp=b_days_ago)

        atime = self.get_unique_txt_record(name, A).dwTimeStamp

        self.dns_delete(name, B)
        if not aging and touch:
            # this resets the timestamp even if it is a static record.
            self.assert_soon_after(self.get_unique_txt_record(name, A), now)
        else:
            self.assert_timestamps_equal(self.get_unique_txt_record(name, A), atime)

    def test_dns_delete_simple_2_3_days_aging(self):
        self._test_dns_delete_simple(2, 3, True)

    def test_dns_delete_simple_2_3_days_no_aging(self):
        self._test_dns_delete_simple(2, 3, False)

    def test_dns_delete_simple_2_13_days_aging(self):
        self._test_dns_delete_simple(2, 13, True)

    def test_dns_delete_simple_2_13_days_no_aging(self):
        self._test_dns_delete_simple(2, 13, False)

    def test_dns_delete_simple_12_13_days_aging(self):
        self._test_dns_delete_simple(12, 13, True)

    def test_dns_delete_simple_12_13_days_no_aging(self):
        self._test_dns_delete_simple(12, 13, False)

    def test_dns_delete_simple_112_113_days_aging(self):
        self._test_dns_delete_simple(112, 113, True)

    def test_dns_delete_simple_112_113_days_no_aging(self):
        self._test_dns_delete_simple(112, 113, False)

    def test_dns_delete_simple_0_113_days_aging(self):
        # 1e9 hours ago evaluates to 0, i.e static
        self._test_dns_delete_simple(1e9, 113, True)

    def test_dns_delete_simple_0_113_days_no_aging(self):
        self._test_dns_delete_simple(1e9, 113, False)

    def test_dns_delete_simple_0_0_days_aging(self):
        self._test_dns_delete_simple(1e9, 1e9, True)

    def test_dns_delete_simple_0_0_days_no_aging(self):
        self._test_dns_delete_simple(1e9, 1e9, False)

    def test_dns_delete_simple_10_0_days_aging(self):
        self._test_dns_delete_simple(10, 1e9, True)

    def test_dns_delete_simple_10_0_days_no_aging(self):
        self._test_dns_delete_simple(10, 1e9, False)

    def test_dns_delete_simple_2_3_days_aging_touch(self):
        self._test_dns_delete_simple(2, 3, True, True)

    def test_dns_delete_simple_2_3_days_no_aging_touch(self):
        self._test_dns_delete_simple(2, 3, False, True)

    def test_dns_delete_simple_2_13_days_aging_touch(self):
        self._test_dns_delete_simple(2, 13, True, True)

    def test_dns_delete_simple_2_13_days_no_aging_touch(self):
        self._test_dns_delete_simple(2, 13, False, True)

    def test_dns_delete_simple_12_13_days_aging_touch(self):
        self._test_dns_delete_simple(12, 13, True, True)

    def test_dns_delete_simple_12_13_days_no_aging_touch(self):
        self._test_dns_delete_simple(12, 13, False, True)

    def test_dns_delete_simple_112_113_days_aging_touch(self):
        self._test_dns_delete_simple(112, 113, True, True)

    def test_dns_delete_simple_112_113_days_no_aging_touch(self):
        self._test_dns_delete_simple(112, 113, False, True)

    def test_dns_delete_simple_0_113_days_aging_touch(self):
        # 1e9 hours ago evaluates to 0, i.e static
        self._test_dns_delete_simple(1e9, 113, True, True)

    def test_dns_delete_simple_0_113_days_no_aging_touch(self):
        self._test_dns_delete_simple(1e9, 113, False, True)

    def test_dns_delete_simple_0_0_days_aging_touch(self):
        self._test_dns_delete_simple(1e9, 1e9, True, True)

    def test_dns_delete_simple_0_0_days_no_aging_touch(self):
        self._test_dns_delete_simple(1e9, 1e9, False, True)

    def test_dns_delete_simple_10_0_days_aging_touch(self):
        self._test_dns_delete_simple(10, 1e9, True, True)

    def test_dns_delete_simple_10_0_days_no_aging_touch(self):
        self._test_dns_delete_simple(10, 1e9, False, True)

    def windows_variation(self, fn, *args, msg=None, **kwargs):
        try:
            fn(*args, **kwargs)
        except AssertionError as e:
            print("Expected success on Windows only, failed as expected:\n" +
                  c_GREEN(e))
            return
        print(c_RED("known Windows failure"))
        if msg is not None:
            print(c_DARK_YELLOW(msg))
        print("Expected success on Windows:\n" +
              c_GREEN(f"{fn.__name__} {args} {kwargs}"))

    def _test_dns_add_sibling(self, a_days, refresh, aging=True, touch=False):
        # Here we show that with aging enabled, the timestamp of
        # sibling records *is* modified when a record is added.
        #
        # With aging disabled, it *is* modified, if the dns server has
        # seen it updated before ldap set the time (that is, probably
        # the dns server overwrites AD). This happens even if AD
        # thinks the record is static.
        name = 'test'
        A = ['A']
        B = ['B']
        self.set_zone_int_params(RefreshInterval=int(refresh),
                                 NoRefreshInterval=7,
                                 Aging=int(aging))

        now = dsdb_dns.unix_to_dns_timestamp(int(time.time()))
        a_days_ago = max(now - a_days * 24, 0)

        if touch:
            self.dns_update_record(name, A)

        self.ldap_update_record(name, A, dwTimeStamp=a_days_ago)

        atime = self.get_unique_txt_record(name, A).dwTimeStamp

        self.dns_update_record(name, B)
        a_rec = self.get_unique_txt_record(name, A)
        if not aging and touch:
            # On Windows, this resets the timestamp even if it is a
            # static record, though in that case it may be a
            # transitory effect of the DNS cache. We will insist on
            # the Samba behaviour of not changing (that is
            # un-static-ing) a zero timestamp, because that is the
            # sensible thing.
            if a_days_ago == 0:
                self.windows_variation(
                    self.assert_soon_after, a_rec, now,
                    msg="Windows resets static siblings (cache effect?)")
                self.assert_timestamps_equal(a_rec, 0)
            else:
                self.assert_soon_after(a_rec, now)
        else:
            self.assert_timestamps_equal(a_rec, atime)

        b_rec = self.get_unique_txt_record(name, B)
        self.assert_soon_after(b_rec, now)

    def test_dns_add_sibling_2_7_days_aging(self):
        self._test_dns_add_sibling(2, 7, True)

    def test_dns_add_sibling_2_7_days_no_aging(self):
        self._test_dns_add_sibling(2, 7, False)

    def test_dns_add_sibling_12_7_days_aging(self):
        self._test_dns_add_sibling(12, 7, True)

    def test_dns_add_sibling_12_7_days_no_aging(self):
        self._test_dns_add_sibling(12, 7, False)

    def test_dns_add_sibling_12_3_days_aging(self):
        self._test_dns_add_sibling(12, 3, True)

    def test_dns_add_sibling_12_3_days_no_aging(self):
        self._test_dns_add_sibling(12, 3, False)

    def test_dns_add_sibling_112_7_days_aging(self):
        self._test_dns_add_sibling(112, 7, True)

    def test_dns_add_sibling_112_7_days_no_aging(self):
        self._test_dns_add_sibling(112, 7, False)

    def test_dns_add_sibling_12_113_days_aging(self):
        self._test_dns_add_sibling(12, 113, True)

    def test_dns_add_sibling_12_113_days_no_aging(self):
        self._test_dns_add_sibling(12, 113, False)

    def test_dns_add_sibling_0_7_days_aging(self):
        # 1e9 days ago evaluates to 0, i.e static
        self._test_dns_add_sibling(1e9, 7, True)

    def test_dns_add_sibling_0_7_days_no_aging(self):
        self._test_dns_add_sibling(1e9, 7, False)

    def test_dns_add_sibling_0_0_days_aging(self):
        self._test_dns_add_sibling(1e9, 0, True)

    def test_dns_add_sibling_0_0_days_no_aging(self):
        self._test_dns_add_sibling(1e9, 0, False)

    def test_dns_add_sibling_10_0_days_aging(self):
        self._test_dns_add_sibling(10, 0, True)

    def test_dns_add_sibling_10_0_days_no_aging(self):
        self._test_dns_add_sibling(10, 0, False)

    def test_dns_add_sibling_2_7_days_aging_touch(self):
        self._test_dns_add_sibling(2, 7, True, True)

    def test_dns_add_sibling_2_7_days_no_aging_touch(self):
        self._test_dns_add_sibling(2, 7, False, True)

    def test_dns_add_sibling_12_7_days_aging_touch(self):
        self._test_dns_add_sibling(12, 7, True, True)

    def test_dns_add_sibling_12_7_days_no_aging_touch(self):
        self._test_dns_add_sibling(12, 7, False, True)

    def test_dns_add_sibling_12_3_days_aging_touch(self):
        self._test_dns_add_sibling(12, 3, True, True)

    def test_dns_add_sibling_12_3_days_no_aging_touch(self):
        self._test_dns_add_sibling(12, 3, False, True)

    def test_dns_add_sibling_112_7_days_aging_touch(self):
        self._test_dns_add_sibling(112, 7, True, True)

    def test_dns_add_sibling_112_7_days_no_aging_touch(self):
        self._test_dns_add_sibling(112, 7, False, True)

    def test_dns_add_sibling_12_113_days_aging_touch(self):
        self._test_dns_add_sibling(12, 113, True, True)

    def test_dns_add_sibling_12_113_days_no_aging_touch(self):
        self._test_dns_add_sibling(12, 113, False, True)

    def test_dns_add_sibling_0_7_days_aging_touch(self):
        self._test_dns_add_sibling(1e9, 7, True, True)

    def test_dns_add_sibling_0_7_days_no_aging_touch(self):
        self._test_dns_add_sibling(1e9, 7, False, True)

    def test_dns_add_sibling_0_0_days_aging_touch(self):
        self._test_dns_add_sibling(1e9, 0, True, True)

    def test_dns_add_sibling_0_0_days_no_aging_touch(self):
        self._test_dns_add_sibling(1e9, 0, False, True)

    def test_dns_add_sibling_10_0_days_aging_touch(self):
        self._test_dns_add_sibling(10, 0, True, True)

    def test_dns_add_sibling_10_0_days_no_aging_touch(self):
        self._test_dns_add_sibling(10, 0, False, True)

TestProgram(module=__name__, opts=subunitopts)

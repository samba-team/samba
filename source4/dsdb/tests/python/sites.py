#!/usr/bin/env python3
#
# Unit tests for sites manipulation in samba
# Copyright (C) Matthieu Patou <mat@matws.net> 2011
#
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
from __future__ import print_function

import optparse
import sys
sys.path.insert(0, "bin/python")
import samba

from samba.tests.subunitrun import TestProgram, SubunitOptions

import samba.getopt as options
from samba import sites
from samba import subnets
from samba.auth import system_session
from samba.samdb import SamDB
from samba import gensec
from samba.credentials import Credentials, DONT_USE_KERBEROS
import samba.tests
from samba.tests import delete_force
from samba.dcerpc import security
from ldb import SCOPE_SUBTREE, LdbError, ERR_INSUFFICIENT_ACCESS_RIGHTS

parser = optparse.OptionParser("sites.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]
if "://" not in host:
    ldaphost = "ldap://%s" % host
else:
    ldaphost = host

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

#
# Tests start here
#


class SitesBaseTests(samba.tests.TestCase):

    def setUp(self):
        super(SitesBaseTests, self).setUp()
        self.ldb = SamDB(ldaphost, credentials=creds,
                         session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.domain_sid = security.dom_sid(self.ldb.get_domain_sid())
        self.configuration_dn = self.ldb.get_config_basedn().get_linearized()

    def get_user_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)


# tests on sites
class SimpleSitesTests(SitesBaseTests):

    def test_create_and_delete(self):
        """test creation and deletion of 1 site"""

        sites.create_site(self.ldb, self.ldb.get_config_basedn(),
                          "testsamba")

        self.assertRaises(sites.SiteAlreadyExistsException,
                          sites.create_site, self.ldb,
                          self.ldb.get_config_basedn(),
                          "testsamba")

        sites.delete_site(self.ldb, self.ldb.get_config_basedn(),
                          "testsamba")

        self.assertRaises(sites.SiteNotFoundException,
                          sites.delete_site, self.ldb,
                          self.ldb.get_config_basedn(),
                          "testsamba")

    def test_delete_not_empty(self):
        """test removal of 1 site with servers"""

        self.assertRaises(sites.SiteServerNotEmptyException,
                          sites.delete_site, self.ldb,
                          self.ldb.get_config_basedn(),
                          "Default-First-Site-Name")


# tests for subnets
class SimpleSubnetTests(SitesBaseTests):

    def setUp(self):
        super(SimpleSubnetTests, self).setUp()
        self.basedn = self.ldb.get_config_basedn()
        self.sitename = "testsite"
        self.sitename2 = "testsite2"
        self.ldb.transaction_start()
        sites.create_site(self.ldb, self.basedn, self.sitename)
        sites.create_site(self.ldb, self.basedn, self.sitename2)
        self.ldb.transaction_commit()

    def tearDown(self):
        self.ldb.transaction_start()
        sites.delete_site(self.ldb, self.basedn, self.sitename)
        sites.delete_site(self.ldb, self.basedn, self.sitename2)
        self.ldb.transaction_commit()
        super(SimpleSubnetTests, self).tearDown()

    def test_create_delete(self):
        """Create a subnet and delete it again."""
        basedn = self.ldb.get_config_basedn()
        cidr = "10.11.12.0/24"

        subnets.create_subnet(self.ldb, basedn, cidr, self.sitename)

        self.assertRaises(subnets.SubnetAlreadyExists,
                          subnets.create_subnet, self.ldb, basedn, cidr,
                          self.sitename)

        subnets.delete_subnet(self.ldb, basedn, cidr)

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % cidr)

        self.assertEqual(len(ret), 0, 'Failed to delete subnet %s' % cidr)

    def test_create_shift_delete(self):
        """Create a subnet, shift it to another site, then delete it."""
        basedn = self.ldb.get_config_basedn()
        cidr = "10.11.12.0/24"

        subnets.create_subnet(self.ldb, basedn, cidr, self.sitename)

        subnets.set_subnet_site(self.ldb, basedn, cidr, self.sitename2)

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % cidr)

        sites = ret[0]['siteObject']
        self.assertEqual(len(sites), 1)
        self.assertEqual(str(sites[0]),
                         'CN=testsite2,CN=Sites,%s' % self.ldb.get_config_basedn())

        self.assertRaises(subnets.SubnetAlreadyExists,
                          subnets.create_subnet, self.ldb, basedn, cidr,
                          self.sitename)

        subnets.delete_subnet(self.ldb, basedn, cidr)

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % cidr)

        self.assertEqual(len(ret), 0, 'Failed to delete subnet %s' % cidr)

    def test_delete_subnet_that_does_not_exist(self):
        """Ensure we can't delete a site that isn't there."""
        basedn = self.ldb.get_config_basedn()
        cidr = "10.15.0.0/16"

        self.assertRaises(subnets.SubnetNotFound,
                          subnets.delete_subnet, self.ldb, basedn, cidr)

    def get_user_and_ldb(self, username, password, hostname=ldaphost):
        """Get a connection for a temporarily user that will vanish as soon as
        the test is over."""
        user = self.ldb.newuser(username, password)
        creds_tmp = Credentials()
        creds_tmp.set_username(username)
        creds_tmp.set_password(password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        creds_tmp.set_kerberos_state(DONT_USE_KERBEROS)
        ldb_target = SamDB(url=hostname, credentials=creds_tmp, lp=lp)
        self.addCleanup(delete_force, self.ldb, self.get_user_dn(username))
        return (user, ldb_target)

    def test_rename_delete_good_subnet_to_good_subnet_other_user(self):
        """Make sure that we can't rename or delete subnets when we aren't
        admin."""
        basedn = self.ldb.get_config_basedn()
        cidr = "10.16.0.0/24"
        new_cidr = "10.16.1.0/24"
        subnets.create_subnet(self.ldb, basedn, cidr, self.sitename)
        user, non_admin_ldb = self.get_user_and_ldb("notadmin", "samba123@")
        try:
            subnets.rename_subnet(non_admin_ldb, basedn, cidr, new_cidr)
        except LdbError as e:
            self.assertEqual(e.args[0], ERR_INSUFFICIENT_ACCESS_RIGHTS,
                             ("subnet rename by non-admin failed "
                              "in the wrong way: %s" % e))
        else:
            self.fail("subnet rename by non-admin succeeded")

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % cidr)

        self.assertEqual(len(ret), 1, ('Subnet %s destroyed or renamed '
                                       'by non-admin' % cidr))

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression=('(&(objectclass=subnet)(cn=%s))'
                                          % new_cidr))

        self.assertEqual(len(ret), 0,
                         'New subnet %s created by non-admin' % cidr)

        try:
            subnets.delete_subnet(non_admin_ldb, basedn, cidr)
        except LdbError as e:
            self.assertEqual(e.args[0], ERR_INSUFFICIENT_ACCESS_RIGHTS,
                             ("subnet delete by non-admin failed "
                              "in the wrong way: %s" % e))
        else:
            self.fail("subnet delete by non-admin succeeded:")

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % cidr)

        self.assertEqual(len(ret), 1, 'Subnet %s deleted non-admin' % cidr)

        subnets.delete_subnet(self.ldb, basedn, cidr)

    def test_create_good_subnet_other_user(self):
        """Make sure that we can't create subnets when we aren't admin."""
        basedn = self.ldb.get_config_basedn()
        cidr = "10.16.0.0/24"
        user, non_admin_ldb = self.get_user_and_ldb("notadmin", "samba123@")
        try:
            subnets.create_subnet(non_admin_ldb, basedn, cidr, self.sitename)
        except LdbError as e:
            self.assertEqual(e.args[0], ERR_INSUFFICIENT_ACCESS_RIGHTS,
                             ("subnet create by non-admin failed "
                              "in the wrong way: %s" % e))
        else:
            subnets.delete_subnet(self.ldb, basedn, cidr)
            self.fail("subnet create by non-admin succeeded: %s")

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % cidr)

        self.assertEqual(len(ret), 0, 'New subnet %s created by non-admin' % cidr)

    def test_rename_good_subnet_to_good_subnet(self):
        """Make sure that we can rename subnets"""
        basedn = self.ldb.get_config_basedn()
        cidr = "10.16.0.0/24"
        new_cidr = "10.16.1.0/24"

        subnets.create_subnet(self.ldb, basedn, cidr, self.sitename)

        subnets.rename_subnet(self.ldb, basedn, cidr, new_cidr)

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % new_cidr)

        self.assertEqual(len(ret), 1, 'Failed to rename subnet %s' % cidr)

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % cidr)

        self.assertEqual(len(ret), 0, 'Failed to remove old subnet during rename %s' % cidr)

        subnets.delete_subnet(self.ldb, basedn, new_cidr)

    def test_rename_good_subnet_to_bad_subnet(self):
        """Make sure that the CIDR checking runs during rename"""
        basedn = self.ldb.get_config_basedn()
        cidr = "10.17.0.0/24"
        bad_cidr = "10.11.12.0/14"

        subnets.create_subnet(self.ldb, basedn, cidr, self.sitename)

        self.assertRaises(subnets.SubnetInvalid, subnets.rename_subnet,
                          self.ldb, basedn, cidr, bad_cidr)

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % bad_cidr)

        self.assertEqual(len(ret), 0, 'Failed to rename subnet %s' % cidr)

        ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                              expression='(&(objectclass=subnet)(cn=%s))' % cidr)

        self.assertEqual(len(ret), 1, 'Failed to remove old subnet during rename %s' % cidr)

        subnets.delete_subnet(self.ldb, basedn, cidr)

    def test_create_bad_ranges(self):
        """These CIDR ranges all have something wrong with them, and they
        should all fail."""
        basedn = self.ldb.get_config_basedn()

        cidrs = [
            # IPv4
            # insufficient zeros
            "10.11.12.0/14",
            "110.0.0.0/6",
            "1.0.0.0/0",
            "10.11.13.1/24",
            "1.2.3.4/29",
            "10.11.12.0/21",
            # out of range mask
            "110.0.0.0/33",
            "110.0.0.0/-1",
            "4.0.0.0/111",
            # out of range address
            "310.0.0.0/24",
            "10.0.0.256/32",
            "1.1.-20.0/24",
            # badly formed
            "1.0.0.0/1e",
            "1.0.0.0/24.0",
            "1.0.0.0/1/1",
            "1.0.0.0",
            "1.c.0.0/24",
            "1.2.0.0.0/27",
            "1.23.0/24",
            "1.23.0.-7/24",
            "1.-23.0.7/24",
            "1.23.-0.7/24",
            "1.23.0.0/0x10",
            # IPv6 insufficient zeros -- this could be a subtle one
            # due to the vagaries of endianness in the 16 bit groups.
            "aaaa:bbbb:cccc:dddd:eeee:ffff:2222:1100/119",
            "aaaa:bbbb::/31",
            "a:b::/31",
            "c000::/1",
            "a::b00/119",
            "1::1/127",
            "1::2/126",
            "1::100/119",
            "1::8000/112",
            # out of range mask
            "a:b::/130",
            "a:b::/-1",
            "::/129",
            # An IPv4 address can't be exactly the bitmask (MS ADTS)
            "128.0.0.0/1",
            "192.0.0.0/2",
            "255.192.0.0/10",
            "255.255.255.0/24",
            "255.255.255.255/32",
            "0.0.0.0/0",
            # The address can't have leading zeros (not RFC 4632, but MS ADTS)
            "00.1.2.0/24",
            "003.1.2.0/24",
            "022.1.0.0/16",
            "00000000000000000000000003.1.2.0/24",
            "09876::abfc/126",
            "0aaaa:bbbb::/32",
            "009876::abfc/126",
            "000a:bbbb::/32",

            # How about extraneous zeros later on
            "3.01.2.0/24",
            "3.1.2.00/24",
            "22.001.0.0/16",
            "3.01.02.0/24",
            "100a:0bbb:0023::/48",
            "100a::0023/128",

            # Windows doesn't like the zero IPv4 address
            "0.0.0.0/8",
            # or the zero mask on IPv6
            "::/0",

            # various violations of RFC5952
            "0:0:0:0:0:0:0:0/8",
            "0::0/0",
            "::0:0/48",
            "::0:4/128",
            "0::/8",
            "0::4f/128",
            "0::42:0:0:0:0/64",
            "4f::0/48",

            # badly formed -- mostly the wrong arrangement of colons
            "a::b::0/120",
            "a::abcdf:0/120",
            "a::g:0/120",
            "::0::3/48",
            "2001:3::110::3/118",
            "aaaa:bbbb:cccc:dddd:eeee:ffff:2222:1111:0000/128",
            "a:::5:0/120",

            # non-canonical representations (vs RFC 5952)
            # "2001:0:c633:63::1:0/120"  is correct
            "2001:0:c633:63:0:0:1:0/120",
            "2001::c633:63:0:0:1:0/120",
            "2001:0:c633:63:0:0:1::/120",

            # "10:0:0:42::/64" is correct
            "10::42:0:0:0:0/64",
            "10:0:0:42:0:0:0:0/64",

            # "1::4:5:0:0:8/127" is correct
            "1:0:0:4:5:0:0:8/127",
            "1:0:0:4:5::8/127",

            # "2001:db8:0:1:1:1:1:1/128" is correct
            "2001:db8::1:1:1:1:1/128",

            # IP4 embedded - rejected
            "a::10.0.0.0/120",
            "a::10.9.8.7/128",

            # The next ones tinker indirectly with IPv4 embedding,
            # where Windows has some odd behaviour.
            #
            # Samba's libreplace inet_ntop6 expects IPv4 embedding
            # with addresses in these forms:
            #
            #     ::wx:yz
            #     ::FFFF:wx:yz
            #
            # these will be stringified with trailing dottted decimal, thus:
            #
            #     ::w.x.y.z
            #     ::ffff:w.x.y.z
            #
            # and this will cause the address to be rejected by Samba,
            # because it uses a inet_pton / inet_ntop round trip to
            # ascertain correctness.

            "::ffff:0:0/96",  # this one fails on WIN2012r2
            "::ffff:aaaa:a000/120",
            "::ffff:10:0/120",
            "::ffff:2:300/120",
            "::3:0/120",
            "::2:30/124",
            "::ffff:2:30/124",

            # completely wrong
            None,
            "bob",
            3.1415,
            False,
            "10.11.16.0/24\x00hidden bytes past a zero",
            self,
        ]

        failures = []
        for cidr in cidrs:
            try:
                subnets.create_subnet(self.ldb, basedn, cidr, self.sitename)
            except subnets.SubnetInvalid:
                print("%s fails properly" % (cidr,), file=sys.stderr)
                continue

            # we are here because it succeeded when it shouldn't have.
            print("CIDR %s fails to fail" % (cidr,), file=sys.stderr)
            failures.append(cidr)
            subnets.delete_subnet(self.ldb, basedn, cidr)

        if failures:
            print("These bad subnet names were accepted:")
            for cidr in failures:
                print("    %s" % cidr)
            self.fail()

    def test_create_good_ranges(self):
        """All of these CIDRs are good, and the subnet creation should
        succeed."""
        basedn = self.ldb.get_config_basedn()

        cidrs = [
            # IPv4
            "10.11.12.0/24",
            "10.11.12.0/23",
            "10.11.12.0/25",
            "110.0.0.0/7",
            "1.0.0.0/32",
            "10.11.13.0/32",
            "10.11.13.1/32",
            "99.0.97.0/24",
            "1.2.3.4/30",
            "10.11.12.0/22",
            "0.12.13.0/24",
            # IPv6
            "aaaa:bbbb:cccc:dddd:eeee:ffff:2222:1100/120",
            "aaaa:bbbb:cccc:dddd:eeee:ffff:2222:11f0/124",
            "aaaa:bbbb:cccc:dddd:eeee:ffff:2222:11fc/126",
            # don't forget upper case
            "FFFF:FFFF:FFFF:FFFF:ABCD:EfFF:FFFF:FFeF/128",
            "9876::ab00/120",
            "9876::abf0/124",
            "9876::abfc/126",
            "aaaa:bbbb::/32",
            "aaaa:bbba::/31",
            "aaaa:ba00::/23",
            "aaaa:bb00::/24",
            "aaaa:bb00::/77",
            "::/48",
            "a:b::/32",
            "c000::/2",
            "a::b00/120",
            "1::2/127",
            # this pattern of address suffix == mask is forbidden with
            # IPv4 but OK for IPv6.
            "8000::/1",
            "c000::/2",
            "ffff:ffff:ffc0::/42",
            "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF/128",
            # leading zeros are forbidden, but implicit IPv6 zeros
            # (via "::") are OK.
            "::1000/116",
            "::8000/113",
            # taken to the logical conclusion, "::/0" should be OK, but no.
            "::/48",

            # Try some reserved ranges, which it might be reasonable
            # to exclude, but which are not excluded in practice.
            "129.0.0.0/16",
            "129.255.0.0/16",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "127.0.0.0/24",
            "169.254.0.0/16",
            "169.254.1.0/24",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "130.129.0.0/16",
            "130.255.0.0/16",
            "192.12.0.0/24",
            "223.255.255.0/24",
            "240.255.255.0/24",
            "224.0.0.0/8",
            "::/96",
            "100::/64",
            "2001:10::/28",
            "fec0::/10",
            "ff00::/8",
            "::1/128",
            "2001:db8::/32",
            "2001:10::/28",
            "2002::/24",
            "2002:a00::/24",
            "2002:7f00::/24",
            "2002:a9fe::/32",
            "2002:ac10::/28",
            "2002:c000::/40",
            "2002:c000:200::/40",
            "2002:c0a8::/32",
            "2002:c612::/31",
            "2002:c633:6400::/40",
            "2002:cb00:7100::/40",
            "2002:e000::/20",
            "2002:f000::/20",
            "2002:ffff:ffff::/48",
            "2001::/40",
            "2001:0:a00::/40",
            "2001:0:7f00::/40",
            "2001:0:a9fe::/48",
            "2001:0:ac10::/44",
            "2001:0:c000::/56",
            "2001:0:c000:200::/56",
            "2001:0:c0a8::/48",
            "2001:0:c612::/47",
            "2001:0:c633:6400::/56",
            "2001:0:cb00:7100::/56",
            "2001:0:e000::/36",
            "2001:0:f000::/36",
            "2001:0:ffff:ffff::/64",

            # non-RFC-5952 versions of these are tested in create_bad_ranges
            "2001:0:c633:63::1:0/120",
            "10:0:0:42::/64",
            "1::4:5:0:0:8/127",
            "2001:db8:0:1:1:1:1:1/128",

            # The "well-known prefix" 64::ff9b is another IPv4
            # embedding scheme. Let's try that.
            "64:ff9b::aaaa:aaaa/127",
            "64:ff9b::/120",
            "64:ff9b::ffff:2:3/128",
        ]
        failures = []

        for cidr in cidrs:
            try:
                subnets.create_subnet(self.ldb, basedn, cidr, self.sitename)
            except subnets.SubnetInvalid as e:
                print(e)
                failures.append(cidr)
                continue

            ret = self.ldb.search(base=basedn, scope=SCOPE_SUBTREE,
                                  expression=('(&(objectclass=subnet)(cn=%s))' %
                                              cidr))

            if len(ret) != 1:
                print("%s was not created" % cidr)
                failures.append(cidr)
                continue
            subnets.delete_subnet(self.ldb, basedn, cidr)

        if failures:
            print("These good subnet names were not accepted:")
            for cidr in failures:
                print("    %s" % cidr)
            self.fail()


TestProgram(module=__name__, opts=subunitopts)

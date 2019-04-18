#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008-2011
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
import os
from itertools import permutations
import traceback

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram
import samba.getopt as options

from samba.auth import system_session
from ldb import SCOPE_BASE, LdbError
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba.samdb import SamDB

from samba.tests import delete_force

TEST_DATA_DIR = os.path.join(
    os.path.dirname(__file__),
    'testdata')

LDB_STRERR = {}
def _build_ldb_strerr():
    import ldb
    for k, v in vars(ldb).items():
        if k.startswith('ERR_') and isinstance(v, int):
            LDB_STRERR[v] = k

_build_ldb_strerr()


class ModifyOrderTests(samba.tests.TestCase):

    def setUp(self):
        super().setUp()
        self.admin_dsdb = get_dsdb(admin_creds)
        self.base_dn = self.admin_dsdb.domain_dn()

    def delete_object(self, dn):
        delete_force(self.admin_dsdb, dn)

    def get_user_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)

    def _test_modify_order(self,
                           start_attrs,
                           mod_attrs,
                           extra_search_attrs=(),
                           name=None):
        if name is None:
            name = traceback.extract_stack()[-2][2][5:]

        if opts.normal_user:
            name += '-non-admin'
            username = "user123"
            password = "pass123@#$@#"
            self.admin_dsdb.newuser(username, password)
            self.addCleanup(self.delete_object, self.get_user_dn(username))
            mod_creds = self.insta_creds(template=admin_creds,
                                         username=username,
                                         userpass=password)
        else:
            mod_creds = admin_creds

        mod_dsdb = get_dsdb(mod_creds)
        sig = []
        op_lut = ['', 'add', 'replace', 'delete']

        search_attrs = set(extra_search_attrs)
        lines = [name, "initial attrs:"]
        for k, v in start_attrs:
            lines.append("%20s: %r" % (k, v))
            search_attrs.add(k)

        for k, v, op in mod_attrs:
            search_attrs.add(k)

        search_attrs = sorted(search_attrs)
        header = "\n".join(lines)
        sig.append(header)

        clusters = {}
        for i, attrs in enumerate(permutations(mod_attrs)):
            # for each permuation we construct a string describing the
            # requested operations, and a string describing the result
            # (which may be an exception). The we cluster the
            # attribute strings by their results.
            dn = "cn=ldaptest_%s_%d,cn=users,%s" % (name, i, self.base_dn)
            m = Message()
            m.dn = Dn(self.admin_dsdb, dn)

            # We are using Message objects here for add (rather than the
            # more convenient dict) because we maybe care about the order
            # in which attributes are added.

            for k, v in start_attrs:
                m[k] = MessageElement(v, 0, k)

            self.admin_dsdb.add(m)
            self.addCleanup(self.delete_object, dn)

            m = Message()
            m.dn = Dn(mod_dsdb, dn)

            attr_lines = []
            for k, v, op in attrs:
                if v is None:
                    v = dn
                m[k] = MessageElement(v, op, k)
                attr_lines.append("%16s %-8s %s" % (k, op_lut[op], v))

            attr_str = '\n'.join(attr_lines)

            try:
                mod_dsdb.modify(m)
            except LdbError as e:
                err, _ = e.args
                s = LDB_STRERR.get(err, "unknown error")
                result_str = "%s (%d)" % (s, err)
            else:
                res = self.admin_dsdb.search(base=dn, scope=SCOPE_BASE,
                                             attrs=search_attrs)

                lines = []
                for k, v in sorted(dict(res[0]).items()):
                    if k != "dn" or k in extra_search_attrs:
                        lines.append("%20s: %r" % (k, sorted(v)))

                result_str = '\n'.join(lines)

            clusters.setdefault(result_str, []).append(attr_str)

        for s, attrs in sorted(clusters.items()):
            sig.extend([
                "== result ===[%3d]=======================" % len(attrs),
                s,
                "-- operations ---------------------------"])
            for a in attrs:
                sig.append(a)
                sig.append("-" * 34)

        sig = '\n'.join(sig).replace(self.base_dn, "{base dn}")

        if opts.verbose:
            print(sig)

        if opts.rewrite_ground_truth:
            f = open(os.path.join(TEST_DATA_DIR, name + '.expected'), 'w')
            f.write(sig)
            f.close()
        f = open(os.path.join(TEST_DATA_DIR, name + '.expected'))
        expected = f.read()
        f.close()

        self.assertStringsEqual(sig, expected)

    def test_modify_order_mixed(self):
        start_attrs = [("objectclass", "user"),
                       ("carLicense", ["1", "2", "3"]),
                       ("otherTelephone", "123")]

        mod_attrs = [("carLicense", "3", FLAG_MOD_DELETE),
                     ("carLicense", "4", FLAG_MOD_ADD),
                     ("otherTelephone", "4", FLAG_MOD_REPLACE),
                     ("otherTelephone", "123", FLAG_MOD_DELETE)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_mixed2(self):
        start_attrs = [("objectclass", "user"),
                       ("carLicense", ["1", "2", "3"]),
                       ("ipPhone", "123")]

        mod_attrs = [("carLicense", "3", FLAG_MOD_DELETE),
                     ("carLicense", "4", FLAG_MOD_ADD),
                     ("ipPhone", "4", FLAG_MOD_REPLACE),
                     ("ipPhone", "123", FLAG_MOD_DELETE)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_telephone(self):
        start_attrs = [("objectclass", "user"),
                       ("otherTelephone", "123")]

        mod_attrs = [("carLicense", "3", FLAG_MOD_REPLACE),
                     ("carLicense", "4", FLAG_MOD_ADD),
                     ("otherTelephone", "4", FLAG_MOD_REPLACE),
                     ("otherTelephone", "4", FLAG_MOD_ADD),
                     ("otherTelephone", "123", FLAG_MOD_DELETE)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_telephone_delete_delete(self):
        start_attrs = [("objectclass", "user"),
                       ("otherTelephone", "123")]

        mod_attrs = [("carLicense", "3", FLAG_MOD_REPLACE),
                     ("carLicense", "4", FLAG_MOD_DELETE),
                     ("otherTelephone", "4", FLAG_MOD_REPLACE),
                     ("otherTelephone", "4", FLAG_MOD_DELETE),
                     ("otherTelephone", "123", FLAG_MOD_DELETE)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_objectclass(self):
        start_attrs = [("objectclass", "user"),
                       ("otherTelephone", "123")]

        mod_attrs = [("objectclass", "computer", FLAG_MOD_REPLACE),
                     ("objectclass", "user", FLAG_MOD_DELETE),
                     ("objectclass", "person", FLAG_MOD_DELETE)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_objectclass2(self):
        start_attrs = [("objectclass", "user")]

        mod_attrs = [("objectclass", "computer", FLAG_MOD_REPLACE),
                     ("objectclass", "user", FLAG_MOD_ADD),
                     ("objectclass", "attributeSchema", FLAG_MOD_REPLACE),
                     ("objectclass", "inetOrgPerson", FLAG_MOD_ADD),
                     ("objectclass", "person", FLAG_MOD_DELETE)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_singlevalue(self):
        start_attrs = [("objectclass", "user"),
                       ("givenName", "a")]

        mod_attrs = [("givenName", "a", FLAG_MOD_REPLACE),
                     ("givenName", ["b", "a"], FLAG_MOD_REPLACE),
                     ("givenName", "b", FLAG_MOD_DELETE),
                     ("givenName", "a", FLAG_MOD_DELETE),
                     ("givenName", "c", FLAG_MOD_ADD)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_inapplicable(self):
        #attrbutes that don't go on a user
        start_attrs = [("objectclass", "user"),
                       ("givenName", "a")]

        mod_attrs = [("dhcpSites", "b", FLAG_MOD_REPLACE),
                     ("dhcpSites", "b", FLAG_MOD_DELETE),
                     ("dhcpSites", "c", FLAG_MOD_ADD)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_sometimes_inapplicable(self):
        # attributes that don't go on a user, but do on a computer,
        # which we sometimes change into.
        start_attrs = [("objectclass", "user"),
                       ("givenName", "a")]

        mod_attrs = [("objectclass", "computer", FLAG_MOD_REPLACE),
                     ("objectclass", "person", FLAG_MOD_DELETE),
                     ("dnsHostName", "b", FLAG_MOD_ADD),
                     ("dnsHostName", "c", FLAG_MOD_REPLACE)]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_account_locality_device(self):
        # account, locality, and device all take l (locality name) but
        # only device takes owner. We shouldn't be able to change
        # objectclass at all.
        start_attrs = [("objectclass", "account"),
                       ("l", "a")]

        mod_attrs = [("objectclass", ["device", "top"], FLAG_MOD_REPLACE),
                     ("l", "a", FLAG_MOD_DELETE),
                     ("owner", "c", FLAG_MOD_ADD)
        ]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_container_flags_multivalue(self):
        # account, locality, and device all take l (locality name)
        # but only device takes owner
        start_attrs = [("objectclass", "container"),
                       ("wWWHomePage", "a")]

        mod_attrs = [("flags", ["0", "1"], FLAG_MOD_ADD),
                     ("flags", "65355", FLAG_MOD_ADD),
                     ("flags", "65355", FLAG_MOD_DELETE),
                     ("flags", ["2", "101"], FLAG_MOD_REPLACE),
        ]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_container_flags(self):
        #flags should be an integer
        start_attrs = [("objectclass", "container")]

        mod_attrs = [("flags", "0x6", FLAG_MOD_ADD),
                     ("flags", "5", FLAG_MOD_ADD),
                     ("flags", "101", FLAG_MOD_REPLACE),
                     ("flags", "c", FLAG_MOD_DELETE),
        ]
        self._test_modify_order(start_attrs, mod_attrs)

    def test_modify_order_member(self):
        name = "modify_order_member_other_group"

        dn2 = "cn=%s,%s" % (name, self.base_dn)
        m = Message()
        m.dn = Dn(self.admin_dsdb, dn2)
        self.admin_dsdb.add({"dn": dn2, "objectclass": "group"})
        self.addCleanup(self.delete_object, dn2)

        start_attrs = [("objectclass", "group"),
                       ("member", dn2)]

        mod_attrs = [("member", None, FLAG_MOD_DELETE),
                     ("member", None, FLAG_MOD_REPLACE),
                     ("member", dn2, FLAG_MOD_DELETE),
                     ("member", None, FLAG_MOD_ADD),
        ]
        self._test_modify_order(start_attrs, mod_attrs, ["memberOf"])


def get_dsdb(creds=None):
    if creds is None:
        creds = admin_creds
    dsdb = SamDB(host,
                 credentials=creds,
                 session_info=system_session(lp),
                 lp=lp)
    return dsdb


parser = optparse.OptionParser("ldap_modify_order.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)
parser.add_option("--rewrite-ground-truth", action="store_true",
                  help="write expected values")
parser.add_option("-v", "--verbose", action="store_true")
parser.add_option("--normal-user", action="store_true")

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
admin_creds = credopts.get_credentials(lp)

if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


TestProgram(module=__name__, opts=subunitopts)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Originally based on ./sam.py
from __future__ import print_function
import optparse
import sys
import os
import itertools
from time import time
from binascii import hexlify

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
import ldb
from samba.samdb import SamDB
from samba.dcerpc import misc
from samba import colour

parser = optparse.OptionParser("linked_attributes.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

parser.add_option('--delete-in-setup', action='store_true',
                  help="cleanup in setup")

parser.add_option('--no-cleanup', action='store_true',
                  help="don't cleanup in teardown")

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)


def debug(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)


class SubtreeRenameTestException(Exception):
    pass


class SubtreeRenameTests(samba.tests.TestCase):

    def delete_ous(self):
        for ou in (self.ou1, self.ou2, self.ou3):
            try:
                self.samdb.delete(ou, ['tree_delete:1'])
            except ldb.LdbError as e:
                pass

    def setUp(self):
        super(SubtreeRenameTests, self).setUp()
        self.samdb = SamDB(host, credentials=creds,
                           session_info=system_session(lp), lp=lp)

        self.base_dn = self.samdb.domain_dn()
        self.ou1 = "OU=subtree1,%s" % self.base_dn
        self.ou2 = "OU=subtree2,%s" % self.base_dn
        self.ou3 = "OU=subtree3,%s" % self.base_dn
        if opts.delete_in_setup:
            self.delete_ous()
        self.samdb.add({'objectclass': 'organizationalUnit',
                        'dn': self.ou1})
        self.samdb.add({'objectclass': 'organizationalUnit',
                        'dn': self.ou2})

        debug(colour.c_REV_RED(self.id()))

    def tearDown(self):
        super(SubtreeRenameTests, self).tearDown()
        if not opts.no_cleanup:
            self.delete_ous()

    def add_object(self, cn, objectclass, ou=None, more_attrs={}):
        dn = "CN=%s,%s" % (cn, ou)
        attrs = {'cn': cn,
                 'objectclass': objectclass,
                 'dn': dn}
        attrs.update(more_attrs)
        self.samdb.add(attrs)

        return dn

    def add_objects(self, n, objectclass, prefix=None, ou=None, more_attrs={}):
        if prefix is None:
            prefix = objectclass
        dns = []
        for i in range(n):
            dns.append(self.add_object("%s%d" % (prefix, i + 1),
                                       objectclass,
                                       more_attrs=more_attrs,
                                       ou=ou))
        return dns

    def add_linked_attribute(self, src, dest, attr='member',
                             controls=None):
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_ADD, attr)
        self.samdb.modify(m, controls=controls)

    def remove_linked_attribute(self, src, dest, attr='member',
                                controls=None):
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_DELETE, attr)
        self.samdb.modify(m, controls=controls)

    def add_binary_link(self, src, dest, binary,
                        attr='msDS-RevealedUsers',
                        controls=None):
        b = hexlify(str(binary).encode('utf-8')).decode('utf-8').upper()
        dest = 'B:%d:%s:%s' % (len(b), b, dest)
        self.add_linked_attribute(src, dest, attr, controls)
        return dest

    def remove_binary_link(self, src, dest, binary,
                           attr='msDS-RevealedUsers',
                           controls=None):
        b = str(binary).encode('utf-8')
        dest = 'B:%s:%s' % (hexlify(b), dest)
        self.remove_linked_attribute(src, dest, attr, controls)

    def replace_linked_attribute(self, src, dest, attr='member',
                                 controls=None):
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_REPLACE, attr)
        self.samdb.modify(m, controls=controls)

    def attr_search(self, obj, attr, scope=ldb.SCOPE_BASE, **controls):

        controls = ['%s:%d' % (k, int(v)) for k, v in controls.items()]

        res = self.samdb.search(obj,
                                scope=scope,
                                attrs=[attr],
                                controls=controls)
        return res

    def assert_links(self, obj, expected, attr, msg='', **kwargs):
        res = self.attr_search(obj, attr, **kwargs)

        if len(expected) == 0:
            if attr in res[0]:
                self.fail("found attr '%s' in %s" % (attr, res[0]))
            return

        try:
            results = [str(x) for x in res[0][attr]]
        except KeyError:
            self.fail("missing attr '%s' on %s" % (attr, obj))

        expected = sorted(expected)
        results = sorted(results)

        if expected != results:
            debug(msg)
            debug("expected %s" % expected)
            debug("received %s" % results)
            debug("missing    %s" % (sorted(set(expected) - set(results))))
            debug("unexpected %s" % (sorted(set(results) - set(expected))))


        self.assertEqual(results, expected)

    def assert_back_links(self, obj, expected, attr='memberOf', **kwargs):
        self.assert_links(obj, expected, attr=attr,
                          msg='%s back links do not match for %s' %
                          (attr, obj),
                          **kwargs)

    def assert_forward_links(self, obj, expected, attr='member', **kwargs):
        self.assert_links(obj, expected, attr=attr,
                          msg='%s forward links do not match for %s' %
                          (attr, obj),
                          **kwargs)

    def get_object_guid(self, dn):
        res = self.samdb.search(dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=['objectGUID'])
        return str(misc.GUID(res[0]['objectGUID'][0]))

    def test_la_move_ou_tree(self):
        tag = 'move_tree'

        u1, u2 = self.add_objects(2, 'user', '%s_u_' % tag, ou=self.ou1)
        g1, g2 = self.add_objects(2, 'group', '%s_g_' % tag, ou=self.ou1)
        c1, c2, c3 = self.add_objects(3, 'computer',
                                      '%s_c_' % tag,
                                      ou=self.ou1)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g1, g2)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)
        c1u1 = self.add_binary_link(c1, u1, 'a').replace(self.ou1, self.ou3)
        c2u1 = self.add_binary_link(c2, u1, 'b').replace(self.ou1, self.ou3)
        c3u1 = self.add_binary_link(c3, u1, 124.543).replace(self.ou1, self.ou3)
        c1g1 = self.add_binary_link(c1, g1, 'd').replace(self.ou1, self.ou3)
        c2g2 = self.add_binary_link(c2, g2, 'd').replace(self.ou1, self.ou3)
        c2c1 = self.add_binary_link(c2, c1, 'd').replace(self.ou1, self.ou3)
        c1u2 = self.add_binary_link(c1, u2, 'd').replace(self.ou1, self.ou3)
        c1u1_2 = self.add_binary_link(c1, u1, 'b').replace(self.ou1, self.ou3)

        self.assertRaisesLdbError(20,
                                  "Attribute msDS-RevealedUsers already exists",
                                  self.add_binary_link, c1, u2, 'd')

        self.samdb.rename(self.ou1, self.ou3)
        debug(colour.c_CYAN("rename FINISHED"))
        u1, u2, g1, g2, c1, c2, c3 = [x.replace(self.ou1, self.ou3)
                                      for x in (u1, u2, g1, g2, c1, c2, c3)]

        self.samdb.delete(g2, ['tree_delete:1'])

        self.assert_forward_links(g1, [u1])
        self.assert_back_links(u1, [g1])
        self.assert_back_links(u2, set())
        self.assert_forward_links(c1, [c1u1, c1u1_2, c1u2, c1g1],
                                  attr='msDS-RevealedUsers')
        self.assert_forward_links(c2, [c2u1, c2c1], attr='msDS-RevealedUsers')
        self.assert_forward_links(c3, [c3u1], attr='msDS-RevealedUsers')
        self.assert_back_links(u1, [c1, c1, c2, c3], attr='msDS-RevealedDSAs')
        self.assert_back_links(u2, [c1], attr='msDS-RevealedDSAs')
        self.assert_back_links(g1, [c1], attr='msDS-RevealedDSAs')
        self.assert_back_links(c1, [c2], attr='msDS-RevealedDSAs')

    def test_la_move_ou_groups(self):
        tag = 'move_groups'

        u1, u2 = self.add_objects(2, 'user', '%s_u_' % tag, ou=self.ou2)
        g1, g2 = self.add_objects(2, 'group', '%s_g_' % tag, ou=self.ou1)
        c1, c2, c3 = self.add_objects(3, 'computer',
                                      '%s_c_' % tag,
                                      ou=self.ou1)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g1, g2)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)
        c1u1 = self.add_binary_link(c1, u1, 'a').replace(self.ou1, self.ou3)
        c2u1 = self.add_binary_link(c2, u1, 'b').replace(self.ou1, self.ou3)
        c3u1 = self.add_binary_link(c3, u1, 124.543).replace(self.ou1, self.ou3)
        c1g1 = self.add_binary_link(c1, g1, 'd').replace(self.ou1, self.ou3)
        c2g2 = self.add_binary_link(c2, g2, 'd').replace(self.ou1, self.ou3)
        c2c1 = self.add_binary_link(c2, c1, 'd').replace(self.ou1, self.ou3)
        c1u2 = self.add_binary_link(c1, u2, 'd').replace(self.ou1, self.ou3)
        c1u1_2 = self.add_binary_link(c1, u1, 'b').replace(self.ou1, self.ou3)

        self.samdb.rename(self.ou1, self.ou3)
        debug(colour.c_CYAN("rename FINISHED"))
        u1, u2, g1, g2, c1, c2, c3 = [x.replace(self.ou1, self.ou3)
                                      for x in (u1, u2, g1, g2, c1, c2, c3)]

        self.samdb.delete(g2, ['tree_delete:1'])

        self.assert_forward_links(g1, [u1])
        self.assert_back_links(u1, [g1])
        self.assert_back_links(u2, set())
        self.assert_forward_links(c1, [c1u1, c1u1_2, c1u2, c1g1],
                                  attr='msDS-RevealedUsers')
        self.assert_forward_links(c2, [c2u1, c2c1], attr='msDS-RevealedUsers')
        self.assert_forward_links(c3, [c3u1], attr='msDS-RevealedUsers')
        self.assert_back_links(u1, [c1, c1, c2, c3], attr='msDS-RevealedDSAs')
        self.assert_back_links(u2, [c1], attr='msDS-RevealedDSAs')
        self.assert_back_links(g1, [c1], attr='msDS-RevealedDSAs')
        self.assert_back_links(c1, [c2], attr='msDS-RevealedDSAs')

    def test_la_move_ou_users(self):
        tag = 'move_users'

        u1, u2 = self.add_objects(2, 'user', '%s_u_' % tag, ou=self.ou1)
        g1, g2 = self.add_objects(2, 'group', '%s_g_' % tag, ou=self.ou2)
        c1, c2 = self.add_objects(2, 'computer', '%s_c_' % tag, ou=self.ou1)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g1, g2)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)
        c1u1 = self.add_binary_link(c1, u1, 'a').replace(self.ou1, self.ou3)
        c2u1 = self.add_binary_link(c2, u1, 'b').replace(self.ou1, self.ou3)
        c1g1 = self.add_binary_link(c1, g1, 'd').replace(self.ou1, self.ou3)
        c2g2 = self.add_binary_link(c2, g2, 'd').replace(self.ou1, self.ou3)
        c2c1 = self.add_binary_link(c2, c1, 'd').replace(self.ou1, self.ou3)
        c1u2 = self.add_binary_link(c1, u2, 'd').replace(self.ou1, self.ou3)
        c1u1_2 = self.add_binary_link(c1, u1, 'b').replace(self.ou1, self.ou3)


        self.samdb.rename(self.ou1, self.ou3)
        debug(colour.c_CYAN("rename FINISHED"))
        u1, u2, g1, g2, c1, c2 = [x.replace(self.ou1, self.ou3)
                                  for x in (u1, u2, g1, g2, c1, c2)]

        self.samdb.delete(g2, ['tree_delete:1'])

        self.assert_forward_links(g1, [u1])
        self.assert_back_links(u1, [g1])
        self.assert_back_links(u2, set())
        self.assert_forward_links(c1, [c1u1, c1u1_2, c1u2, c1g1],
                                  attr='msDS-RevealedUsers')
        self.assert_forward_links(c2, [c2u1, c2c1], attr='msDS-RevealedUsers')
        self.assert_back_links(u1, [c1, c1, c2], attr='msDS-RevealedDSAs')
        self.assert_back_links(u2, [c1], attr='msDS-RevealedDSAs')
        self.assert_back_links(g1, [c1], attr='msDS-RevealedDSAs')
        self.assert_back_links(c1, [c2], attr='msDS-RevealedDSAs')

    def test_la_move_ou_noncomputers(self):
        """Here we are especially testing the msDS-RevealedDSAs links"""
        tag = 'move_noncomputers'

        u1, u2 = self.add_objects(2, 'user', '%s_u_' % tag, ou=self.ou1)
        g1, g2 = self.add_objects(2, 'group', '%s_g_' % tag, ou=self.ou1)
        c1, c2, c3 = self.add_objects(3, 'computer', '%s_c_' % tag, ou=self.ou2)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g1, g2)
        c1u1 = self.add_binary_link(c1, u1, 'a').replace(self.ou1, self.ou3)
        c2u1 = self.add_binary_link(c2, u1, 'b').replace(self.ou1, self.ou3)
        c2u1_2 = self.add_binary_link(c2, u1, 'c').replace(self.ou1, self.ou3)
        c3u1 = self.add_binary_link(c3, g1, 'b').replace(self.ou1, self.ou3)
        c1g1 = self.add_binary_link(c1, g1, 'd').replace(self.ou1, self.ou3)
        c2g2 = self.add_binary_link(c2, g2, 'd').replace(self.ou1, self.ou3)
        c2c1 = self.add_binary_link(c2, c1, 'd').replace(self.ou1, self.ou3)
        c1u2 = self.add_binary_link(c1, u2, 'd').replace(self.ou1, self.ou3)
        c1u1_2 = self.add_binary_link(c1, u1, 'b').replace(self.ou1, self.ou3)
        c1u1_3 = self.add_binary_link(c1, u1, 'c').replace(self.ou1, self.ou3)
        c2u1_3 = self.add_binary_link(c2, u1, 'e').replace(self.ou1, self.ou3)
        c3u2 = self.add_binary_link(c3, u2, 'b').replace(self.ou1, self.ou3)

        self.samdb.rename(self.ou1, self.ou3)
        debug(colour.c_CYAN("rename FINISHED"))
        u1, u2, g1, g2, c1, c2, c3 = [x.replace(self.ou1, self.ou3)
                                      for x in (u1, u2, g1, g2, c1, c2, c3)]

        self.samdb.delete(c3, ['tree_delete:1'])

        self.assert_forward_links(g1, [g2, u1])
        self.assert_back_links(u1, [g1])
        self.assert_back_links(u2, [])
        self.assert_forward_links(c1, [c1u1, c1u1_2, c1u1_3, c1u2, c1g1],
                                  attr='msDS-RevealedUsers')
        self.assert_forward_links(c2, [c2u1, c2u1_2, c2u1_3, c2c1, c2g2],
                                  attr='msDS-RevealedUsers')
        self.assert_back_links(u1, [c1, c1, c1, c2, c2, c2],
                               attr='msDS-RevealedDSAs')
        self.assert_back_links(u2, [c1], attr='msDS-RevealedDSAs')
        self.assert_back_links(g1, [c1], attr='msDS-RevealedDSAs')
        self.assert_back_links(c1, [c2], attr='msDS-RevealedDSAs')

    def test_la_move_ou_tree_big(self):
        tag = 'move_ou_big'
        USERS, GROUPS, COMPUTERS = 50, 10, 7

        users = self.add_objects(USERS, 'user', '%s_u_' % tag, ou=self.ou1)
        groups = self.add_objects(GROUPS, 'group', '%s_g_' % tag, ou=self.ou1)
        computers = self.add_objects(COMPUTERS, 'computer', '%s_c_' % tag,
                                     ou=self.ou1)

        start = time()
        for i in range(USERS):
            u = users[i]
            for j in range(i % GROUPS):
                g = groups[j]
                self.add_linked_attribute(g, u)
            for j in range(i % COMPUTERS):
                c = computers[j]
                self.add_binary_link(c, u, 'a')

        debug("linking took %.3fs" % (time() - start))
        start = time()
        self.samdb.rename(self.ou1, self.ou3)
        debug("rename ou took %.3fs" % (time() - start))

        g1 = groups[0].replace(self.ou1, self.ou3)
        start = time()
        self.samdb.rename(g1, g1.replace(self.ou3, self.ou2))
        debug("rename group took %.3fs" % (time() - start))

        u1 = users[0].replace(self.ou1, self.ou3)
        start = time()
        self.samdb.rename(u1, u1.replace(self.ou3, self.ou2))
        debug("rename user took %.3fs" % (time() - start))

        c1 = computers[0].replace(self.ou1, self.ou3)
        start = time()
        self.samdb.rename(c1, c1.replace(self.ou3, self.ou2))
        debug("rename computer took %.3fs" % (time() - start))


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


TestProgram(module=__name__, opts=subunitopts)

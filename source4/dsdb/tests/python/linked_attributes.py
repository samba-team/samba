#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Originally based on ./sam.py
import optparse
import sys
import os
import base64
import random
import re

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
import ldb
from samba.samdb import SamDB
from samba.dcerpc import misc

import time

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

parser.add_option('--no-reveal-internals', action='store_true',
                  help="Only use windows compatible ldap controls")

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)


class LATestException(Exception):
    pass


class LATests(samba.tests.TestCase):

    def setUp(self):
        super(LATests, self).setUp()
        self.samdb = SamDB(host, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        self.base_dn = self.samdb.domain_dn()
        self.ou = "OU=la,%s" % self.base_dn
        if opts.delete_in_setup:
            try:
                self.samdb.delete(self.ou, ['tree_delete:1'])
            except ldb.LdbError, e:
                print "tried deleting %s, got error %s" % (self.ou, e)
        self.samdb.add({'objectclass': 'organizationalUnit',
                        'dn': self.ou})

    def tearDown(self):
        super(LATests, self).tearDown()
        if not opts.no_cleanup:
            self.samdb.delete(self.ou, ['tree_delete:1'])

    def delete_user(self, user):
        self.samdb.delete(user['dn'])
        del self.users[self.users.index(user)]

    def add_object(self, cn, objectclass):
        dn = "CN=%s,%s" % (cn, self.ou)
        self.samdb.add({'cn': cn,
                      'objectclass': objectclass,
                      'dn': dn})

        return dn

    def add_objects(self, n, objectclass, prefix=None):
        if prefix is None:
            prefix = objectclass
        dns = []
        for i in range(n):
            dns.append(self.add_object("%s%d" % (prefix, i + 1),
                                       objectclass))
        return dns

    def add_linked_attribute(self, src, dest, attr='member'):
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_ADD, attr)
        self.samdb.modify(m)

    def remove_linked_attribute(self, src, dest, attr='member'):
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_DELETE, attr)
        self.samdb.modify(m)

    def attr_search(self, obj, expected, attr, scope=ldb.SCOPE_BASE,
                    **controls):
        if opts.no_reveal_internals:
            if 'reveal_internals' in controls:
                del controls['reveal_internals']

        controls = ['%s:%d' % (k, int(v)) for k, v in controls.items()]

        res = self.samdb.search(obj,
                                scope=scope,
                                attrs=[attr],
                                controls=controls)
        return res

    def assert_links(self, obj, expected, attr, sorted=False, msg='',
                     **kwargs):
        res = self.attr_search(obj, expected, attr, **kwargs)

        if len(expected) == 0:
            if attr in res[0]:
                self.fail("found attr '%s' in %s" % (attr, res[0]))
            return

        try:
            results = list([x[attr] for x in res][0])
        except KeyError:
            self.fail("missing attr '%s' on %s" % (attr, obj))

        if sorted == False:
            results = set(results)
            expected = set(expected)

        if expected != results:
            print msg
            print "expected %s" % expected
            print "received %s" % results

        self.assertEqual(results, expected)

    def assert_back_links(self, obj, expected, attr='memberOf', **kwargs):
        self.assert_links(obj, expected, attr=attr,
                          msg='back links do not match', **kwargs)

    def assert_forward_links(self, obj, expected, attr='member', **kwargs):
        self.assert_links(obj, expected, attr=attr,
                          msg='forward links do not match', **kwargs)

    def get_object_guid(self, dn):
        res = self.samdb.search(dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=['objectGUID'])
        return str(misc.GUID(res[0]['objectGUID'][0]))

    def _test_la_backlinks(self, reveal=False):
        tag = 'backlinks'
        kwargs = {}
        if reveal:
            tag += '_reveal'
            kwargs = {'reveal_internals': 0}

        u1, u2 = self.add_objects(2, 'user', 'u_%s' % tag)
        g1, g2 = self.add_objects(2, 'group', 'g_%s' % tag)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.assert_back_links(u1, [g1, g2], **kwargs)
        self.assert_back_links(u2, [g2], **kwargs)

    def test_la_backlinks(self):
        self._test_la_backlinks()

    def test_la_backlinks_reveal(self):
        if opts.no_reveal_internals:
            print 'skipping because --no-reveal-internals'
            return
        self._test_la_backlinks(True)

    def _test_la_backlinks_delete_group(self, reveal=False):
        tag = 'del_group'
        kwargs = {}
        if reveal:
            tag += '_reveal'
            kwargs = {'reveal_internals': 0}

        u1, u2 = self.add_objects(2, 'user', 'u_' + tag)
        g1, g2 = self.add_objects(2, 'group', 'g_' + tag)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.samdb.delete(g2, ['tree_delete:1'])

        self.assert_back_links(u1, [g1], **kwargs)
        self.assert_back_links(u2, set(), **kwargs)

    def test_la_backlinks_delete_group(self):
        self._test_la_backlinks_delete_group()

    def test_la_backlinks_delete_group_reveal(self):
        if opts.no_reveal_internals:
            print 'skipping because --no-reveal-internals'
            return
        self._test_la_backlinks_delete_group(True)

    def test_links_all_delete_group(self):
        u1, u2 = self.add_objects(2, 'user', 'u_all_del_group')
        g1, g2 = self.add_objects(2, 'group', 'g_all_del_group')
        g2guid = self.get_object_guid(g2)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.samdb.delete(g2)
        self.assert_back_links(u1, [g1], show_deleted=1, show_recycled=1,
                               show_deactivated_link=0)
        self.assert_back_links(u2, set(), show_deleted=1, show_recycled=1,
                               show_deactivated_link=0)
        self.assert_forward_links(g1, [u1], show_deleted=1, show_recycled=1,
                                  show_deactivated_link=0)
        self.assert_forward_links('<GUID=%s>' % g2guid,
                                  [], show_deleted=1, show_recycled=1,
                                  show_deactivated_link=0)

    def test_links_all_delete_group_reveal(self):
        u1, u2 = self.add_objects(2, 'user', 'u_all_del_group_reveal')
        g1, g2 = self.add_objects(2, 'group', 'g_all_del_group_reveal')
        g2guid = self.get_object_guid(g2)

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.samdb.delete(g2)
        self.assert_back_links(u1, [g1], show_deleted=1, show_recycled=1,
                               show_deactivated_link=0,
                                  reveal_internals=0)
        self.assert_back_links(u2, set(), show_deleted=1, show_recycled=1,
                               show_deactivated_link=0,
                                  reveal_internals=0)
        self.assert_forward_links(g1, [u1], show_deleted=1, show_recycled=1,
                                  show_deactivated_link=0,
                                  reveal_internals=0)
        self.assert_forward_links('<GUID=%s>' % g2guid,
                                  [], show_deleted=1, show_recycled=1,
                                  show_deactivated_link=0,
                                  reveal_internals=0)

    def test_la_links_delete_link(self):
        u1, u2 = self.add_objects(2, 'user', 'u_del_link')
        g1, g2 = self.add_objects(2, 'group', 'g_del_link')

        res = self.samdb.search(g1, scope=ldb.SCOPE_BASE,
                                attrs=['uSNChanged'])
        old_usn1 = int(res[0]['uSNChanged'][0])

        self.add_linked_attribute(g1, u1)

        res = self.samdb.search(g1, scope=ldb.SCOPE_BASE,
                                attrs=['uSNChanged'])
        new_usn1 = int(res[0]['uSNChanged'][0])

        self.assertNotEqual(old_usn1, new_usn1, "USN should have incremented")

        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        res = self.samdb.search(g2, scope=ldb.SCOPE_BASE,
                                attrs=['uSNChanged'])
        old_usn2 = int(res[0]['uSNChanged'][0])

        self.remove_linked_attribute(g2, u1)

        res = self.samdb.search(g2, scope=ldb.SCOPE_BASE,
                                attrs=['uSNChanged'])
        new_usn2 = int(res[0]['uSNChanged'][0])

        self.assertNotEqual(old_usn2, new_usn2, "USN should have incremented")

        self.assert_forward_links(g1, [u1])
        self.assert_forward_links(g2, [u2])

        self.add_linked_attribute(g2, u1)
        self.assert_forward_links(g2, [u1, u2])
        self.remove_linked_attribute(g2, u2)
        self.assert_forward_links(g2, [u1])
        self.remove_linked_attribute(g2, u1)
        self.assert_forward_links(g2, [])

    def _test_la_links_delete_link_reveal(self):
        u1, u2 = self.add_objects(2, 'user', 'u_del_link_reveal')
        g1, g2 = self.add_objects(2, 'group', 'g_del_link_reveal')

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.remove_linked_attribute(g2, u1)

        self.assert_forward_links(g2, [u1, u2], show_deleted=1,
                                  show_recycled=1,
                                  show_deactivated_link=0,
                                  reveal_internals=0
        )
    def test_la_links_delete_link_reveal(self):
        if opts.no_reveal_internals:
            print 'skipping because --no-reveal-internals'
            return
        self._test_la_links_delete_link_reveal()

    def test_la_links_delete_user(self):
        u1, u2 = self.add_objects(2, 'user', 'u_del_user')
        g1, g2 = self.add_objects(2, 'group', 'g_del_user')

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        res = self.samdb.search(g1, scope=ldb.SCOPE_BASE,
                                attrs=['uSNChanged'])
        old_usn1 = int(res[0]['uSNChanged'][0])

        res = self.samdb.search(g2, scope=ldb.SCOPE_BASE,
                                attrs=['uSNChanged'])
        old_usn2 = int(res[0]['uSNChanged'][0])

        self.samdb.delete(u1)

        self.assert_forward_links(g1, [])
        self.assert_forward_links(g2, [u2])

        res = self.samdb.search(g1, scope=ldb.SCOPE_BASE,
                                attrs=['uSNChanged'])
        new_usn1 = int(res[0]['uSNChanged'][0])

        res = self.samdb.search(g2, scope=ldb.SCOPE_BASE,
                                attrs=['uSNChanged'])
        new_usn2 = int(res[0]['uSNChanged'][0])

        # Assert the USN on the alternate object is unchanged
        self.assertEqual(old_usn1, new_usn1)
        self.assertEqual(old_usn2, new_usn2)

    def test_la_links_delete_user_reveal(self):
        u1, u2 = self.add_objects(2, 'user', 'u_del_user_reveal')
        g1, g2 = self.add_objects(2, 'group', 'g_del_user_reveal')

        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)

        self.samdb.delete(u1)

        self.assert_forward_links(g2, [u2],
                                  show_deleted=1, show_recycled=1,
                                  show_deactivated_link=0,
                                  reveal_internals=0)
        self.assert_forward_links(g1, [],
                                  show_deleted=1, show_recycled=1,
                                  show_deactivated_link=0,
                                  reveal_internals=0)

    def _test_la_links_sort_order(self):
        u1, u2, u3 = self.add_objects(3, 'user', 'u_sort_order')
        g1, g2, g3 = self.add_objects(3, 'group', 'g_sort_order')

        # Add these in a haphazard order
        self.add_linked_attribute(g2, u3)
        self.add_linked_attribute(g3, u2)
        self.add_linked_attribute(g1, u3)
        self.add_linked_attribute(g1, u1)
        self.add_linked_attribute(g2, u1)
        self.add_linked_attribute(g2, u2)
        self.add_linked_attribute(g3, u3)
        self.add_linked_attribute(g3, u1)

        self.assert_forward_links(g1, [u3, u1], sorted=True)
        self.assert_forward_links(g2, [u3, u2, u1], sorted=True)
        self.assert_forward_links(g3, [u3, u2, u1], sorted=True)

        self.assert_back_links(u1, [g3, g2, g1], sorted=True)
        self.assert_back_links(u2, [g3, g2], sorted=True)
        self.assert_back_links(u3, [g3, g2, g1], sorted=True)

    def test_one_way_attributes(self):
        e1, e2 = self.add_objects(2, 'msExchConfigurationContainer',
                                  'e_one_way')
        guid = self.get_object_guid(e2)

        self.add_linked_attribute(e1, e2, attr="addressBookRoots")
        self.assert_forward_links(e1, [e2], attr='addressBookRoots')

        self.samdb.delete(e2)

        res = self.samdb.search("<GUID=%s>" % guid,
                                scope=ldb.SCOPE_BASE,
                                controls=['show_deleted:1',
                                          'show_recycled:1'])

        new_dn = str(res[0].dn)
        self.assert_forward_links(e1, [new_dn], attr='addressBookRoots')
        self.assert_forward_links(e1, [new_dn],
                                  attr='addressBookRoots',
                                  show_deactivated_link=0)

    def test_one_way_attributes_delete_link(self):
        e1, e2 = self.add_objects(2, 'msExchConfigurationContainer',
                                  'e_one_way')
        guid = self.get_object_guid(e2)

        self.add_linked_attribute(e1, e2, attr="addressBookRoots")
        self.assert_forward_links(e1, [e2], attr='addressBookRoots')

        self.remove_linked_attribute(e1, e2, attr="addressBookRoots")

        self.assert_forward_links(e1, [], attr='addressBookRoots')
        self.assert_forward_links(e1, [], attr='addressBookRoots',
                                  show_deactivated_link=0)

    def test_pretend_one_way_attributes(self):
        e1, e2 = self.add_objects(2, 'msExchConfigurationContainer',
                                  'e_one_way')
        guid = self.get_object_guid(e2)

        self.add_linked_attribute(e1, e2, attr="addressBookRoots2")
        self.assert_forward_links(e1, [e2], attr='addressBookRoots2')

        self.samdb.delete(e2)
        res = self.samdb.search("<GUID=%s>" % guid,
                                scope=ldb.SCOPE_BASE,
                                controls=['show_deleted:1',
                                          'show_recycled:1'])

        new_dn = str(res[0].dn)

        self.assert_forward_links(e1, [], attr='addressBookRoots2')
        self.assert_forward_links(e1, [], attr='addressBookRoots2',
                                  show_deactivated_link=0)

    def test_pretend_one_way_attributes_delete_link(self):
        e1, e2 = self.add_objects(2, 'msExchConfigurationContainer',
                                  'e_one_way')
        guid = self.get_object_guid(e2)

        self.add_linked_attribute(e1, e2, attr="addressBookRoots2")
        self.assert_forward_links(e1, [e2], attr='addressBookRoots2')

        self.remove_linked_attribute(e1, e2, attr="addressBookRoots2")

        self.assert_forward_links(e1, [], attr='addressBookRoots2')
        self.assert_forward_links(e1, [], attr='addressBookRoots2',
                                  show_deactivated_link=0)

if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


TestProgram(module=__name__, opts=subunitopts)

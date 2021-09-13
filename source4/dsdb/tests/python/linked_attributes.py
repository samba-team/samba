#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Originally based on ./sam.py
from __future__ import print_function
import optparse
import sys
import os
import itertools

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
import ldb
from samba.samdb import SamDB
from samba.dcerpc import misc

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
            except ldb.LdbError as e:
                print("tried deleting %s, got error %s" % (self.ou, e))
        self.samdb.add({'objectclass': 'organizationalUnit',
                        'dn': self.ou})

    def tearDown(self):
        super(LATests, self).tearDown()
        if not opts.no_cleanup:
            self.samdb.delete(self.ou, ['tree_delete:1'])

    def add_object(self, cn, objectclass, more_attrs={}):
        dn = "CN=%s,%s" % (cn, self.ou)
        attrs = {'cn': cn,
                 'objectclass': objectclass,
                 'dn': dn}
        attrs.update(more_attrs)
        self.samdb.add(attrs)

        return dn

    def add_objects(self, n, objectclass, prefix=None, more_attrs={}):
        if prefix is None:
            prefix = objectclass
        dns = []
        for i in range(n):
            dns.append(self.add_object("%s%d" % (prefix, i + 1),
                                       objectclass,
                                       more_attrs=more_attrs))
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

    def replace_linked_attribute(self, src, dest, attr='member',
                                 controls=None):
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, src)
        m[attr] = ldb.MessageElement(dest, ldb.FLAG_MOD_REPLACE, attr)
        self.samdb.modify(m, controls=controls)

    def attr_search(self, obj, attr, scope=ldb.SCOPE_BASE, **controls):
        if opts.no_reveal_internals:
            if 'reveal_internals' in controls:
                del controls['reveal_internals']

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
            print(msg)
            print("expected %s" % expected)
            print("received %s" % results)

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
            print('skipping because --no-reveal-internals')
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
            print('skipping because --no-reveal-internals')
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
        self.remove_linked_attribute(g1, [])
        self.assert_forward_links(g1, [])

        # removing a duplicate link in the same message should fail
        self.add_linked_attribute(g2, [u1, u2])
        self.assertRaises(ldb.LdbError,
                          self.remove_linked_attribute, g2, [u1, u1])

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
            print('skipping because --no-reveal-internals')
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

    def test_multiple_links(self):
        u1, u2, u3, u4 = self.add_objects(4, 'user', 'u_multiple_links')
        g1, g2, g3, g4 = self.add_objects(4, 'group', 'g_multiple_links')

        self.add_linked_attribute(g1, [u1, u2, u3, u4])
        self.add_linked_attribute(g2, [u3, u1])
        self.add_linked_attribute(g3, u2)

        self.assertRaisesLdbError(ldb.ERR_ENTRY_ALREADY_EXISTS,
                                  "adding duplicate values",
                                  self.add_linked_attribute, g2,
                                  [u1, u2, u3, u2])

        self.assert_forward_links(g1, [u1, u2, u3, u4])
        self.assert_forward_links(g2, [u3, u1])
        self.assert_forward_links(g3, [u2])
        self.assert_back_links(u1, [g2, g1])
        self.assert_back_links(u2, [g3, g1])
        self.assert_back_links(u3, [g2, g1])
        self.assert_back_links(u4, [g1])

        self.remove_linked_attribute(g2, [u1, u3])
        self.remove_linked_attribute(g1, [u1, u3])

        self.assert_forward_links(g1, [u2, u4])
        self.assert_forward_links(g2, [])
        self.assert_forward_links(g3, [u2])
        self.assert_back_links(u1, [])
        self.assert_back_links(u2, [g3, g1])
        self.assert_back_links(u3, [])
        self.assert_back_links(u4, [g1])

        self.add_linked_attribute(g1, [u1, u3])
        self.add_linked_attribute(g2, [u3, u1])
        self.add_linked_attribute(g3, [u1, u3])

        self.assert_forward_links(g1, [u1, u2, u3, u4])
        self.assert_forward_links(g2, [u1, u3])
        self.assert_forward_links(g3, [u1, u2, u3])
        self.assert_back_links(u1, [g1, g2, g3])
        self.assert_back_links(u2, [g3, g1])
        self.assert_back_links(u3, [g3, g2, g1])
        self.assert_back_links(u4, [g1])

    def test_la_links_replace(self):
        u1, u2, u3, u4 = self.add_objects(4, 'user', 'u_replace')
        g1, g2, g3, g4 = self.add_objects(4, 'group', 'g_replace')

        self.add_linked_attribute(g1, [u1, u2])
        self.add_linked_attribute(g2, [u1, u3])
        self.add_linked_attribute(g3, u1)

        self.replace_linked_attribute(g1, [u2])
        self.replace_linked_attribute(g2, [u2, u3])
        self.replace_linked_attribute(g3, [u1, u3])
        self.replace_linked_attribute(g4, [u4])

        self.assert_forward_links(g1, [u2])
        self.assert_forward_links(g2, [u3, u2])
        self.assert_forward_links(g3, [u3, u1])
        self.assert_forward_links(g4, [u4])
        self.assert_back_links(u1, [g3])
        self.assert_back_links(u2, [g1, g2])
        self.assert_back_links(u3, [g2, g3])
        self.assert_back_links(u4, [g4])

        self.replace_linked_attribute(g1, [u1, u2, u3])
        self.replace_linked_attribute(g2, [u1])
        self.replace_linked_attribute(g3, [u2])
        self.replace_linked_attribute(g4, [])

        self.assert_forward_links(g1, [u1, u2, u3])
        self.assert_forward_links(g2, [u1])
        self.assert_forward_links(g3, [u2])
        self.assert_forward_links(g4, [])
        self.assert_back_links(u1, [g1, g2])
        self.assert_back_links(u2, [g1, g3])
        self.assert_back_links(u3, [g1])
        self.assert_back_links(u4, [])

        self.assertRaisesLdbError(ldb.ERR_ENTRY_ALREADY_EXISTS,
                                  "replacing duplicate values",
                                  self.replace_linked_attribute, g2,
                                  [u1, u2, u3, u2])

    def test_la_links_replace2(self):
        users = self.add_objects(12, 'user', 'u_replace2')
        g1, = self.add_objects(1, 'group', 'g_replace2')

        self.add_linked_attribute(g1, users[:6])
        self.assert_forward_links(g1, users[:6])
        self.replace_linked_attribute(g1, users)
        self.assert_forward_links(g1, users)
        self.replace_linked_attribute(g1, users[6:])
        self.assert_forward_links(g1, users[6:])
        self.remove_linked_attribute(g1, users[6:9])
        self.assert_forward_links(g1, users[9:])
        self.remove_linked_attribute(g1, users[9:])
        self.assert_forward_links(g1, [])

    def test_la_links_permutations(self):
        """Make sure the order in which we add links doesn't matter."""
        users = self.add_objects(3, 'user', 'u_permutations')
        groups = self.add_objects(6, 'group', 'g_permutations')

        for g, p in zip(groups, itertools.permutations(users)):
            self.add_linked_attribute(g, p)

        # everyone should be in every group
        for g in groups:
            self.assert_forward_links(g, users)

        for u in users:
            self.assert_back_links(u, groups)

        for g, p in zip(groups[::-1], itertools.permutations(users)):
            self.replace_linked_attribute(g, p)

        for g in groups:
            self.assert_forward_links(g, users)

        for u in users:
            self.assert_back_links(u, groups)

        for g, p in zip(groups, itertools.permutations(users)):
            self.remove_linked_attribute(g, p)

        for g in groups:
            self.assert_forward_links(g, [])

        for u in users:
            self.assert_back_links(u, [])

    def test_la_links_relaxed(self):
        """Check that the relax control doesn't mess with linked attributes."""
        relax_control = ['relax:0']

        users = self.add_objects(10, 'user', 'u_relax')
        groups = self.add_objects(3, 'group', 'g_relax',
                                  more_attrs={'member': users[:2]})
        g_relax1, g_relax2, g_uptight = groups

        # g_relax1 has all users added at once
        # g_relax2 gets them one at a time in reverse order
        # g_uptight never relaxes

        self.add_linked_attribute(g_relax1, users[2:5], controls=relax_control)

        for u in reversed(users[2:5]):
            self.add_linked_attribute(g_relax2, u, controls=relax_control)
            self.add_linked_attribute(g_uptight, u)

        for g in groups:
            self.assert_forward_links(g, users[:5])

            self.add_linked_attribute(g, users[5:7])
            self.assert_forward_links(g, users[:7])

            for u in users[7:]:
                self.add_linked_attribute(g, u)

            self.assert_forward_links(g, users)

        for u in users:
            self.assert_back_links(u, groups)

        # try some replacement permutations
        import random
        random.seed(1)
        users2 = users[:]
        for i in range(5):
            random.shuffle(users2)
            self.replace_linked_attribute(g_relax1, users2,
                                          controls=relax_control)

            self.assert_forward_links(g_relax1, users)

        for i in range(5):
            random.shuffle(users2)
            self.remove_linked_attribute(g_relax2, users2,
                                         controls=relax_control)
            self.remove_linked_attribute(g_uptight, users2)

            self.replace_linked_attribute(g_relax1, [], controls=relax_control)

            random.shuffle(users2)
            self.add_linked_attribute(g_relax2, users2,
                                      controls=relax_control)
            self.add_linked_attribute(g_uptight, users2)
            self.replace_linked_attribute(g_relax1, users2,
                                          controls=relax_control)

            self.assert_forward_links(g_relax1, users)
            self.assert_forward_links(g_relax2, users)
            self.assert_forward_links(g_uptight, users)

        for u in users:
            self.assert_back_links(u, groups)

    def test_add_all_at_once(self):
        """All these other tests are creating linked attributes after the
        objects are there. We want to test creating them all at once
        using LDIF.
        """
        users = self.add_objects(7, 'user', 'u_all_at_once')
        g1, g3 = self.add_objects(2, 'group', 'g_all_at_once',
                                  more_attrs={'member': users})
        (g2,) = self.add_objects(1, 'group', 'g_all_at_once2',
                                 more_attrs={'member': users[:5]})

        self.assertRaisesLdbError(ldb.ERR_ENTRY_ALREADY_EXISTS,
                                  "adding multiple duplicate values",
                                  self.add_objects, 1, 'group',
                                  'g_with_duplicate_links',
                                  more_attrs={'member': users[:5] + users[1:2]})

        self.assert_forward_links(g1, users)
        self.assert_forward_links(g2, users[:5])
        self.assert_forward_links(g3, users)
        for u in users[:5]:
            self.assert_back_links(u, [g1, g2, g3])
        for u in users[5:]:
            self.assert_back_links(u, [g1, g3])

        self.remove_linked_attribute(g2, users[0])
        self.remove_linked_attribute(g2, users[1])
        self.add_linked_attribute(g2, users[1])
        self.add_linked_attribute(g2, users[5])
        self.add_linked_attribute(g2, users[6])

        self.assert_forward_links(g1, users)
        self.assert_forward_links(g2, users[1:])

        for u in users[1:]:
            self.remove_linked_attribute(g2, u)
        self.remove_linked_attribute(g1, users)

        for u in users:
            self.samdb.delete(u)

        self.assert_forward_links(g1, [])
        self.assert_forward_links(g2, [])
        self.assert_forward_links(g3, [])

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


    def test_self_link(self):
        e1, = self.add_objects(1, 'group',
                              'e_self_link')

        guid = self.get_object_guid(e1)
        self.add_linked_attribute(e1, e1, attr="member")
        self.assert_forward_links(e1, [e1], attr='member')
        self.assert_back_links(e1, [e1], attr='memberOf')

        try:
            self.samdb.delete(e1)
        except ldb.LdbError:
            # Cope with the current bug to make this a failure
            self.remove_linked_attribute(e1, e1, attr="member")
            self.samdb.delete(e1)
            self.fail("could not delete object with link to itself")

        self.assert_forward_links('<GUID=%s>' % guid, [], attr='member',
                                  show_deleted=1)
        self.assert_forward_links('<GUID=%s>' % guid, [], attr='member',
                                  show_deactivated_link=0,
                                  show_deleted=1)
        self.assert_back_links('<GUID=%s>' % guid, [], attr='memberOf',
                               show_deleted=1)

if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


TestProgram(module=__name__, opts=subunitopts)

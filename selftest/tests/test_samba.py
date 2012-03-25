# test_run.py -- Tests for selftest.target.samba
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 3
# of the License or (at your option) any later version of
# the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

"""Tests for selftest.target.samba."""

from cStringIO import StringIO

from selftest.tests import TestCase

from selftest.target.samba import (
    bindir_path,
    get_interface,
    mk_realms_stanza,
    write_krb5_conf,
    )


class BinDirPathTests(TestCase):

    def test_mapping(self):
        self.assertEquals("exe4",
            bindir_path({"exe": "exe4"}, "/some/path", "exe"))
        self.assertEquals("/bin/ls",
            bindir_path({"exe": "ls"}, "/bin", "exe"))

    def test_no_mapping(self):
        self.assertEqual("exe", bindir_path({}, "/some/path", "exe"))
        self.assertEqual("/bin/ls",
            bindir_path({}, "/bin", "ls"))


class MkRealmsStanzaTests(TestCase):

    def test_basic(self):
        self.assertEqual(
           mk_realms_stanza("rijk", "dnsnaam", "domein", "ipv4_kdc"),
          '''\
 rijk = {
  kdc = ipv4_kdc:88
  admin_server = ipv4_kdc:88
  default_domain = dnsnaam
 }
 dnsnaam = {
  kdc = ipv4_kdc:88
  admin_server = ipv4_kdc:88
  default_domain = dnsnaam
 }
 domein = {
  kdc = ipv4_kdc:88
  admin_server = ipv4_kdc:88
  default_domain = dnsnaam
 }

''')


class WriteKrb5ConfTests(TestCase):

    def test_simple(self):
        f = StringIO()
        write_krb5_conf(f, "rijk", "dnsnaam", "domein", "kdc_ipv4")
        self.assertEquals('''\
#Generated krb5.conf for rijk

[libdefaults]
\tdefault_realm = rijk
\tdns_lookup_realm = false
\tdns_lookup_kdc = false
\tticket_lifetime = 24h
\tforwardable = yes
\tallow_weak_crypto = yes

[realms]
 rijk = {
  kdc = kdc_ipv4:88
  admin_server = kdc_ipv4:88
  default_domain = dnsnaam
 }
 dnsnaam = {
  kdc = kdc_ipv4:88
  admin_server = kdc_ipv4:88
  default_domain = dnsnaam
 }
 domein = {
  kdc = kdc_ipv4:88
  admin_server = kdc_ipv4:88
  default_domain = dnsnaam
 }

''', f.getvalue())


class GetInterfaceTests(TestCase):

    def test_get_interface(self):
        self.assertEquals(21, get_interface("localdc"))
        self.assertEquals(4, get_interface("localshare4"))

    def test_unknown(self):
        self.assertRaises(KeyError, get_interface, "unknown")

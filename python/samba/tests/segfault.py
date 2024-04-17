# Unix SMB/CIFS implementation.
#
# Copyright (C) Catalyst.Net Ltd. 2017
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

"""Test whether various python calls segfault when given unexpected input.
"""

import samba.tests
import os
import sys
from samba.net import Net
from samba.credentials import DONT_USE_KERBEROS
from samba.dcerpc import misc, drsuapi, samr, unixinfo, dnsserver
from samba import auth, gensec
from samba.samdb import SamDB
from samba import netbios
from samba import registry
from samba import ldb
from samba import messaging
from samba import dsdb

import traceback


def segfault_detector(f):
    def wrapper(*args, **kwargs):
        pid = os.fork()
        if pid == 0:
            try:
                f(*args, **kwargs)
            except Exception as e:
                traceback.print_exc()
            sys.stderr.flush()
            sys.stdout.flush()
            os._exit(0)

        pid2, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            signal = os.WTERMSIG(status)
            raise AssertionError("Failed with signal %d" % signal)

    return wrapper


def no_gdb_backtrace(f):
    from os import environ
    def w(*args, **kwargs):
        old = environ.get('PLEASE_NO_GDB_BACKTRACE')
        environ['PLEASE_NO_GDB_BACKTRACE'] = '1'
        try:
            f(*args, **kwargs)
        finally:
            if old is not None:
                environ['PLEASE_NO_GDB_BACKTRACE'] = old
            else:
                del environ['PLEASE_NO_GDB_BACKTRACE']

    return w


class SegfaultTests(samba.tests.TestCase):
    def get_lp_et_al(self):
        server = os.environ["SERVER"]
        lp = self.get_loadparm()

        creds = self.insta_creds(template=self.get_credentials(),
                                 kerberos_state=DONT_USE_KERBEROS)
        return lp, creds, server

    def get_samdb(self):
        lp, creds, server = self.get_lp_et_al()
        url = 'ldap://' + server
        ldb = SamDB(url, credentials=creds, lp=lp)
        return ldb

    @segfault_detector
    def test_net_replicate_init__1(self):
        lp, creds, server = self.get_lp_et_al()
        net = Net(creds, lp, server=server)
        net.replicate_init(42, lp, None, misc.GUID())

    @no_gdb_backtrace
    @segfault_detector
    def test_net_replicate_init__3(self):
        # third argument is also unchecked
        samdb = self.get_samdb()
        lp, creds, server = self.get_lp_et_al()
        net = Net(creds, lp, server=server)
        net.replicate_init(samdb, lp, 42, misc.GUID())

    @segfault_detector
    def test_net_replicate_chunk_1(self):
        lp, creds, server = self.get_lp_et_al()
        ctr = drsuapi.DsGetNCChangesCtr6()
        net = Net(creds, lp, server=server)
        net.replicate_chunk(42, 1, ctr)

    @segfault_detector
    def test_auth_context_gensec_start_server(self):
        a = auth.AuthContext(ldb=42, methods=['sam'])
        # there is no failure yet because the ldb is not actually
        # dereferenced.
        g = gensec.Security.start_server(auth_context=a)
        # and still the ldb is not dereferenced...

    @segfault_detector
    def test_auth_user_session(self):
        s = auth.user_session(ldb=42, principal='foo')

    @segfault_detector
    def test_gensec_start_server(self):
        gensec.Security.start_server(auth_context=42)

    @segfault_detector
    def test_netbios_query_name(self):
        n = netbios.Node()
        t = n.query_name((42, 'foo'), 'localhost')

    @segfault_detector
    def test_encrypt_netr_crypt_password(self):
        lp, creds, server = self.get_lp_et_al()
        creds.encrypt_netr_crypt_password(42)

    @segfault_detector
    def test_hive_open_ldb(self):
        # we don't need to provide a valid path because we segfault first
        try:
            registry.open_ldb('', credentials=42)
        except ldb.LdbError as e:
            print("failed with %s" % e)

    @segfault_detector
    def test_hive_open_hive(self):
        # we don't need to provide a valid path because we segfault first
        try:
            registry.open_hive('s', 's', 's', 's')
        except ldb.LdbError as e:
            print("failed with %s" % e)

    @segfault_detector
    def test_ldb_add_nameless_element(self):
        m = ldb.Message()
        e = ldb.MessageElement('q')
        try:
            m.add(e)
        except ldb.LdbError:
            pass
        str(m)

    @segfault_detector
    def test_messaging_deregister(self):
        messaging.deregister('s', 's', 's', False)

    @segfault_detector
    def test_rpcecho(self):
        from samba.dcerpc import echo
        echo.rpcecho("")

    @segfault_detector
    def test_dcerpc_idl_ref_elements(self):
        """There are many pidl generated functions that crashed on this
        pattern, where a NULL pointer was created rather than an empty
        structure."""
        samr.Connect5().out_info_out = 1

    @segfault_detector
    def test_dcerpc_idl_unixinfo_elements(self):
        """Dereferencing is sufficient to crash"""
        unixinfo.GetPWUid().out_infos

    @segfault_detector
    def test_dcerpc_idl_inline_arrays(self):
        """Inline arrays were incorrectly handled."""
        dnsserver.DNS_RPC_SERVER_INFO_DOTNET().pExtensions

    @segfault_detector
    def test_dcerpc_idl_set_inline_arrays(self):
        """Setting an inline array was incorrectly handled."""
        a = dnsserver.DNS_EXTENSION()
        x = dnsserver.DNS_RPC_DP_INFO()
        x.pwszReserved = [a, a, a]

    @no_gdb_backtrace
    @segfault_detector
    def test_dnsp_string_list(self):
        from samba.dcerpc import dnsp
        # We segfault if s.count is greater than the length of s.str
        s = dnsp.string_list()
        s.count = 3
        s.str

    @no_gdb_backtrace
    @segfault_detector
    def test_dns_record(self):
        from samba.dnsserver import TXTRecord
        from samba.dcerpc import dnsp
        # there are many others here
        rec = TXTRecord(["a", "b", "c"])
        rec.wType = dnsp.DNS_TYPE_A
        rec.data

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_msg_diff(self):
        samdb = self.get_samdb()

        msg = ldb.Message()
        msg.dn = ldb.Dn(samdb, '')
        diff = samdb.msg_diff(msg, msg)

        del msg
        diff.dn

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_msg_del_dn(self):
        msg = ldb.Message()
        del msg.dn

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_control_del_critical(self):
        samdb = self.get_samdb()

        c = ldb.Control(samdb, 'relax:1')
        del c.critical

    @segfault_detector
    def test_random_bytes(self):
        # memory error from SIZE_MAX -1 allocation.
        from samba import generate_random_bytes
        generate_random_bytes(-1)

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_get_default_basedn(self):
        samdb = self.get_samdb()

        dn = samdb.get_default_basedn()
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        del samdb
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_get_ncroot_existing(self):
        samdb = self.get_samdb()

        base_dn = samdb.get_default_basedn()
        dn = samdb.get_nc_root(base_dn)
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        del samdb
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_get_ncroot_not_existing(self):
        samdb = self.get_samdb()

        base_dn = samdb.get_default_basedn()
        base_dn.add_child("CN=TEST")
        dn = samdb.get_nc_root(base_dn)
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        del samdb
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_get_wellknown_dn(self):
        samdb = self.get_samdb()

        base_dn = samdb.get_default_basedn()
        wk_dn = samdb.get_wellknown_dn(base_dn, dsdb.DS_GUID_LOSTANDFOUND_CONTAINER)
        wk_dn.add_child("CN=TEST")
        wk_dn.set_component(0, "CN", "Test2")
        del samdb
        del base_dn
        wk_dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_concat(self):
        samdb = self.get_samdb()

        dn1 = ldb.Dn(samdb, "CN=foo")
        dn2 = ldb.Dn(samdb, "CN=bar")
        dn = dn1 + dn2
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        del samdb
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_get_parent(self):
        samdb = self.get_samdb()

        dn1 = ldb.Dn(samdb, "CN=foo,CN=bar")
        dn = dn1.parent()
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        del samdb
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_search_result(self):
        samdb = self.get_samdb()
        base_dn = samdb.get_default_basedn()
        res = samdb.search(base=base_dn,
                           scope=ldb.SCOPE_SUBTREE,
                           attrs=[],
                           expression="(cn=administrator)")
        msg = res[0]
        dn1 = msg.dn
        dn = dn1.parent()
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        del samdb
        del msg
        del dn1
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")

        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")

        del samdb
        del msg
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_ldif_parse(self):

        ldif = """dn: cn=test
        changetype: add
        -
        cn: test
        -
        """
        samdb = self.get_samdb()
        for changetype, msg in samdb.parse_ldif(ldif):
            dn = msg.dn
            dn.add_child("CN=TEST")
            dn.set_component(0, "CN", "Test2")

            del samdb
            del msg
            dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_dict_init(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")

        msg2 = ldb.Message.from_dict(samdb,
                                     {"dn": msg.dn,
                                      "foo": ["bar"]})
        del msg
        dn = msg2.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")

        del samdb

        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_msg_init(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")

        msg2 = ldb.Message(dn=msg.dn)
        del msg
        dn = msg2.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")

        del samdb

        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_msg_diff(self):
        samdb = self.get_samdb()
        msg = ldb.Message()
        msg.dn = ldb.Dn(samdb, "CN=foo")
        msg["foo"] = ["bar"]

        msg2 = ldb.Message()
        msg2.dn = ldb.Dn(samdb, "CN=foo")
        msg2["foo"] = ["bar2"]

        msg3 = samdb.msg_diff(msg, msg2)
        dn = msg3.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")

        del samdb
        del msg3
        del msg2
        del msg
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_msg_from_dict(self):
        samdb = self.get_samdb()
        msg = ldb.Message.from_dict(samdb,
                                    {
                                        "dn": "CN=foo",
                                        "foo": ["bar"]},
                                    ldb.FLAG_MOD_REPLACE)

        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")

        del samdb
        del msg
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign_disconnecting_connection(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")
        samdb.disconnect()
        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")

        del samdb
        del msg
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign_disconnecting_connection_no_del(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")
        samdb.disconnect()
        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign_disconnecting_connection_later__no_del(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")
        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        samdb.disconnect()
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign_disconnecting_connection_add_child_later(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")
        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        samdb.disconnect()
        dn.add_child("CN=TeSt")

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign_disconnecting_connection_later(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")
        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        samdb.disconnect()
        del samdb
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign_disconnecting_connection_reconnecting_later(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")
        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        samdb.disconnect()
        lp, creds, server = self.get_lp_et_al()
        url = 'ldap://' + server
        samdb.set_loadparm(lp)
        samdb.connect(url)
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign_switching_out_connection(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")
        lp, creds, server = self.get_lp_et_al()
        url = 'ldap://' + server
        samdb.disconnect()
        samdb.set_loadparm(lp)
        samdb.connect(url)

        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")
        samdb.disconnect()
        samdb.set_loadparm(lp)
        samdb.connect(url)
        del samdb
        del msg
        dn.get_casefold()

    @no_gdb_backtrace
    @segfault_detector
    def test_ldb_use_after_free_dn_assign_disconnecting_and_switching_out_connection(self):

        msg = ldb.Message()

        samdb = self.get_samdb()
        msg.dn = ldb.Dn(samdb, "CN=Test")
        samdb.disconnect()
        lp, creds, server = self.get_lp_et_al()
        url = 'ldap://' + server
        samdb.set_loadparm(lp)
        samdb.connect(url)

        dn = msg.dn
        dn.add_child("CN=TEST")
        dn.set_component(0, "CN", "Test2")

        del samdb
        del msg
        dn.get_casefold()

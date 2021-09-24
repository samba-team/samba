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
from samba.net import Net, LIBNET_JOIN_AUTOMATIC
from samba.credentials import DONT_USE_KERBEROS
from samba import NTSTATUSError, ntstatus
from samba.dcerpc import misc, drsuapi, samr, unixinfo, dnsserver
from samba import auth, gensec
from samba.samdb import SamDB
from samba import netbios
from samba import registry
from samba import ldb
from samba import messaging

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
        signal = status & 255
        if os.WIFSIGNALED(status):
            signal = os.WTERMSIG(status)
            raise AssertionError("Failed with signal %d" % signal)

    return wrapper


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
    def test_ldb_register_module(self):
        ldb.register_module('')

    @segfault_detector
    def test_messaging_deregister(self):
        messaging.deregister('s', 's', 's', False)

    @segfault_detector
    def test_rpcecho(self):
        from dcerpc import echo
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
    def test_ldb_msg_diff(self):
        samdb = self.get_samdb()

        msg = ldb.Message()
        msg.dn = ldb.Dn(samdb, '')
        diff = samdb.msg_diff(msg, msg)

        del msg
        diff.dn

    @segfault_detector
    def test_ldb_msg_del_dn(self):
        msg = ldb.Message()
        del msg.dn

    @segfault_detector
    def test_ldb_control_del_critical(self):
        samdb = self.get_samdb()

        c = ldb.Control(samdb, 'relax:1')
        del c.critical

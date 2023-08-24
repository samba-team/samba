# Unix SMB/CIFS implementation.
# Copyright (C) Volker Lendecke <vl@samba.org> 2023
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

from samba import Ldb,tests
from samba.samba3 import param as s3param
from samba import credentials
import os

class LdapWhoami(tests.TestCase):
    def test_ldap_whoami(self):
        lp = s3param.get_context()
        lp.load(os.getenv("SERVERCONFFILE"));

        domain=os.getenv("DOMAIN")
        username=os.getenv("DC_USERNAME")

        creds = credentials.Credentials()
        creds.guess(lp)
        creds.set_domain(domain)
        creds.set_username(username)
        creds.set_password(os.getenv("DC_PASSWORD"))

        l=Ldb(f'ldap://{os.getenv("DC_SERVER_IP")}/', credentials=creds, lp=lp)
        w=l.whoami()
        self.assertEqual(w,f'u:{domain}\\{username}')

#!/usr/bin/env python
#
# python site manipulation code
# Copyright Matthieu Patou <mat@matws.net> 2011
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

"""Manipulating sites."""

import ldb
from ldb import FLAG_MOD_ADD

def create_site(samdb, configDn, siteName):
    ret = samdb.search(base=configDn, scope=ldb.SCOPE_SUBTREE,
                    expression='(&(objectclass=Site)(cn=%s))' % siteName)
    if len(ret) != 0:
        raise Exception('A site with the name %s already exists' % siteName)

    m = ldb.Message()
    m.dn = ldb.Dn(samdb, "Cn=%s,CN=Sites,%s" % (siteName, str(configDn)))
    m["objectclass"] = ldb.MessageElement("site", FLAG_MOD_ADD, "objectclass")

    samdb.add(m)

    m2 = ldb.Message()
    m2.dn = ldb.Dn(samdb, "Cn=NTDS Site Settings,%s" % str(m.dn))
    m2["objectclass"] = ldb.MessageElement("nTDSSiteSettings", FLAG_MOD_ADD, "objectclass")

    samdb.add(m2)

    m3 = ldb.Message()
    m3.dn = ldb.Dn(samdb, "Cn=Servers,%s" % str(m.dn))
    m3["objectclass"] = ldb.MessageElement("serversContainer", FLAG_MOD_ADD, "objectclass")

    samdb.add(m3)

    return True

def delete_site(samdb, configDn, siteName):

    dnsite = ldb.Dn(samdb, "Cn=%s,CN=Sites,%s" % (siteName, str(configDn)))
    dnserver = ldb.Dn(samdb, "Cn=Servers,%s" % str(dnsite))

    ret = samdb.search(base=dnserver, scope=ldb.SCOPE_ONELEVEL,
                    expression='(objectclass=server)')
    if len(ret) != 0:
        raise Exception('Site %s still has servers in it, move them before removal' % siteName)

    samdb.delete(dnsite, ["tree_delete:0"])

    return True

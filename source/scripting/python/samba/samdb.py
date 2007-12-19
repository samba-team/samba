#!/usr/bin/python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
#
# Based on the original in EJS:
# Copyright (C) Andrew Tridgell 2005
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

import samba
import misc
import ldb

class SamDB(samba.Ldb):
    def __init__(self, url=None, session_info=None, credentials=None, 
                 modules_dir=None, lp=None):
        super(SamDB, self).__init__(session_info=session_info, credentials=credentials,
                                    modules_dir=modules_dir, lp=lp)
        assert misc.dsdb_set_global_schema(self) == 0
        assert misc.ldb_register_samba_handlers(self) == 0
        if url:
            self.connect(url)

    def add_foreign(self, domaindn, sid, desc):
        """Add a foreign security principle."""
        add = """
dn: CN=%s,CN=ForeignSecurityPrincipals,%s
objectClass: top
objectClass: foreignSecurityPrincipal
description: %s
        """ % (sid, domaindn, desc)
        # deliberately ignore errors from this, as the records may
        # already exist
        for msg in self.parse_ldif(add):
            self.add(msg[1])

    def setup_name_mapping(self, domaindn, sid, unixname):
        """Setup a mapping between a sam name and a unix name."""
        res = self.search(ldb.Dn(self, domaindn), ldb.SCOPE_SUBTREE, 
                         "objectSid=%s" % sid, ["dn"])
        assert len(res) == 1, "Failed to find record for objectSid %s" % sid

        mod = """
dn: %s
changetype: modify
replace: unixName
unixName: %s
""" % (res[0].dn, unixname)
        self.modify(self.parse_ldif(mod).next()[1])

    def enable_account(self, user_dn):
        """enable the account.
        
        :param user_dn: Dn of the account to enable.
        """
        res = self.search(user_dn, SCOPE_ONELEVEL, None, ["userAccountControl"])
        assert len(res) == 1
        userAccountControl = res[0].userAccountControl
        userAccountControl = userAccountControl - 2 # remove disabled bit
        mod = """
dn: %s
changetype: modify
replace: userAccountControl
userAccountControl: %u
""" % (user_dn, userAccountControl)
        self.modify(mod)

    def newuser(self, username, unixname, password, message):
        """add a new user record"""
        # connect to the sam 
        self.transaction_start()

        # find the DNs for the domain and the domain users group
        res = self.search("", SCOPE_BASE, "defaultNamingContext=*", 
                         ["defaultNamingContext"])
        assert(len(res) == 1 and res[0].defaultNamingContext is not None)
        domain_dn = res[0].defaultNamingContext
        assert(domain_dn is not None)
        dom_users = self.searchone(domain_dn, "dn", "name=Domain Users")
        assert(dom_users is not None)

        user_dn = "CN=%s,CN=Users,%s" % (username, domain_dn)

        #
        #  the new user record. note the reliance on the samdb module to fill
        #  in a sid, guid etc
        #
        ldif = """
dn: %s
sAMAccountName: %s
unixName: %s
sambaPassword: %s
objectClass: user
    """ % (user_dn, username, unixname, password)
        #  add the user to the users group as well
        modgroup = """
dn: %s
changetype: modify
add: member
member: %s
""" % (dom_users, user_dn)


        #  now the real work
        message("Adding user %s" % user_dn)
        self.add(ldif)

        message("Modifying group %s" % dom_users)
        self.modify(modgroup)

        #  modify the userAccountControl to remove the disabled bit
        enable_account(self, user_dn)
        self.transaction_commit()

    def set_domain_sid(self, sid):
        misc.samdb_set_domain_sid(self, sid)

    def attach_schema_from_ldif(self, pf, df):
        misc.dsdb_attach_schema_from_ldif_file(self, pf, df)

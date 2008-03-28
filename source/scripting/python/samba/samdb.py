#!/usr/bin/python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
#
# Based on the original in EJS:
# Copyright (C) Andrew Tridgell <tridge@samba.org> 2005
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

"""Convenience functions for using the SAM."""

import samba
import misc
import ldb

class SamDB(samba.Ldb):
    """The SAM database."""
    def __init__(self, url=None, session_info=None, credentials=None, 
                 modules_dir=None, lp=None):
        """Open the Sam Database.

        :param url: URL of the database.
        """
        super(SamDB, self).__init__(session_info=session_info, credentials=credentials,
                                    modules_dir=modules_dir, lp=lp)
        assert misc.dsdb_set_global_schema(self) == 0
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
        """Setup a mapping between a sam name and a unix name.
        
        :param domaindn: DN of the domain.
        :param sid: SID of the NT-side of the mapping.
        :param unixname: Unix name to map to.
        """
        res = self.search(domaindn, ldb.SCOPE_SUBTREE, 
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
        """Enable an account.
        
        :param user_dn: Dn of the account to enable.
        """
        res = self.search(user_dn, ldb.SCOPE_BASE, None, ["userAccountControl"])
        assert len(res) == 1
        userAccountControl = res[0]["userAccountControl"][0]
        userAccountControl = int(userAccountControl)
        if (userAccountControl & 0x2):
            userAccountControl = userAccountControl & ~0x2 # remove disabled bit
        if (userAccountControl & 0x20):
            userAccountControl = userAccountControl & ~0x20 # remove 'no password required' bit

        mod = """
dn: %s
changetype: modify
replace: userAccountControl
userAccountControl: %u
""" % (user_dn, userAccountControl)
        self.modify_ldif(mod)

    def newuser(self, username, unixname, password):
        """add a new user record.
        
        :param username: Name of the new user.
        :param unixname: Name of the unix user to map to.
        :param password: Password for the new user
        """
        # connect to the sam 
        self.transaction_start()

        # find the DNs for the domain and the domain users group
        res = self.search("", scope=ldb.SCOPE_BASE, 
                          expression="(defaultNamingContext=*)", 
                          attrs=["defaultNamingContext"])
        assert(len(res) == 1 and res[0]["defaultNamingContext"] is not None)
        domain_dn = res[0]["defaultNamingContext"][0]
        assert(domain_dn is not None)
        user_dn = "CN=%s,CN=Users,%s" % (username, domain_dn)

        #
        #  the new user record. note the reliance on the samdb module to fill
        #  in a sid, guid etc
        #
        #  now the real work
        self.add({"dn": user_dn, 
            "sAMAccountName": username,
            "unixName": unixname,
            "sambaPassword": password,
            "objectClass": "user"})

        #  modify the userAccountControl to remove the disabled bit
        self.enable_account(user_dn)
        self.transaction_commit()

    def setpassword(self, filter, password):
        """Set a password on a user record
        
        :param filter: LDAP filter to find the user (eg samccountname=name)
        :param password: Password for the user
        """
        # connect to the sam 
        self.transaction_start()

        # find the DNs for the domain
        res = self.search("", scope=ldb.SCOPE_BASE, 
                          expression="(defaultNamingContext=*)", 
                          attrs=["defaultNamingContext"])
        assert(len(res) == 1 and res[0]["defaultNamingContext"] is not None)
        domain_dn = res[0]["defaultNamingContext"][0]
        assert(domain_dn is not None)

        res = self.search(domain_dn, scope=ldb.SCOPE_SUBTREE, 
                          expression=filter,
                          attrs=[])
        assert(len(res) == 1)
        user_dn = res[0].dn

        setpw = """
dn: %s
changetype: modify
replace: sambaPassword
sambaPassword: %s
""" % (user_dn, password)

        self.modify_ldif(setpw)

        #  modify the userAccountControl to remove the disabled bit
        self.enable_account(user_dn)
        self.transaction_commit()

    def set_domain_sid(self, sid):
        """Change the domain SID used by this SamDB.

        :param sid: The new domain sid to use.
        """
        misc.samdb_set_domain_sid(self, sid)

    def attach_schema_from_ldif(self, pf, df):
        misc.dsdb_attach_schema_from_ldif_file(self, pf, df)

    def set_invocation_id(self, invocation_id):
    	"""Set the invocation id for this SamDB handle.
    	
    	:param invocation_id: GUID of the invocation id.
    	"""
    	misc.dsdb_set_ntds_invocation_id(self, invocation_id)

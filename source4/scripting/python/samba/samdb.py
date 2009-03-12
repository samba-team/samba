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
import glue
import ldb
from samba.idmap import IDmapDB
import pwd
import time
import base64

__docformat__ = "restructuredText"

class SamDB(samba.Ldb):
    """The SAM database."""

    def __init__(self, url=None, session_info=None, credentials=None, 
                 modules_dir=None, lp=None):
        """Open the Sam Database.

        :param url: URL of the database.
        """
        self.lp = lp
        super(SamDB, self).__init__(session_info=session_info, credentials=credentials,
                                    modules_dir=modules_dir, lp=lp)
        glue.dsdb_set_global_schema(self)
        if url:
            self.connect(url)
        else:
            self.connect(lp.get("sam database"))

    def connect(self, url):
        super(SamDB, self).connect(self.lp.private_path(url))

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

    def add_stock_foreign_sids(self):
        domaindn = self.domain_dn()
        self.add_foreign(domaindn, "S-1-5-7", "Anonymous")
        self.add_foreign(domaindn, "S-1-1-0", "World")
        self.add_foreign(domaindn, "S-1-5-2", "Network")
        self.add_foreign(domaindn, "S-1-5-18", "System")
        self.add_foreign(domaindn, "S-1-5-11", "Authenticated Users")

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

    def domain_dn(self):
        # find the DNs for the domain and the domain users group
        res = self.search("", scope=ldb.SCOPE_BASE, 
                          expression="(defaultNamingContext=*)", 
                          attrs=["defaultNamingContext"])
        assert(len(res) == 1 and res[0]["defaultNamingContext"] is not None)
        return res[0]["defaultNamingContext"][0]

    def newuser(self, username, unixname, password):
        """add a new user record.
        
        :param username: Name of the new user.
        :param unixname: Name of the unix user to map to.
        :param password: Password for the new user
        """
        # connect to the sam 
        self.transaction_start()
        try:
            domain_dn = self.domain_dn()
            assert(domain_dn is not None)
            user_dn = "CN=%s,CN=Users,%s" % (username, domain_dn)

            #
            #  the new user record. note the reliance on the samdb module to 
            #  fill in a sid, guid etc
            #
            #  now the real work
            self.add({"dn": user_dn, 
                "sAMAccountName": username,
                "userPassword": password,
                "objectClass": "user"})

            res = self.search(user_dn, scope=ldb.SCOPE_BASE,
                              expression="objectclass=*",
                              attrs=["objectSid"])
            assert len(res) == 1
            user_sid = self.schema_format_value("objectSid", res[0]["objectSid"][0])
            
            try:
                idmap = IDmapDB(lp=self.lp)

                user = pwd.getpwnam(unixname)
                # setup ID mapping for this UID
                
                idmap.setup_name_mapping(user_sid, idmap.TYPE_UID, user[2])

            except KeyError:
                pass

            #  modify the userAccountControl to remove the disabled bit
            self.enable_account(user_dn)
        except:
            self.transaction_cancel()
            raise
        self.transaction_commit()

    def setpassword(self, filter, password):
        """Set a password on a user record
        
        :param filter: LDAP filter to find the user (eg samccountname=name)
        :param password: Password for the user
        """
        # connect to the sam 
        self.transaction_start()
        try:
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
replace: userPassword
userPassword:: %s
""" % (user_dn, base64.b64encode(password))

            self.modify_ldif(setpw)

            #  modify the userAccountControl to remove the disabled bit
            self.enable_account(user_dn)
        except:
            self.transaction_cancel()
            raise
        self.transaction_commit()

    def set_domain_sid(self, sid):
        """Change the domain SID used by this SamDB.

        :param sid: The new domain sid to use.
        """
        glue.samdb_set_domain_sid(self, sid)

    def attach_schema_from_ldif(self, pf, df):
        glue.dsdb_attach_schema_from_ldif_file(self, pf, df)

    def set_invocation_id(self, invocation_id):
        """Set the invocation id for this SamDB handle.
        
        :param invocation_id: GUID of the invocation id.
        """
        glue.dsdb_set_ntds_invocation_id(self, invocation_id)

    def setexpiry(self, user, expiry_seconds, noexpiry):
        """Set the password expiry for a user
        
        :param expiry_seconds: expiry time from now in seconds
        :param noexpiry: if set, then don't expire password
        """
        self.transaction_start()
        try:
            res = self.search(base=self.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                              expression=("(samAccountName=%s)" % user),
                              attrs=["userAccountControl", "accountExpires"])
            assert len(res) == 1
            userAccountControl = int(res[0]["userAccountControl"][0])
            accountExpires     = int(res[0]["accountExpires"][0])
            if noexpiry:
                userAccountControl = userAccountControl | 0x10000
                accountExpires = 0
            else:
                userAccountControl = userAccountControl & ~0x10000
                accountExpires = glue.unix2nttime(expiry_seconds + int(time.time()))

            mod = """
dn: %s
changetype: modify
replace: userAccountControl
userAccountControl: %u
replace: accountExpires
accountExpires: %u
""" % (res[0].dn, userAccountControl, accountExpires)
            # now change the database
            self.modify_ldif(mod)
        except:
            self.transaction_cancel()
            raise
        self.transaction_commit();

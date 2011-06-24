#!/usr/bin/env python
#
# delegation management
#
# Copyright Matthieu Patou mat@samba.org 2010
# Copyright Stefan Metzmacher metze@samba.org 2011
# Copyright Bjoern Baumbach bb@sernet.de 2011
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

import samba.getopt as options
import ldb
import re
from samba import provision
from samba import dsdb
from samba.samdb import SamDB
from samba.auth import system_session
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option
    )

def _get_user_realm_domain(user):
    """ get the realm or the domain and the base user
        from user like:
        * username
        * DOMAIN\username
        * username@REALM
    """
    baseuser = user
    realm = ""
    domain = ""
    m = re.match(r"(\w+)\\(\w+$)", user)
    if m:
        domain = m.group(1)
        baseuser = m.group(2)
        return (baseuser.lower(), domain.upper(), realm)
    m = re.match(r"(\w+)@(\w+)", user)
    if m:
        baseuser = m.group(1)
        realm = m.group(2)
    return (baseuser.lower(), domain, realm.upper())

class cmd_delegation_show(Command):
    """Show the delegation setting of an account."""
    synopsis = "%prog delegation show <accountname>"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_args = ["accountname"]

    def run(self, accountname, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        sam = SamDB(paths.samdb, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)
        print "Searching for: %s" % (cleanedaccount)
        res = sam.search(expression="sAMAccountName=%s" % cleanedaccount,
                            scope=ldb.SCOPE_SUBTREE,
                            attrs=["userAccountControl", "msDS-AllowedToDelegateTo"])
        if len(res) != 1:
            raise CommandError("Account %s found %d times" % (accountname, len(res)))

        uac = int(res[0].get("userAccountControl")[0])
        allowed = res[0].get("msDS-AllowedToDelegateTo")

        print "Account-DN: %s" %  str(res[0].dn)

        if uac & dsdb.UF_TRUSTED_FOR_DELEGATION:
            print "UF_TRUSTED_FOR_DELEGATION: 1"
        else:
            print "UF_TRUSTED_FOR_DELEGATION: 0"

        if uac & dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
            print "UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: 1"
        else:
            print "UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: 0"

        if allowed != None:
            for a in allowed:
                print "msDS-AllowedToDelegateTo: %s" % (str(a))

class cmd_delegation_for_any_service(Command):
    """Set/unset UF_TRUSTED_FOR_DELEGATION for an account."""
    synopsis = "%prog delegation for-any-service <accountname> on|off"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_args = ["accountname", "onoff"]

    def run(self, accountname, onoff, credopts=None, sambaopts=None, versionopts=None):

        on = False
        if onoff == "on":
            on = True
        elif onoff == "off":
            on = False
        else:
            raise CommandError("Invalid argument [%s]" % onoff)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        sam = SamDB(paths.samdb, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

	search_filter = "sAMAccountName=%s" % cleanedaccount
        flag = dsdb.UF_TRUSTED_FOR_DELEGATION
        try:
            sam.toggle_userAccountFlags(search_filter, flag, on=on, strict=True)
        except Exception, err:
            raise CommandError(err)

class cmd_delegation_for_any_protocol(Command):
    """Set/unset UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (S4U2Proxy) for an account."""
    synopsis = "%prog delegation for-any-protocol <accountname> on|off"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_args = ["accountname", "onoff"]

    def run(self, accountname, onoff, credopts=None, sambaopts=None, versionopts=None):

        on = False
        if onoff == "on":
            on = True
        elif onoff == "off":
            on = False
        else:
            raise CommandError("Invalid argument [%s]" % onoff)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        sam = SamDB(paths.samdb, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

	search_filter = "sAMAccountName=%s" % cleanedaccount
        flag = dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
        try:
            sam.toggle_userAccountFlags(search_filter, flag, on=on, strict=True)
        except Exception, err:
            raise CommandError(err)

class cmd_delegation_add_service(Command):
    """Add a service principal as msDS-AllowedToDelegateTo"""
    synopsis = "%prog delegation add-service  <accountname> <principal>"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_args = ["accountname", "principal"]

    def run(self, accountname, principal, credopts=None, sambaopts=None, versionopts=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        sam = SamDB(paths.samdb, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

        res = sam.search(expression="sAMAccountName=%s" % cleanedaccount,
                            scope=ldb.SCOPE_SUBTREE,
                            attrs=["msDS-AllowedToDelegateTo"])
        if len(res) != 1:
            raise CommandError("Account %s found %d times" % (accountname, len(res)))

        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["msDS-AllowedToDelegateTo"] = ldb.MessageElement([principal],
                                              ldb.FLAG_MOD_ADD,
                                              "msDS-AllowedToDelegateTo")
        try:
            sam.modify(msg)
        except Exception, err:
            raise CommandError(err)

class cmd_delegation_del_service(Command):
    """Add a service principal as msDS-AllowedToDelegateTo"""
    synopsis = "%prog delegation del-service  <accountname> <principal>"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_args = ["accountname", "principal"]

    def run(self, accountname, principal, credopts=None, sambaopts=None, versionopts=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        sam = SamDB(paths.samdb, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

        res = sam.search(expression="sAMAccountName=%s" % cleanedaccount,
                            scope=ldb.SCOPE_SUBTREE,
                            attrs=["msDS-AllowedToDelegateTo"])
        if len(res) != 1:
            raise CommandError("Account %s found %d times" % (accountname, len(res)))

        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["msDS-AllowedToDelegateTo"] = ldb.MessageElement([principal],
                                              ldb.FLAG_MOD_DELETE,
                                              "msDS-AllowedToDelegateTo")
        try:
            sam.modify(msg)
        except Exception, err:
            raise CommandError(err)

class cmd_delegation(SuperCommand):
    """Delegation management [server connection needed]"""

    subcommands = {}
    subcommands["show"] = cmd_delegation_show()
    subcommands["for-any-service"] = cmd_delegation_for_any_service()
    subcommands["for-any-protocol"] = cmd_delegation_for_any_protocol()
    subcommands["add-service"] = cmd_delegation_add_service()
    subcommands["del-service"] = cmd_delegation_del_service()

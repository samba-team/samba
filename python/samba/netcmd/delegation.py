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
from samba import provision
from samba import dsdb
from samba.samdb import SamDB
from samba.auth import system_session
from samba.dcerpc import security
from samba.netcmd.common import _get_user_realm_domain
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option
)


class cmd_delegation_show(Command):
    """Show the delegation setting of an account."""

    synopsis = "%prog <accountname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["accountname"]

    def show_security_descriptor(self, sam, security_descriptor):
        dacl = security_descriptor.dacl
        desc_type = security_descriptor.type

        warning_info = ('Security Descriptor of attribute '
                        'msDS-AllowedToActOnBehalfOfOtherIdentity')

        if dacl is None or not desc_type & security.SEC_DESC_DACL_PRESENT:
            self.errf.write(f'Warning: DACL not present in {warning_info}!\n')
            return

        if not desc_type & security.SEC_DESC_SELF_RELATIVE:
            self.errf.write(f'Warning: DACL in {warning_info} lacks '
                            f'SELF_RELATIVE flag!\n')
            return

        for ace in dacl.aces:
            trustee = ace.trustee

            # Convert the trustee SID into a DN if we can.
            try:
                res = sam.search(f'<SID={trustee}>',
                                 scope=ldb.SCOPE_BASE)
            except ldb.LdbError as err:
                num, _ = err.args
                if num != ldb.ERR_NO_SUCH_OBJECT:
                    raise
            else:
                if len(res) == 1:
                    trustee = res[0].dn

            ignore = False

            if (ace.type == security.SEC_ACE_TYPE_ACCESS_DENIED
                    or ace.type == security.SEC_ACE_TYPE_ACCESS_DENIED_OBJECT):
                self.errf.write(f'Warning: ACE in {warning_info} denies '
                                f'access for trustee {trustee}!\n')
                # Ignore the ACE if it denies access
                ignore = True
            elif (ace.type != security.SEC_ACE_TYPE_ACCESS_ALLOWED
                    and ace.type != security.SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT):
                # Ignore the ACE if it doesn't explicitly allow access
                ignore = True

            inherit_only = ace.flags & security.SEC_ACE_FLAG_INHERIT_ONLY
            object_inherit = ace.flags & security.SEC_ACE_FLAG_OBJECT_INHERIT
            container_inherit = (
                ace.flags & security.SEC_ACE_FLAG_CONTAINER_INHERIT)
            inherited_ace = ace.flags & security.SEC_ACE_FLAG_INHERITED_ACE

            if inherit_only and not object_inherit and not container_inherit:
                # Ignore the ACE if it is propagated only to child objects, but
                # neither of the object and container inherit flags are set.
                ignore = True
            else:
                if container_inherit:
                    self.errf.write(f'Warning: ACE for trustee {trustee} has '
                                    f'unexpected CONTAINER_INHERIT flag set in '
                                    f'{warning_info}!\n')
                    ignore = True

                if inherited_ace:
                    self.errf.write(f'Warning: ACE for trustee {trustee} has '
                                    f'unexpected INHERITED_ACE flag set in '
                                    f'{warning_info}!\n')
                    ignore = True

            if not ace.access_mask:
                # Ignore the ACE if it doesn't grant any permissions.
                ignore = True

            if not ignore:
                self.outf.write(f'msDS-AllowedToActOnBehalfOfOtherIdentity: '
                                f'{trustee}\n')


    def run(self, accountname, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))

        if H is None:
            path = paths.samdb
        else:
            path = H

        sam = SamDB(path, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

        res = sam.search(expression="sAMAccountName=%s" %
                         ldb.binary_encode(cleanedaccount),
                         scope=ldb.SCOPE_SUBTREE,
                         attrs=["userAccountControl", "msDS-AllowedToDelegateTo"])
        if len(res) == 0:
            raise CommandError("Unable to find account name '%s'" % accountname)
        assert(len(res) == 1)

        uac = int(res[0].get("userAccountControl")[0])
        allowed = res[0].get("msDS-AllowedToDelegateTo")

        self.outf.write("Account-DN: %s\n" % str(res[0].dn))
        self.outf.write("UF_TRUSTED_FOR_DELEGATION: %s\n"
                        % bool(uac & dsdb.UF_TRUSTED_FOR_DELEGATION))
        self.outf.write("UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: %s\n" %
                        bool(uac & dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION))

        if allowed is not None:
            for a in allowed:
                self.outf.write("msDS-AllowedToDelegateTo: %s\n" % a)


class cmd_delegation_for_any_service(Command):
    """Set/unset UF_TRUSTED_FOR_DELEGATION for an account."""

    synopsis = "%prog <accountname> [(on|off)] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["accountname", "onoff"]

    def run(self, accountname, onoff, H=None, credopts=None, sambaopts=None,
            versionopts=None):

        on = False
        if onoff == "on":
            on = True
        elif onoff == "off":
            on = False
        else:
            raise CommandError("invalid argument: '%s' (choose from 'on', 'off')" % onoff)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        if H is None:
            path = paths.samdb
        else:
            path = H

        sam = SamDB(path, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

        search_filter = "sAMAccountName=%s" % ldb.binary_encode(cleanedaccount)
        flag = dsdb.UF_TRUSTED_FOR_DELEGATION
        try:
            sam.toggle_userAccountFlags(search_filter, flag,
                                        flags_str="Trusted-for-Delegation",
                                        on=on, strict=True)
        except Exception as err:
            raise CommandError(err)


class cmd_delegation_for_any_protocol(Command):
    """Set/unset UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (S4U2Proxy) for an account."""

    synopsis = "%prog <accountname> [(on|off)] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["accountname", "onoff"]

    def run(self, accountname, onoff, H=None, credopts=None, sambaopts=None,
            versionopts=None):

        on = False
        if onoff == "on":
            on = True
        elif onoff == "off":
            on = False
        else:
            raise CommandError("invalid argument: '%s' (choose from 'on', 'off')" % onoff)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        if H is None:
            path = paths.samdb
        else:
            path = H

        sam = SamDB(path, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

        search_filter = "sAMAccountName=%s" % ldb.binary_encode(cleanedaccount)
        flag = dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
        try:
            sam.toggle_userAccountFlags(search_filter, flag,
                                        flags_str="Trusted-to-Authenticate-for-Delegation",
                                        on=on, strict=True)
        except Exception as err:
            raise CommandError(err)


class cmd_delegation_add_service(Command):
    """Add a service principal as msDS-AllowedToDelegateTo."""

    synopsis = "%prog <accountname> <principal> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["accountname", "principal"]

    def run(self, accountname, principal, H=None, credopts=None, sambaopts=None,
            versionopts=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        if H is None:
            path = paths.samdb
        else:
            path = H

        sam = SamDB(path, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

        res = sam.search(expression="sAMAccountName=%s" %
                         ldb.binary_encode(cleanedaccount),
                         scope=ldb.SCOPE_SUBTREE,
                         attrs=["msDS-AllowedToDelegateTo"])
        if len(res) == 0:
            raise CommandError("Unable to find account name '%s'" % accountname)
        assert(len(res) == 1)

        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["msDS-AllowedToDelegateTo"] = ldb.MessageElement([principal],
                                                             ldb.FLAG_MOD_ADD,
                                                             "msDS-AllowedToDelegateTo")
        try:
            sam.modify(msg)
        except Exception as err:
            raise CommandError(err)


class cmd_delegation_del_service(Command):
    """Delete a service principal as msDS-AllowedToDelegateTo."""

    synopsis = "%prog <accountname> <principal> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["accountname", "principal"]

    def run(self, accountname, principal, H=None, credopts=None, sambaopts=None,
            versionopts=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        paths = provision.provision_paths_from_lp(lp, lp.get("realm"))
        if H is None:
            path = paths.samdb
        else:
            path = H

        sam = SamDB(path, session_info=system_session(),
                    credentials=creds, lp=lp)
        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname)

        res = sam.search(expression="sAMAccountName=%s" %
                         ldb.binary_encode(cleanedaccount),
                         scope=ldb.SCOPE_SUBTREE,
                         attrs=["msDS-AllowedToDelegateTo"])
        if len(res) == 0:
            raise CommandError("Unable to find account name '%s'" % accountname)
        assert(len(res) == 1)

        msg = ldb.Message()
        msg.dn = res[0].dn
        msg["msDS-AllowedToDelegateTo"] = ldb.MessageElement([principal],
                                                             ldb.FLAG_MOD_DELETE,
                                                             "msDS-AllowedToDelegateTo")
        try:
            sam.modify(msg)
        except Exception as err:
            raise CommandError(err)


class cmd_delegation(SuperCommand):
    """Delegation management."""

    subcommands = {}
    subcommands["show"] = cmd_delegation_show()
    subcommands["for-any-service"] = cmd_delegation_for_any_service()
    subcommands["for-any-protocol"] = cmd_delegation_for_any_protocol()
    subcommands["add-service"] = cmd_delegation_add_service()
    subcommands["del-service"] = cmd_delegation_del_service()

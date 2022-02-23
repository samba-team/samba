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
from samba.ndr import ndr_pack, ndr_unpack
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

        first = True

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
                if first:
                    self.outf.write(f'  Principals that may delegate to this '
                                    f'account:\n')
                    first = False

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
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname,
                                                                 sam)

        res = sam.search(expression="sAMAccountName=%s" %
                         ldb.binary_encode(cleanedaccount),
                         scope=ldb.SCOPE_SUBTREE,
                         attrs=["userAccountControl", "msDS-AllowedToDelegateTo",
                                "msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if len(res) == 0:
            raise CommandError("Unable to find account name '%s'" % accountname)
        assert(len(res) == 1)

        uac = int(res[0].get("userAccountControl")[0])
        allowed = res[0].get("msDS-AllowedToDelegateTo")
        allowed_from = res[0].get("msDS-AllowedToActOnBehalfOfOtherIdentity", idx=0)

        self.outf.write("Account-DN: %s\n" % str(res[0].dn))
        self.outf.write("UF_TRUSTED_FOR_DELEGATION: %s\n"
                        % bool(uac & dsdb.UF_TRUSTED_FOR_DELEGATION))
        self.outf.write("UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: %s\n" %
                        bool(uac & dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION))

        if allowed:
            self.outf.write("  Services this account may delegate to:\n")
            for a in allowed:
                self.outf.write("msDS-AllowedToDelegateTo: %s\n" % a)
        if allowed_from is not None:
            try:
                security_descriptor = ndr_unpack(security.descriptor, allowed_from)
            except RuntimeError:
                self.errf.write("Warning: Security Descriptor of attribute "
                                "msDS-AllowedToActOnBehalfOfOtherIdentity "
                                "could not be unmarshalled!\n")
            else:
                self.show_security_descriptor(sam, security_descriptor)


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
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname,
                                                                 sam)

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
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname,
                                                                 sam)

        search_filter = "sAMAccountName=%s" % ldb.binary_encode(cleanedaccount)
        flag = dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
        try:
            sam.toggle_userAccountFlags(search_filter, flag,
                                        flags_str="Trusted-to-Authenticate-for-Delegation",
                                        on=on, strict=True)
        except Exception as err:
            raise CommandError(err)


class cmd_delegation_add_service(Command):
    """Add a service principal to msDS-AllowedToDelegateTo so that an account may delegate to it."""

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
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname,
                                                                 sam)

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
    """Delete a service principal from msDS-AllowedToDelegateTo so that an account may no longer delegate to it."""

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
        (cleanedaccount, realm, domain) = _get_user_realm_domain(accountname,
                                                                 sam)

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


class cmd_delegation_add_principal(Command):
    """Add a principal to msDS-AllowedToActOnBehalfOfOtherIdentity that may delegate to an account."""

    synopsis = "%prog <accountname> <principal> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
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
        cleanedaccount, _, _ = _get_user_realm_domain(accountname, sam)

        account_res = sam.search(
            expression="sAMAccountName=%s" %
            ldb.binary_encode(cleanedaccount),
            scope=ldb.SCOPE_SUBTREE,
            attrs=["msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if len(account_res) == 0:
            raise CommandError(f"Unable to find account name '{accountname}'")
        assert(len(account_res) == 1)

        data = account_res[0].get(
            "msDS-AllowedToActOnBehalfOfOtherIdentity", idx=0)
        if data is None:
            # Create the security descriptor if it is not present.
            owner_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)

            security_desc = security.descriptor()
            security_desc.revision = security.SD_REVISION
            security_desc.type = (security.SEC_DESC_DACL_PRESENT |
                                  security.SEC_DESC_SELF_RELATIVE)
            security_desc.owner_sid = owner_sid

            dacl = None
        else:
            try:
                security_desc = ndr_unpack(security.descriptor, data)
            except RuntimeError:
                raise CommandError(f"Security Descriptor of attribute "
                                   f"msDS-AllowedToActOnBehalfOfOtherIdentity "
                                   f"for account '{accountname}' could not be "
                                   f"unmarshalled!")

            dacl = security_desc.dacl

        if dacl is None:
            # Create the DACL if it is not present.
            dacl = security.acl()
            dacl.revision = security.SECURITY_ACL_REVISION_ADS
            dacl.num_aces = 0

        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        cleanedprinc, _, _ = _get_user_realm_domain(principal, sam)

        princ_res = sam.search(expression="sAMAccountName=%s" %
                               ldb.binary_encode(cleanedprinc),
                               scope=ldb.SCOPE_SUBTREE,
                               attrs=["objectSid"])
        if len(princ_res) == 0:
            raise CommandError(f"Unable to find principal name '{principal}'")
        assert(len(princ_res) == 1)

        princ_sid = security.dom_sid(
            sam.schema_format_value(
                "objectSID",
                princ_res[0].get("objectSID", idx=0)).decode("utf-8"))

        aces = dacl.aces

        # Check that there is no existing ACE for this principal.
        if any(ace.trustee == princ_sid for ace in aces):
            raise CommandError(
                f"ACE for principal '{principal}' already present in Security "
                f"Descriptor of attribute "
                f"msDS-AllowedToActOnBehalfOfOtherIdentity for account "
                f"'{accountname}'.")

        # Create the new ACE.
        ace = security.ace()
        ace.type = security.SEC_ACE_TYPE_ACCESS_ALLOWED
        ace.flags = 0
        ace.access_mask = security.SEC_ADS_GENERIC_ALL
        ace.trustee = princ_sid

        aces.append(ace)

        dacl.aces = aces
        dacl.num_aces += 1

        security_desc.dacl = dacl

        new_data = ndr_pack(security_desc)

        # Set the new security descriptor. First, delete the original value to
        # detect a race condition if someone else updates the attribute at the
        # same time.
        msg = ldb.Message()
        msg.dn = account_res[0].dn
        if data is not None:
            msg["0"] = ldb.MessageElement(
                data, ldb.FLAG_MOD_DELETE,
                "msDS-AllowedToActOnBehalfOfOtherIdentity")
        msg["1"] = ldb.MessageElement(
            new_data, ldb.FLAG_MOD_ADD,
            "msDS-AllowedToActOnBehalfOfOtherIdentity")
        try:
            sam.modify(msg)
        except ldb.LdbError as err:
            num, _ = err.args
            if num == ldb.ERR_NO_SUCH_ATTRIBUTE:
                raise CommandError(
                    f"Refused to update attribute "
                    f"msDS-AllowedToActOnBehalfOfOtherIdentity for account "
                    f"'{accountname}': a conflicting attribute update "
                    f"occurred simultaneously.")
            else:
                raise CommandError(err)


class cmd_delegation_del_principal(Command):
    """Delete a principal from msDS-AllowedToActOnBehalfOfOtherIdentity that may no longer delegate to an account."""

    synopsis = "%prog <accountname> <principal> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
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
        cleanedaccount, _, _ = _get_user_realm_domain(accountname, sam)

        account_res = sam.search(
            expression="sAMAccountName=%s" %
            ldb.binary_encode(cleanedaccount),
            scope=ldb.SCOPE_SUBTREE,
            attrs=["msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if len(account_res) == 0:
            raise CommandError("Unable to find account name '%s'" % accountname)
        assert(len(account_res) == 1)

        data = account_res[0].get(
            "msDS-AllowedToActOnBehalfOfOtherIdentity", idx=0)
        if data is None:
            raise CommandError(f"Attribute "
                               f"msDS-AllowedToActOnBehalfOfOtherIdentity for "
                               f"account '{accountname}' not present!")

        try:
            security_desc = ndr_unpack(security.descriptor, data)
        except RuntimeError:
            raise CommandError(f"Security Descriptor of attribute "
                               f"msDS-AllowedToActOnBehalfOfOtherIdentity for "
                               f"account '{accountname}' could not be "
                               f"unmarshalled!")

        dacl = security_desc.dacl
        if dacl is None:
            raise CommandError(f"DACL not present on Security Descriptor of "
                               f"attribute "
                               f"msDS-AllowedToActOnBehalfOfOtherIdentity for "
                               f"account '{accountname}'!")

        # TODO once I understand how, use the domain info to naildown
        # to the correct domain
        cleanedprinc, _, _ = _get_user_realm_domain(principal, sam)

        princ_res = sam.search(expression="sAMAccountName=%s" %
                               ldb.binary_encode(cleanedprinc),
                               scope=ldb.SCOPE_SUBTREE,
                               attrs=["objectSid"])
        if len(princ_res) == 0:
            raise CommandError(f"Unable to find principal name '{principal}'")
        assert(len(princ_res) == 1)

        princ_sid = security.dom_sid(
            sam.schema_format_value(
                "objectSID",
                princ_res[0].get("objectSID", idx=0)).decode("utf-8"))

        old_aces = dacl.aces

        # Remove any ACEs relating to the specified principal.
        aces = [ace for ace in old_aces if ace.trustee != princ_sid]

        # Raise an error if we didn't find any.
        if len(aces) == len(old_aces):
            raise CommandError(f"Unable to find ACE for principal "
                               f"'{principal}' in Security Descriptor of "
                               f"attribute "
                               f"msDS-AllowedToActOnBehalfOfOtherIdentity for "
                               f"account '{accountname}'.")

        dacl.num_aces = len(aces)
        dacl.aces = aces

        security_desc.dacl = dacl

        new_data = ndr_pack(security_desc)

        # Set the new security descriptor. First, delete the original value to
        # detect a race condition if someone else updates the attribute at the
        # same time.
        msg = ldb.Message()
        msg.dn = account_res[0].dn
        msg["0"] = ldb.MessageElement(
            data, ldb.FLAG_MOD_DELETE,
            "msDS-AllowedToActOnBehalfOfOtherIdentity")
        msg["1"] = ldb.MessageElement(
            new_data, ldb.FLAG_MOD_ADD,
            "msDS-AllowedToActOnBehalfOfOtherIdentity")
        try:
            sam.modify(msg)
        except ldb.LdbError as err:
            num, _ = err.args
            if num == ldb.ERR_NO_SUCH_ATTRIBUTE:
                raise CommandError(
                    f"Refused to update attribute "
                    f"msDS-AllowedToActOnBehalfOfOtherIdentity for account "
                    f"'{accountname}': a conflicting attribute update "
                    f"occurred simultaneously.")
            else:
                raise CommandError(err)


class cmd_delegation(SuperCommand):
    """Delegation management."""

    subcommands = {}
    subcommands["show"] = cmd_delegation_show()
    subcommands["for-any-service"] = cmd_delegation_for_any_service()
    subcommands["for-any-protocol"] = cmd_delegation_for_any_protocol()
    subcommands["add-service"] = cmd_delegation_add_service()
    subcommands["del-service"] = cmd_delegation_del_service()
    subcommands["add-principal"] = cmd_delegation_add_principal()
    subcommands["del-principal"] = cmd_delegation_del_principal()

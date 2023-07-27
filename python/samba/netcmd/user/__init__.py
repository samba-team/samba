# user management
#
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
# Copyright Theresa Halloran 2011 <theresahalloran@gmail.com>
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
from samba.auth import system_session
from samba.samdb import SamDB
from samba import (
    dsdb,
)

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
)

from .add import cmd_user_add
from .common import (
    GetPasswordCommand,
    disabled_virtual_attributes,
    decrypt_samba_gpg_help,
    get_crypt_value,
    gpg_decrypt,
    virtual_attributes,
    virtual_attributes_help
)
from .delete import cmd_user_delete
from .disable import cmd_user_disable
from .edit import cmd_user_edit
from .enable import cmd_user_enable
from .getgroups import cmd_user_getgroups
from .getpassword import cmd_user_getpassword, cmd_user_syncpasswords
from .list import cmd_user_list
from .move import cmd_user_move
from .password import cmd_user_password
from .rename import cmd_user_rename
from .setexpiry import cmd_user_setexpiry
from .setpassword import cmd_user_setpassword
from .setprimarygroup import cmd_user_setprimarygroup
from .show import cmd_user_show
from .unlock import cmd_user_unlock


class cmd_user_add_unix_attrs(Command):
    """Add RFC2307 attributes to a user.

This command adds Unix attributes to a user account in the Active
Directory domain.

The username specified on the command is the sAMaccountName.

You must supply a unique uidNumber.

Unix (RFC2307) attributes will be added to the user account.

If you supply a gidNumber with '--gid-number', this will be used for the
users Unix 'gidNumber' attribute.

If '--gid-number' is not supplied, the users Unix gidNumber will be set to the
one found in 'Domain Users', this means Domain Users must have a gidNumber
attribute.

if '--unix-home' is not supplied, the users Unix home directory will be
set to /home/DOMAIN/username

if '--login-shell' is not supplied, the users Unix login shell will be
set to '/bin/sh'

if ---gecos' is not supplied, the users Unix gecos field will be set to the
users 'CN'

Add 'idmap_ldb:use rfc2307 = Yes' to the smb.conf on DCs, to use these
attributes for UID/GID mapping.

The command may be run from the root userid or another authorised userid.
The -H or --URL= option can be used to execute the command against a
remote server.

Example1:
samba-tool user addunixattrs User1 10001

Example1 shows how to add RFC2307 attributes to a domain enabled user
account, Domain Users will be set as the users gidNumber.

The users Unix ID will be set to '10001', provided this ID isn't already
in use.

Example2:
samba-tool user addunixattrs User2 10002 --gid-number=10001 \
--unix-home=/home/User2

Example2 shows how to add RFC2307 attributes to a domain enabled user
account.

The users Unix ID will be set to '10002', provided this ID isn't already
in use.

The users gidNumber attribute will be set to '10001'

The users Unix home directory will be set to '/home/user2'

Example3:
samba-tool user addunixattrs User3 10003 --gid-number=10001 \
--login-shell=/bin/false --gecos='User3 test'

Example3 shows how to add RFC2307 attributes to a domain enabled user
account.

The users Unix ID will be set to '10003', provided this ID isn't already
in use.

The users gidNumber attribute will be set to '10001'

The users Unix login shell will be set to '/bin/false'

The users gecos field will be set to 'User3 test'

Example4:
samba-tool user addunixattrs User4 10004 --gid-number=10001 \
--unix-home=/home/User4 --login-shell=/bin/bash --gecos='User4 test'

Example4 shows how to add RFC2307 attributes to a domain enabled user
account.

The users Unix ID will be set to '10004', provided this ID isn't already
in use.

The users gidNumber attribute will be set to '10001'

The users Unix home directory will be set to '/home/User4'

The users Unix login shell will be set to '/bin/bash'

The users gecos field will be set to 'User4 test'

"""

    synopsis = "%prog <username> <uid-number> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--gid-number", help="User's Unix/RFC2307 GID", type=str),
        Option("--unix-home", help="User's Unix/RFC2307 home directory",
               type=str),
        Option("--login-shell", help="User's Unix/RFC2307 login shell",
               type=str),
        Option("--gecos", help="User's Unix/RFC2307 GECOS field", type=str),
        Option("--uid", help="User's Unix/RFC2307 username", type=str),
    ]

    takes_args = ["username", "uid-number"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, username, uid_number, credopts=None, sambaopts=None,
            versionopts=None, H=None, gid_number=None, unix_home=None,
            login_shell=None, gecos=None, uid=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domaindn = samdb.domain_dn()

        # Check that uidNumber supplied isn't already in use
        filter = ("(&(objectClass=person)(uidNumber={}))"
                  .format(uid_number))
        res = samdb.search(domaindn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression=filter)
        if (len(res) != 0):
            raise CommandError("uidNumber {} is already being used."
                               .format(uid_number))

        # Check user exists and doesn't have a uidNumber
        filter = "(samaccountname={})".format(ldb.binary_encode(username))
        res = samdb.search(domaindn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression=filter)
        if (len(res) == 0):
            raise CommandError("Unable to find user '{}'".format(username))

        user_dn = res[0].dn

        if "uidNumber" in res[0]:
            raise CommandError("User {} is already a Unix user."
                               .format(username))

        if gecos is None:
            gecos = res[0]["cn"][0]

        if uid is None:
            uid = res[0]["cn"][0]

        if gid_number is None:
            search_filter = ("(samaccountname={})"
                              .format(ldb.binary_encode('Domain Users')))
            try:
                res = samdb.search(domaindn,
                                   scope=ldb.SCOPE_SUBTREE,
                                   expression=search_filter)
                for msg in res:
                    gid_number=msg.get('gidNumber')
            except IndexError:
                raise CommandError('Domain Users does not have a'
                                   ' gidNumber attribute')

        if login_shell is None:
            login_shell = "/bin/sh"

        if unix_home is None:
            # obtain nETBIOS Domain Name
            unix_domain = samdb.domain_netbios_name()
            if unix_domain is None:
                raise CommandError('Unable to find Unix domain')

            tmpl = lp.get('template homedir')
            unix_home = tmpl.replace('%D', unix_domain).replace('%U', username)

        if not lp.get("idmap_ldb:use rfc2307"):
            self.outf.write("You are setting a Unix/RFC2307 UID & GID. "
                            "You may want to set 'idmap_ldb:use rfc2307 = Yes'"
                            " in smb.conf to use the attributes for "
                            "XID/SID-mapping.\n")

        user_mod = """
dn: {0}
changetype: modify
add: uidNumber
uidNumber: {1}
add: gidnumber
gidNumber: {2}
add: gecos
gecos: {3}
add: uid
uid: {4}
add: loginshell
loginShell: {5}
add: unixHomeDirectory
unixHomeDirectory: {6}
""".format(user_dn, uid_number, gid_number, gecos, uid, login_shell, unix_home)

        samdb.transaction_start()
        try:
            samdb.modify_ldif(user_mod)
        except ldb.LdbError as e:
            raise CommandError("Failed to modify user '{0}': {1}"
                               .format(username, e))
        else:
            samdb.transaction_commit()
            self.outf.write("Modified User '{}' successfully\n"
                            .format(username))


class cmd_user_sensitive(Command):
    """Set/unset or show UF_NOT_DELEGATED for an account."""

    synopsis = "%prog <accountname> [(show|on|off)] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["accountname", "cmd"]

    def run(self, accountname, cmd, H=None, credopts=None, sambaopts=None,
            versionopts=None):

        if cmd not in ("show", "on", "off"):
            raise CommandError("invalid argument: '%s' (choose from 'show', 'on', 'off')" % cmd)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        sam = SamDB(url=H, session_info=system_session(),
                    credentials=creds, lp=lp)

        search_filter = "sAMAccountName=%s" % ldb.binary_encode(accountname)
        flag = dsdb.UF_NOT_DELEGATED;

        if cmd == "show":
            res = sam.search(scope=ldb.SCOPE_SUBTREE, expression=search_filter,
                             attrs=["userAccountControl"])
            if len(res) == 0:
                raise Exception("Unable to find account where '%s'" % search_filter)

            uac = int(res[0].get("userAccountControl")[0])

            self.outf.write("Account-DN: %s\n" % str(res[0].dn))
            self.outf.write("UF_NOT_DELEGATED: %s\n" % bool(uac & flag))

            return

        if cmd == "on":
            on = True
        elif cmd == "off":
            on = False

        try:
            sam.toggle_userAccountFlags(search_filter, flag, flags_str="Not-Delegated",
                                        on=on, strict=True)
        except Exception as err:
            raise CommandError(err)


class cmd_user(SuperCommand):
    """User management."""

    subcommands = {}
    subcommands["add"] = cmd_user_add()
    subcommands["create"] = cmd_user_add()
    subcommands["delete"] = cmd_user_delete()
    subcommands["disable"] = cmd_user_disable()
    subcommands["enable"] = cmd_user_enable()
    subcommands["list"] = cmd_user_list()
    subcommands["setexpiry"] = cmd_user_setexpiry()
    subcommands["password"] = cmd_user_password()
    subcommands["getgroups"] = cmd_user_getgroups()
    subcommands["setprimarygroup"] = cmd_user_setprimarygroup()
    subcommands["setpassword"] = cmd_user_setpassword()
    subcommands["getpassword"] = cmd_user_getpassword()
    subcommands["syncpasswords"] = cmd_user_syncpasswords()
    subcommands["edit"] = cmd_user_edit()
    subcommands["show"] = cmd_user_show()
    subcommands["move"] = cmd_user_move()
    subcommands["rename"] = cmd_user_rename()
    subcommands["unlock"] = cmd_user_unlock()
    subcommands["addunixattrs"] = cmd_user_add_unix_attrs()
    subcommands["sensitive"] = cmd_user_sensitive()

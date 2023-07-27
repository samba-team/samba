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
from .add_unix_attrs import cmd_user_add_unix_attrs
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

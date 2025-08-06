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

from samba.netcmd import SuperCommand

from .add import cmd_user_add
from .add_unix_attrs import cmd_user_add_unix_attrs
from .auth import cmd_user_auth
from .delete import cmd_user_delete
from .disable import cmd_user_disable
from .edit import cmd_user_edit
from .enable import cmd_user_enable
from .getgroups import cmd_user_getgroups
from .keytrust import cmd_user_keytrust
from .list import cmd_user_list
from .move import cmd_user_move
from .password import cmd_user_password
from .readpasswords import (cmd_user_getpassword,
                            cmd_user_show,
                            cmd_user_syncpasswords,
                            cmd_user_get_kerberos_ticket)
from .rename import cmd_user_rename
from .sensitive import cmd_user_sensitive
from .setexpiry import cmd_user_setexpiry
from .setpassword import cmd_user_setpassword
from .setprimarygroup import cmd_user_setprimarygroup
from .unlock import cmd_user_unlock


class cmd_user(SuperCommand):
    """User management."""

    subcommands = {}
    subcommands["auth"] = cmd_user_auth()
    subcommands["add"] = cmd_user_add()
    subcommands["create"] = cmd_user_add()
    subcommands["delete"] = cmd_user_delete()
    subcommands["disable"] = cmd_user_disable()
    subcommands["enable"] = cmd_user_enable()
    subcommands["keytrust"] = cmd_user_keytrust()
    subcommands["list"] = cmd_user_list()
    subcommands["setexpiry"] = cmd_user_setexpiry()
    subcommands["password"] = cmd_user_password()
    subcommands["getgroups"] = cmd_user_getgroups()
    subcommands["setprimarygroup"] = cmd_user_setprimarygroup()
    subcommands["setpassword"] = cmd_user_setpassword()
    subcommands["getpassword"] = cmd_user_getpassword()
    subcommands["get-kerberos-ticket"] = cmd_user_get_kerberos_ticket()
    subcommands["syncpasswords"] = cmd_user_syncpasswords()
    subcommands["edit"] = cmd_user_edit()
    subcommands["show"] = cmd_user_show()
    subcommands["move"] = cmd_user_move()
    subcommands["rename"] = cmd_user_rename()
    subcommands["unlock"] = cmd_user_unlock()
    subcommands["addunixattrs"] = cmd_user_add_unix_attrs()
    subcommands["sensitive"] = cmd_user_sensitive()

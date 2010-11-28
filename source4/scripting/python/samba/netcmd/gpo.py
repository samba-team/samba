#!/usr/bin/env python
#
# implement samba_tool gpo commands
#
# Copyright Andrew Tridgell 2010
#
# based on C implementation by Guenther Deschner and Wilco Baan Hofman
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
from samba.netcmd import (
    Command,
    CommandError,
    Option,
    SuperCommand,
    )
from samba.samdb import SamDB
from samba import drs_utils, nttime2string, dsdb
from samba.dcerpc import misc


def samdb_connect(ctx):
    '''make a ldap connection to the server'''
    try:
        ctx.samdb = SamDB(url=ctx.url,
                          session_info=system_session(),
                          credentials=ctx.creds, lp=ctx.lp)
    except Exception, estr:
        raise CommandError("LDAP connection to %s failed - %s" % (ctx.url, estr))


def attr_default(msg, attrname, default):
    '''get an attribute from a ldap msg with a default'''
    if attrname in msg:
        return msg[attrname][0]
    return default


def flags_string(flags, value):
    '''return a set of flags as a string'''
    if value == 0:
        return 'NONE'
    ret = ''
    for (str, val) in flags:
        if val & value:
            ret += str + ' '
            value &= ~val
    if value != 0:
        ret += '0x%08x' % value
    return ret.rstrip()


class cmd_listall(Command):
    """list all GPOs"""

    synopsis = "%prog gpo listall"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str)
        ]

    def run(self, H=None, sambaopts=None,
            credopts=None, versionopts=None, server=None):

        self.url = H
        self.lp = sambaopts.get_loadparm()

        self.creds = credopts.get_credentials(self.lp)
        if not self.creds.authentication_requested():
            self.creds.set_machine_account(self.lp)

        samdb_connect(self)

        policies_dn = self.samdb.get_default_basedn()
        policies_dn.add_child(ldb.Dn(self.samdb, "CN=Policies,CN=System"))

        gpo_flags = [
            ("GPO_FLAG_USER_DISABLE", dsdb.GPO_FLAG_USER_DISABLE ),
            ( "GPO_FLAG_MACHINE_DISABLE", dsdb.GPO_FLAG_MACHINE_DISABLE ) ]

        msg = self.samdb.search(base=policies_dn, scope=ldb.SCOPE_ONELEVEL,
                                expression="(objectClass=groupPolicyContainer)",
                                attrs=['nTSecurityDescriptor', 'versionNumber', 'flags', 'name', 'displayName', 'gPCFileSysPath'])
        for m in msg:
            print("GPO          : %s" % m['name'][0])
            print("display name : %s" % m['displayName'][0])
            print("path         : %s" % m['gPCFileSysPath'][0])
            print("dn           : %s" % m.dn)
            print("version      : %s" % attr_default(m, 'version', '0'))
            print("flags        : %s" % flags_string(gpo_flags, int(attr_default(m, 'flags', 0))))
            print("")


class cmd_gpo(SuperCommand):
    """GPO commands"""

    subcommands = {}
    subcommands["listall"] = cmd_listall()

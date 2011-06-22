#!/usr/bin/env python
#
# Samba4 AD database checker
#
# Copyright (C) Andrew Tridgell 2011
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

import ldb, sys
import samba.getopt as options
from samba.auth import system_session
from samba.samdb import SamDB
from samba.netcmd import (
    Command,
    CommandError,
    Option
    )
from samba.dbchecker import dbcheck


class cmd_dbcheck(Command):
    """check local AD database for errors"""
    synopsis = "dbcheck <DN> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptionsDouble,
    }

    takes_args = ["DN?"]

    takes_options = [
        Option("--scope", dest="scope", default="SUB",
            help="Pass search scope that builds DN list. Options: SUB, ONE, BASE"),
        Option("--fix", dest="fix", default=False, action='store_true',
               help='Fix any errors found'),
        Option("--yes", dest="yes", default=False, action='store_true',
               help="don't confirm changes, just do them all as a single transaction"),
        Option("--cross-ncs", dest="cross_ncs", default=False, action='store_true',
               help="cross naming context boundaries"),
        Option("-v", "--verbose", dest="verbose", action="store_true", default=False,
            help="Print more details of checking"),
        Option("--quiet", dest="quiet", action="store_true", default=False,
            help="don't print details of checking"),
        Option("-H", help="LDB URL for database or target server (defaults to local SAM database)", type=str),
        ]

    def run(self, H=None, DN=None, verbose=False, fix=False, yes=False, cross_ncs=False, quiet=False,
            scope="SUB", credopts=None, sambaopts=None, versionopts=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(session_info=system_session(), url=H,
                      credentials=creds, lp=lp)
        if H is None:
            samdb_schema = samdb
        else:
            samdb_schema = SamDB(session_info=system_session(), url=None,
                                 credentials=creds, lp=lp)

        scope_map = { "SUB": ldb.SCOPE_SUBTREE, "BASE":ldb.SCOPE_BASE, "ONE":ldb.SCOPE_ONELEVEL }
        scope = scope.upper()
        if not scope in scope_map:
            raise CommandError("Unknown scope %s" % scope)
        search_scope = scope_map[scope]

        controls = []
        if H is not None:
            controls.append('paged_results:1:1000')
        if cross_ncs:
            controls.append("search_options:1:2")

        if yes and fix:
            samdb.transaction_start()

        chk = dbcheck(samdb, samdb_schema=samdb_schema, verbose=verbose, fix=fix, yes=yes, quiet=quiet)
        error_count = chk.check_database(DN=DN, scope=search_scope, controls=controls)

        if yes and fix:
            samdb.transaction_commit()

        if error_count != 0:
            sys.exit(1)


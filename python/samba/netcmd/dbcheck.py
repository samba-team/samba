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
    """Check local AD database for errors."""
    synopsis = "%prog [<DN>] [options]"

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
        Option("--attrs", dest="attrs", default=None, help="list of attributes to check (space separated)"),
        Option("--reindex", dest="reindex", default=False, action="store_true", help="force database re-index"),
        Option("--force-modules", dest="force_modules", default=False, action="store_true", help="force loading of Samba modules and ignore the @MODULES record (for very old databases)"),
        Option("--reset-well-known-acls", dest="reset_well_known_acls", default=False, action="store_true", help="reset ACLs on objects with well known default ACL values to the default"),
        Option("-H", "--URL", help="LDB URL for database or target server (defaults to local SAM database)",
               type=str, metavar="URL", dest="H"),
        ]

    def run(self, DN=None, H=None, verbose=False, fix=False, yes=False,
            cross_ncs=False, quiet=False,
            scope="SUB", credopts=None, sambaopts=None, versionopts=None,
            attrs=None, reindex=False, force_modules=False,
            reset_well_known_acls=False):

        lp = sambaopts.get_loadparm()

        over_ldap = H is not None and H.startswith('ldap')

        if over_ldap:
            creds = credopts.get_credentials(lp, fallback_machine=True)
        else:
            creds = None

        if force_modules:
            samdb = SamDB(session_info=system_session(), url=H,
                          credentials=creds, lp=lp, options=["modules=samba_dsdb"])
        else:
            try:
                samdb = SamDB(session_info=system_session(), url=H,
                              credentials=creds, lp=lp)
            except:
                raise CommandError("Failed to connect to DB at %s.  If this is a really old sam.ldb (before alpha9), then try again with --force-modules" % H)


        if H is None or not over_ldap:
            samdb_schema = samdb
        else:
            samdb_schema = SamDB(session_info=system_session(), url=None,
                                 credentials=creds, lp=lp)

        scope_map = { "SUB": ldb.SCOPE_SUBTREE, "BASE": ldb.SCOPE_BASE, "ONE":ldb.SCOPE_ONELEVEL }
        scope = scope.upper()
        if not scope in scope_map:
            raise CommandError("Unknown scope %s" % scope)
        search_scope = scope_map[scope]

        controls = ['show_deleted:1']
        if over_ldap:
            controls.append('paged_results:1:1000')
        if cross_ncs:
            controls.append("search_options:1:2")

        if not attrs:
            attrs = ['*']
        else:
            attrs = attrs.split()

        started_transaction = False
        if yes and fix:
            samdb.transaction_start()
            started_transaction = True
        try:
            chk = dbcheck(samdb, samdb_schema=samdb_schema, verbose=verbose,
                          fix=fix, yes=yes, quiet=quiet, in_transaction=started_transaction,
                          reset_well_known_acls=reset_well_known_acls)

            if reindex:
                self.outf.write("Re-indexing...\n")
                error_count = 0
                if chk.reindex_database():
                    self.outf.write("completed re-index OK\n")

            elif force_modules:
                self.outf.write("Resetting @MODULES...\n")
                error_count = 0
                if chk.reset_modules():
                    self.outf.write("completed @MODULES reset OK\n")

            else:
                error_count = chk.check_database(DN=DN, scope=search_scope,
                        controls=controls, attrs=attrs)
        except:
            if started_transaction:
                samdb.transaction_cancel()
            raise

        if started_transaction:
            samdb.transaction_commit()

        if error_count != 0:
            sys.exit(1)

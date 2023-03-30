# domain management - domain functional_prep
#
# Copyright Matthias Dieter Wallnoefer 2009
# Copyright Andrew Kroeger 2009
# Copyright Jelmer Vernooij 2007-2012
# Copyright Giampaolo Lauria 2011
# Copyright Matthieu Patou <mat@matws.net> 2011
# Copyright Andrew Bartlett 2008-2015
# Copyright Stefan Metzmacher 2012
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

import ldb
import samba.getopt as options
from samba.auth import system_session
from samba.dsdb import DS_DOMAIN_FUNCTION_2008, DS_DOMAIN_FUNCTION_2008_R2
from samba.netcmd import Command, CommandError, Option
from samba.netcmd.fsmo import get_fsmo_roleowner
from samba.samdb import SamDB

from .common import string_to_level


class cmd_domain_functional_prep(Command):
    """Domain functional level preparation"""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--function-level", type="choice", metavar="FUNCTION_LEVEL",
               choices=["2008_R2", "2012", "2012_R2", "2016"],
               help="The functional level to prepare for. Default is (Windows) 2016.",
               default="2016"),
        Option("--forest-prep", action="store_true",
               help="Run the forest prep (by default, both the domain and forest prep are run)."),
        Option("--domain-prep", action="store_true",
               help="Run the domain prep (by default, both the domain and forest prep are run).")
    ]

    def run(self, **kwargs):
        updates_allowed_overridden = False
        sambaopts = kwargs.get("sambaopts")
        credopts = kwargs.get("credopts")
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        H = kwargs.get("H")
        target_level = string_to_level(kwargs.get("function_level"))
        forest_prep = kwargs.get("forest_prep")
        domain_prep = kwargs.get("domain_prep")

        samdb = SamDB(url=H, session_info=system_session(), credentials=creds, lp=lp)

        # we're not going to get far if the config doesn't allow schema updates
        if lp.get("dsdb:schema update allowed") is None:
            lp.set("dsdb:schema update allowed", "yes")
            print("Temporarily overriding 'dsdb:schema update allowed' setting")
            updates_allowed_overridden = True

        if forest_prep is None and domain_prep is None:
            forest_prep = True
            domain_prep = True

        own_dn = ldb.Dn(samdb, samdb.get_dsServiceName())
        if forest_prep:
            master = get_fsmo_roleowner(samdb, str(samdb.get_schema_basedn()),
                                        'schema')
            if own_dn != master:
                raise CommandError("This server is not the schema master.")

        if domain_prep:
            domain_dn = samdb.domain_dn()
            infrastructure_dn = "CN=Infrastructure," + domain_dn
            master = get_fsmo_roleowner(samdb, infrastructure_dn,
                                        'infrastructure')
            if own_dn != master:
                raise CommandError("This server is not the infrastructure master.")

        exception_encountered = None

        if forest_prep and exception_encountered is None:
            samdb.transaction_start()
            try:
                from samba.forest_update import ForestUpdate
                forest = ForestUpdate(samdb, fix=True)

                forest.check_updates_iterator([11, 54, 79, 80, 81, 82, 83])
                forest.check_updates_functional_level(target_level,
                                                      DS_DOMAIN_FUNCTION_2008_R2,
                                                      update_revision=True)

                samdb.transaction_commit()
            except Exception as e:
                print("Exception: %s" % e)
                samdb.transaction_cancel()
                exception_encountered = e

        if domain_prep and exception_encountered is None:
            samdb.transaction_start()
            try:
                from samba.domain_update import DomainUpdate

                domain = DomainUpdate(samdb, fix=True)
                domain.check_updates_functional_level(target_level,
                                                      DS_DOMAIN_FUNCTION_2008,
                                                      update_revision=True)

                samdb.transaction_commit()
            except Exception as e:
                print("Exception: %s" % e)
                samdb.transaction_cancel()
                exception_encountered = e

        if updates_allowed_overridden:
            lp.set("dsdb:schema update allowed", "no")

        if exception_encountered is not None:
            raise CommandError('Failed to perform functional prep: %r' %
                               exception_encountered)

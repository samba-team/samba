# domain management
#
# Copyright William Brown <william@blackhats.net.au> 2018
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
from samba.samdb import SamDB
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option
)


class cmd_forest_show(Command):
    """Display forest settings.

    These settings control the behaviour of all domain controllers in this
    forest. This displays those settings from the replicated configuration
    partition.
    """

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    def run(self, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        object_dn = "%s,%s" % (self.objectdn, domain_dn)

        # Show all the settings we know how to set in the forest object!
        res = samdb.search(base=object_dn, scope=ldb.SCOPE_BASE,
                           attrs=self.attributes)

        # Now we just display these attributes. The value is that
        # we make them a bit prettier and human accessible.
        # There should only be one response!
        res_object = res[0]

        self.outf.write("Settings for %s\n" % object_dn)
        for attr in self.attributes:
            try:
                self.outf.write("%s: %s\n" % (attr, res_object[attr][0]))
            except KeyError:
                self.outf.write("%s: <NO VALUE>\n" % attr)


class cmd_forest_set(Command):
    """Modify forest settings.

    This will alter the setting specified to value.
    """

    attribute = None
    objectdn = None

    synopsis = "%prog value [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["value"]

    def run(self, value, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        object_dn = "%s,%s" % (self.objectdn, domain_dn)

        # Create the modification
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, object_dn)
        m[self.attribute] = ldb.MessageElement(
            value, ldb.FLAG_MOD_REPLACE, self.attribute)

        samdb.modify(m)
        self.outf.write("set %s: %s\n" % (self.attribute, value))


# Then you override it for each setting name:

class cmd_forest_show_directory_service(cmd_forest_show):
    """Display Directory Service settings for the forest.

    These settings control how the Directory Service behaves on all domain
    controllers in the forest.
    """
    objectdn = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
    attributes = ['dsheuristics']


class cmd_forest_set_directory_service_dsheuristics(cmd_forest_set):
    """Set the value of dsheuristics on the Directory Service.

    This value alters the behaviour of the Directory Service on all domain
    controllers in the forest. Documentation related to this parameter can be
    found here: https://msdn.microsoft.com/en-us/library/cc223560.aspx

    In summary each "character" of the number-string, controls a setting.
    A common setting is to set the value "2" in the 7th character. This controls
    anonymous search behaviour.

    Example: dsheuristics 0000002

    This would allow anonymous LDAP searches to the domain (you may still need
    to alter access controls to allow this).
    """
    objectdn = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
    attribute = 'dsheuristics'


class cmd_forest_directory_service(SuperCommand):
    """Forest configuration partition management."""

    subcommands = {}
    subcommands["show"] = cmd_forest_show_directory_service()
    subcommands["dsheuristics"] = cmd_forest_set_directory_service_dsheuristics()


class cmd_forest(SuperCommand):
    """Forest management."""

    subcommands = {}
    subcommands["directory_service"] = cmd_forest_directory_service()

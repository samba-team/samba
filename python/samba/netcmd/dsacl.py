# Manipulate ACLs on directory objects
#
# Copyright (C) Nadezhda Ivanova <nivanova@samba.org> 2010
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
from samba import sd_utils
from samba.dcerpc import security
from samba.samdb import SamDB
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc.security import (
    GUID_DRS_ALLOCATE_RIDS, GUID_DRS_CHANGE_DOMAIN_MASTER,
    GUID_DRS_CHANGE_INFR_MASTER, GUID_DRS_CHANGE_PDC,
    GUID_DRS_CHANGE_RID_MASTER, GUID_DRS_CHANGE_SCHEMA_MASTER,
    GUID_DRS_GET_CHANGES, GUID_DRS_GET_ALL_CHANGES,
    GUID_DRS_GET_FILTERED_ATTRIBUTES, GUID_DRS_MANAGE_TOPOLOGY,
    GUID_DRS_MONITOR_TOPOLOGY, GUID_DRS_REPL_SYNCRONIZE,
    GUID_DRS_RO_REPL_SECRET_SYNC)


import ldb
from ldb import SCOPE_BASE
import re

from samba.auth import system_session
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
)

class cmd_dsacl_base(Command):
    """Base class for DSACL commands."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def print_acl(self, sd_helper, object_dn, prefix=''):
        desc_sddl = sd_helper.get_sd_as_sddl(object_dn)
        self.outf.write("%sdescriptor for %s:\n" % (prefix, object_dn))
        self.outf.write(desc_sddl + "\n")


class cmd_dsacl_set(cmd_dsacl_base):
    """Modify access list on a directory object."""

    car_help = """ The access control right to allow or deny """

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--car", type="choice", choices=["change-rid",
                                                "change-pdc",
                                                "change-infrastructure",
                                                "change-schema",
                                                "change-naming",
                                                "allocate_rids",
                                                "get-changes",
                                                "get-changes-all",
                                                "get-changes-filtered",
                                                "topology-manage",
                                                "topology-monitor",
                                                "repl-sync",
                                                "ro-repl-secret-sync"],
               help=car_help),
        Option("--action", type="choice", choices=["allow", "deny"],
               help="""Deny or allow access"""),
        Option("--objectdn", help="DN of the object whose SD to modify",
               type="string"),
        Option("--trusteedn", help="DN of the entity that gets access",
               type="string"),
        Option("--sddl", help="An ACE or group of ACEs to be added on the object",
               type="string"),
    ]

    def find_trustee_sid(self, samdb, trusteedn):
        res = samdb.search(base=trusteedn, expression="(objectClass=*)",
                           scope=SCOPE_BASE)
        assert(len(res) == 1)
        return ndr_unpack(security.dom_sid, res[0]["objectSid"][0])

    def add_ace(self, sd_helper, object_dn, new_ace):
        """Add new ace explicitly."""
        ai,ii = sd_helper.dacl_prepend_aces(object_dn, new_ace)
        for ace in ii:
            sddl = ace.as_sddl(sd_helper.domain_sid)
            self.outf.write("WARNING: ignored INHERITED_ACE (%s).\n" % sddl)
        for ace in ai:
            sddl = ace.as_sddl(sd_helper.domain_sid)
            self.outf.write("WARNING: (%s) was already found in the current security descriptor.\n" % sddl)

    def run(self, car, action, objectdn, trusteedn, sddl,
            H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        if sddl is None and (car is None or action is None
                             or objectdn is None or trusteedn is None):
            return self.usage()

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        sd_helper = sd_utils.SDUtils(samdb)
        cars = {'change-rid': GUID_DRS_CHANGE_RID_MASTER,
                'change-pdc': GUID_DRS_CHANGE_PDC,
                'change-infrastructure': GUID_DRS_CHANGE_INFR_MASTER,
                'change-schema': GUID_DRS_CHANGE_SCHEMA_MASTER,
                'change-naming': GUID_DRS_CHANGE_DOMAIN_MASTER,
                'allocate_rids': GUID_DRS_ALLOCATE_RIDS,
                'get-changes': GUID_DRS_GET_CHANGES,
                'get-changes-all': GUID_DRS_GET_ALL_CHANGES,
                'get-changes-filtered': GUID_DRS_GET_FILTERED_ATTRIBUTES,
                'topology-manage': GUID_DRS_MANAGE_TOPOLOGY,
                'topology-monitor': GUID_DRS_MONITOR_TOPOLOGY,
                'repl-sync': GUID_DRS_REPL_SYNCRONIZE,
                'ro-repl-secret-sync': GUID_DRS_RO_REPL_SECRET_SYNC,
                }
        sid = self.find_trustee_sid(samdb, trusteedn)
        if sddl:
            new_ace = sddl
        elif action == "allow":
            new_ace = "(OA;;CR;%s;;%s)" % (cars[car], str(sid))
        elif action == "deny":
            new_ace = "(OD;;CR;%s;;%s)" % (cars[car], str(sid))
        else:
            raise CommandError("Wrong argument '%s'!" % action)

        self.print_acl(sd_helper, objectdn, prefix='old ')
        self.add_ace(sd_helper, objectdn, new_ace)
        self.print_acl(sd_helper, objectdn, prefix='new ')


class cmd_dsacl_get(cmd_dsacl_base):
    """Print access list on a directory object."""

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--objectdn", help="DN of the object whose SD to modify",
            type="string"),
        ]

    def run(self, objectdn,
            H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)
        sd_helper = sd_utils.SDUtils(samdb)
        self.print_acl(sd_helper, objectdn)


class cmd_dsacl_delete(cmd_dsacl_base):
    """Delete an access list entry on a directory object."""

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--objectdn", help="DN of the object whose SD to modify",
            type="string"),
        Option("--sddl", help="An ACE or group of ACEs to be deleted from the object",
               type="string"),
        ]

    def run(self, objectdn, sddl, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        if sddl is None or objectdn is None:
            return self.usage()

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        sd_helper = sd_utils.SDUtils(samdb)

        self.print_acl(sd_helper, objectdn, prefix='old ')
        self.delete_ace(sd_helper, objectdn, sddl)
        self.print_acl(sd_helper, objectdn, prefix='new ')

    def delete_ace(self, sd_helper, object_dn, delete_aces):
        """Delete ace explicitly."""
        di,ii = sd_helper.dacl_delete_aces(object_dn, delete_aces)
        for ace in ii:
            sddl = ace.as_sddl(sd_helper.domain_sid)
            self.outf.write("WARNING: ignored INHERITED_ACE (%s).\n" % sddl)
        for ace in di:
            sddl = ace.as_sddl(sd_helper.domain_sid)
            self.outf.write("WARNING: (%s) was not found in the current security descriptor.\n" % sddl)


class cmd_dsacl(SuperCommand):
    """DS ACLs manipulation."""

    subcommands = {}
    subcommands["set"] = cmd_dsacl_set()
    subcommands["get"] = cmd_dsacl_get()
    subcommands["delete"] = cmd_dsacl_delete()

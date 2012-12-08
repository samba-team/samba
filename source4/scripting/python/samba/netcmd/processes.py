#   Unix SMB/CIFS implementation.
#   List processes (to aid debugging on systems without setproctitle)
#   Copyright (C) 2010-2011 Jelmer Vernooij <jelmer@samba.org>
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
# Testbed for loadparm.c/params.c
#
# This module simply loads a specified configuration file and
# if successful, dumps it's contents to stdout. Note that the
# operation is performed with DEBUGLEVEL at 3.
#
# Useful for a quick 'syntax check' of a configuration file.
#

import os
import sys

import samba
import samba.getopt as options
from samba.netcmd import Command, CommandError, Option
from samba.messaging import Messaging

class cmd_processes(Command):
    """List processes (to aid debugging on systems without setproctitle)."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions
    }

    takes_options = [
        Option("--name", type=str,
               help="Return only processes associated with one particular name"),
        Option("--pid", type=int,
               help="Return only names assoicated with one particular PID"),
        ]

    takes_args = []

    def run(self, sambaopts, versionopts, section_name=None,
            name=None, pid=None):

        lp = sambaopts.get_loadparm()
        logger = self.get_logger("processes")

        msg_ctx = Messaging()

        if name is not None:
            ids = msg_ctx.irpc_servers_byname(name)
            for server_id in ids:
                self.outf.write("%d\n" % server_id.pid)
        elif pid is not None:
            names = msg_ctx.irpc_all_servers()
            for name in names:
                for server_id in name.ids:
                    if server_id.pid == int(pid):
                        self.outf.write("%s\n" % name.name)
        else:
            names = msg_ctx.irpc_all_servers()
            self.outf.write(" Service:                PID \n")
            self.outf.write("-----------------------------\n")
            for name in names:
                for server_id in name.ids:
                    self.outf.write("%-16s      %6d\n" % (name.name, server_id.pid))

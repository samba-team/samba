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
               help="Return only names associated with one particular PID"),
    ]

    takes_args = []

    #
    # Get details of the samba services currently registered in irpc
    # The prefork process model registers names in the form:
    #     prefork-master-<service> and prefork-worker-<service>-<instance>
    #
    # To allow this routine to identify pre-fork master and worker process
    #
    # returns a tuple (filtered, masters, workers)
    #
    #  filtered - is a list of services with the prefork-* removed
    #  masters  - dictionary keyed on service name of prefork master processes
    #  workers  - dictionary keyed on service name containing an ordered list
    #             of worker processes.
    def get_service_data(self, msg_ctx):
        services = msg_ctx.irpc_all_servers()
        filtered = []
        masters = {}
        workers = {}
        for service in services:
            for id in service.ids:
                if service.name.startswith("prefork-master"):
                    ns = service.name.split("-")
                    name = ns[2] + "_server"
                    masters[name] = service.ids[0].pid
                elif service.name.startswith("prefork-worker"):
                    ns = service.name.split("-")
                    name = ns[2] + "_server"
                    instance = int(ns[3])
                    pid = service.ids[0].pid
                    if name not in workers:
                        workers[name] = {}
                    workers[name][instance] = (instance, pid)
                else:
                    filtered.append(service)
        return (filtered, masters, workers)

    def run(self, sambaopts, versionopts, section_name=None,
            name=None, pid=None):

        lp = sambaopts.get_loadparm()
        logger = self.get_logger("processes")

        msg_ctx = Messaging()

        if name is not None:
            try:
                ids = msg_ctx.irpc_servers_byname(name)
            except KeyError:
                ids = []

            for server_id in ids:
                self.outf.write("%d\n" % server_id.pid)
        elif pid is not None:
            names = msg_ctx.irpc_all_servers()
            for name in names:
                for server_id in name.ids:
                    if server_id.pid == int(pid):
                        self.outf.write("%s\n" % name.name)
        else:
            seen = {}     # Service entries already printed, service names can
            #               be registered multiple times against a process
            #               but we should only display them once.
            prefork = {}  # Services running in the prefork process model
            #               want to ensure that the master process and workers
            #               are grouped to together.
            (services, masters, workers) = self.get_service_data(msg_ctx)
            self.outf.write(" Service:                          PID\n")
            self.outf.write("--------------------------------------\n")

            for service in sorted(services, key=lambda x: x.name):
                if service.name in masters:
                    # If this service is running in a pre-forked process we
                    # want to print the master process followed by all the
                    # worker processes
                    pid = masters[service.name]
                    if pid not in prefork:
                        prefork[pid] = True
                        self.outf.write("%-26s      %6d\n" %
                            (service.name, pid))
                        if service.name in workers:
                            ws = workers[service.name]
                            for w in ws:
                                (instance, pid) = ws[w]
                                sn = "{0}(worker {1})".format(
                                    service.name, instance)
                                self.outf.write("%-26s      %6d\n" % (sn, pid))
                else:
                    for server_id in service.ids:
                        if (service.name, server_id.pid) not in seen:
                            self.outf.write("%-26s      %6d\n"
                                % (service.name, server_id.pid))
                            seen[(service.name, server_id.pid)] = True

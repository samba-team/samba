#   Unix SMB/CIFS implementation.
#   Test validity of smb.conf
#   Copyright (C) 2010-2011 Jelmer Vernooij <jelmer@samba.org>
#
# Based on the original in C:
#   Copyright (C) Karl Auer 1993, 1994-1998
#   Extensively modified by Andrew Tridgell, 1995
#   Converted to popt by Jelmer Vernooij (jelmer@nl.linux.org), 2002
#   Updated for Samba4 by Andrew Bartlett <abartlet@samba.org> 2006
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

class cmd_testparm(Command):
    """Syntax check the configuration file."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions
    }

    takes_options = [
        Option("--section-name", type=str,
               help="Limit testparm to a named section"),
        Option("--parameter-name", type=str,
               help="Limit testparm to a named parameter"),
        Option("--client-name", type=str,
               help="Client DNS name for 'hosts allow' checking "
                    "(should match reverse lookup)"),
        Option("--client-ip", type=str,
               help="Client IP address for 'hosts allow' checking"),
        Option("--suppress-prompt", action="store_true", default=False,
               help="Suppress prompt for enter"),
        Option("-v", "--verbose", action="store_true",
               default=False, help="Show default options too"),
        # We need support for smb.conf macros before this will work again
        Option("--server", type=str, help="Set %L macro to servername"),
        # These are harder to do with the new code structure
        Option("--show-all-parameters", action="store_true", default=False,
               help="Show the parameters, type, possible values")
        ]

    takes_args = []

    def run(self, sambaopts, versionopts, section_name=None,
            parameter_name=None, client_ip=None, client_name=None,
            verbose=False, suppress_prompt=None, show_all_parameters=False,
            server=None):
        if server:
            raise NotImplementedError("--server not yet implemented")
        if show_all_parameters:
            raise NotImplementedError("--show-all-parameters not yet implemented")
        if client_name is not None and client_ip is None:
            raise CommandError("Both a DNS name and an IP address are "
                               "required for the host access check")

        try:
            lp = sambaopts.get_loadparm()
        except RuntimeError, err:
            raise CommandError(err)

        # We need this to force the output
        samba.set_debug_level(2)

        logger = self.get_logger("testparm")

        logger.info("Loaded smb config files from %s", lp.configfile)
        logger.info("Loaded services file OK.")

        valid = self.do_global_checks(lp, logger)
        valid = valid and self.do_share_checks(lp, logger)
        if client_name is not None and client_ip is not None:
            self.check_client_access(lp, logger, client_name, client_ip)
        else:
            if section_name is not None or parameter_name is not None:
                if parameter_name is None:
                    lp[section_name].dump(sys.stdout, lp.default_service,
                            verbose)
                else:
                    self.outf.write(lp.get(parameter_name, section_name)+"\n")
            else:
                if not suppress_prompt:
                    self.outf.write("Press enter to see a dump of your service definitions\n")
                    sys.stdin.readline()
                lp.dump(sys.stdout, verbose)
        if valid:
            return
        else:
            raise CommandError("Invalid smb.conf")

    def do_global_checks(self, lp, logger):
        valid = True

        netbios_name = lp.get("netbios name")
        if not samba.valid_netbios_name(netbios_name):
            logger.error("netbios name %s is not a valid netbios name",
                         netbios_name)
            valid = False

        workgroup = lp.get("workgroup")
        if not samba.valid_netbios_name(workgroup):
            logger.error("workgroup name %s is not a valid netbios name",
                         workgroup)
            valid = False

        lockdir = lp.get("lockdir")

        if not os.path.isdir(lockdir):
            logger.error("lock directory %s does not exist", lockdir)
            valid = False

        piddir = lp.get("pid directory")

        if not os.path.isdir(piddir):
            logger.error("pid directory %s does not exist", piddir)
            valid = False

        winbind_separator = lp.get("winbind separator")

        if len(winbind_separator) != 1:
            logger.error("the 'winbind separator' parameter must be a single "
                         "character.")
            valid = False

        if winbind_separator == '+':
            logger.error(
                "'winbind separator = +' might cause problems with group "
                "membership.")
            valid = False

        return valid

    def allow_access(self, deny_list, allow_list, cname, caddr):
        raise NotImplementedError(self.allow_access)

    def do_share_checks(self, lp, logger):
        valid = True
        for s in lp.services():
            if len(s) > 12:
                logger.warning(
                    "You have some share names that are longer than 12 "
                    "characters. These may not be accessible to some older "
                    "clients. (Eg. Windows9x, WindowsMe, and not listed in "
                    "smbclient in Samba 3.0.)")
                break

        for s in lp.services():
            deny_list = lp.get("hosts deny", s)
            allow_list = lp.get("hosts allow", s)
            if deny_list:
                for entry in deny_list:
                    if "*" in entry or "?" in entry:
                        logger.error("Invalid character (* or ?) in hosts deny "
                                     "list (%s) for service %s.", entry, s)
                        valid = False

            if allow_list:
                for entry in allow_list:
                    if "*" in entry or "?" in entry:
                        logger.error("Invalid character (* or ?) in hosts allow "
                                     "list (%s) for service %s.", entry, s)
                        valid = False
        return valid

    def check_client_access(self, lp, logger, cname, caddr):
        # this is totally ugly, a real `quick' hack
        for s in lp.services():
            if (self.allow_access(lp.get("hosts deny"), lp.get("hosts allow"), cname,
                             caddr) and
                self.allow_access(lp.get("hosts deny", s), lp.get("hosts allow", s),
                             cname, caddr)):
                logger.info("Allow connection from %s (%s) to %s", cname, caddr, s)
            else:
                logger.info("Deny connection from %s (%s) to %s", cname, caddr, s)

##   FIXME: We need support for smb.conf macros before this will work again
##
##    if (new_local_machine) {
##        set_local_machine_name(new_local_machine, True)
##    }
#

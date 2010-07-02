#!/usr/bin/env python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2009
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

import optparse
from samba import getopt as options
import sys


class Option(optparse.Option):
    pass


class Command(object):
    """A net command."""

    def _get_description(self):
        return self.__doc__.splitlines()[0].rstrip("\n")

    def _get_name(self):
        name = self.__class__.__name__
        if name.startswith("cmd_"):
            return name[4:]
        return name

    name = property(_get_name)

    def usage(self, *args):
        parser, _ = self._create_parser()
        parser.print_usage()

    description = property(_get_description)

    def _get_synopsis(self):
        ret = self.name
        if self.takes_args:
            ret += " " + " ".join([x.upper() for x in self.takes_args])
        return ret

    synopsis = property(_get_synopsis)

    outf = sys.stdout

    takes_args = []
    takes_options = []
    takes_optiongroups = {}

    def _create_parser(self):
        parser = optparse.OptionParser(self.synopsis)
        parser.prog = "net"
        parser.add_options(self.takes_options)
        optiongroups = {}
        for name, optiongroup in self.takes_optiongroups.iteritems():
            optiongroups[name] = optiongroup(parser)
            parser.add_option_group(optiongroups[name])
        return parser, optiongroups

    def message(self, text):
        print text

    def _run(self, *argv):
        parser, optiongroups = self._create_parser()
        opts, args = parser.parse_args(list(argv))
        # Filter out options from option groups
        args = args[1:]
        kwargs = dict(opts.__dict__)
        for option_group in parser.option_groups:
            for option in option_group.option_list:
                if option.dest is not None:
                    del kwargs[option.dest]
        kwargs.update(optiongroups)
        min_args = 0
        max_args = 0
        for i, arg in enumerate(self.takes_args):
            if arg[-1] not in ("?", "*"):
                min_args += 1
            max_args += 1
            if arg[-1] == "*":
                max_args = -1
        if len(args) < min_args or (max_args != -1 and len(args) > max_args):
            self.usage(*args)
            return -1
        try:
            return self.run(*args, **kwargs)
        except CommandError, e:
            print >>sys.stderr, "ERROR: %s" % e
            return -1

    def run(self):
        """Run the command. This should be overriden by all subclasses."""
        raise NotImplementedError(self.run)


class SuperCommand(Command):
    """A command with subcommands."""

    subcommands = {}

    def _run(self, myname, subcommand=None, *args):
        if subcommand is None:
            print "Available subcommands:"
            for subcommand in self.subcommands:
                print "\t%s" % subcommand
            return 0
        if not subcommand in self.subcommands:
            raise CommandError("No such subcommand '%s'" % subcommand)
        return self.subcommands[subcommand]._run(subcommand, *args)

    def usage(self, myname, subcommand=None, *args):
        if subcommand is None or not subcommand in self.subcommands:
            print "Usage: %s (%s) [options]" % (myname,
                " | ".join(self.subcommands.keys()))
        else:
            return self.subcommands[subcommand].usage(*args)


class CommandError(Exception):
    pass


commands = {}
from samba.netcmd.pwsettings import cmd_pwsettings
commands["pwsettings"] = cmd_pwsettings()
from samba.netcmd.domainlevel import cmd_domainlevel
commands["domainlevel"] = cmd_domainlevel()
from samba.netcmd.setpassword import cmd_setpassword
commands["setpassword"] = cmd_setpassword()
from samba.netcmd.setexpiry import cmd_setexpiry
commands["setexpiry"] = cmd_setexpiry()
from samba.netcmd.enableaccount import cmd_enableaccount
commands["enableaccount"] = cmd_enableaccount()
from samba.netcmd.newuser import cmd_newuser
commands["newuser"] = cmd_newuser()
from samba.netcmd.netacl import cmd_acl
commands["acl"] = cmd_acl()
from samba.netcmd.fsmo import cmd_fsmo
commands["fsmo"] = cmd_fsmo()
from samba.netcmd.export import cmd_export
commands["export"] = cmd_export()
from samba.netcmd.time import cmd_time
commands["time"] = cmd_time()
from samba.netcmd.user import cmd_user
commands["user"] = cmd_user()
from samba.netcmd.vampire import cmd_vampire
commands["vampire"] = cmd_vampire()
from samba.netcmd.machinepw import cmd_machinepw
commands["machinepw"] = cmd_machinepw()
from samba.netcmd.spn import cmd_spn
commands["spn"] = cmd_spn()
from samba.netcmd.group import cmd_group
commands["group"] = cmd_group()

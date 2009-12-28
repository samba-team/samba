#!/usr/bin/python

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
from samba import getopt as options, Ldb


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

    def usage(self):
        self.parser.print_usage()

    description = property(_get_description)

    def _get_synopsis(self):
        ret = self.name
        if self.takes_args:
            ret += " " + " ".join(self.takes_args)
        return ret

    synopsis = property(_get_synopsis)

    takes_args = []
    takes_options = []
    takes_optiongroups = []

    def __init__(self):
        self.parser = optparse.OptionParser(self.synopsis)
        self.parser.add_options(self.takes_options)
        for optiongroup in self.takes_optiongroups:
            self.parser.add_option_group(optiongroup(self.parser))

    def message(self, text):
        print text

    def _run(self, *argv):
        opts, args = self.parser.parse_args(list(argv))
        return self.run(*args, **opts.__dict__)

    def run(self):
        """Run the command. This should be overriden by all subclasses."""
        raise NotImplementedError(self.run)


class SuperCommand(Command):
    """A command with subcommands."""

    subcommands = {}

    def run(self, subcommand, *args, **kwargs):
        if not subcommand in subcommands:
            print >>sys.stderr, "ERROR: No such subcommand '%s'" % subcommand
        try:
            return subcommands[subcommand].run(*args, **kwargs)
        except CommandError, e:
            print >>sys.stderr, "ERROR: %s" % e.message
            return -1

    def usage(self, subcommand=None, *args, **kwargs):
        if subcommand is None:
            print "Available subcommands"
            for subcommand in subcommands:
                print "\t%s" % subcommand
            return 0
        else:
            if not subcommand in subcommands:
                print >>sys.stderr, "ERROR: No such subcommand '%s'" % subcommand
            return subcommands[subcommand].usage(*args, **kwargs)


class CommandError(Exception):
    pass


commands = {}
from samba.netcmd.pwsettings import cmd_pwsettings
commands["pwsettings"] = cmd_pwsettings()

#!/usr/bin/env python

# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2009
# Copyright (C) Theresa Halloran <theresahalloran@gmail.com> 2011
# Copyright (C) Giampaolo Lauria <lauria2@yahoo.com> 2011
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

import optparse, samba
from samba import getopt as options
from ldb import LdbError
import sys, traceback


class Option(optparse.Option):
    pass



class Command(object):
    """A samba-tool command."""
   
    def _get_description(self):
        return self.__doc__.splitlines()[0].rstrip("\n")

    description = property(_get_description)

    # synopsis must be defined in all subclasses in order to provide the command usage
    synopsis = ""
    # long_description is a string describing the command in details
    long_description = ""
    takes_args = []
    takes_options = []
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }
    # This epilog will print at the end when the user invokes the command w/ -h or --help
    epilog = ""
    outf = sys.stdout

    def usage(self, *args):
        parser, _ = self._create_parser()
        parser.print_usage()

    def show_command_error(self, e):
        '''display a command error'''
        if isinstance(e, CommandError):
            (etype, evalue, etraceback) = e.exception_info
            inner_exception = e.inner_exception
            message = e.message
            force_traceback = False
        else:
            (etype, evalue, etraceback) = sys.exc_info()
            inner_exception = e
            message = "uncaught exception"
            force_traceback = True

        if isinstance(inner_exception, LdbError):
            (ldb_ecode, ldb_emsg) = inner_exception
            print >>sys.stderr, "ERROR(ldb): %s - %s" % (message, ldb_emsg)
        elif isinstance(inner_exception, AssertionError):
            print >>sys.stderr, "ERROR(assert): %s" % message
            force_traceback = True
        elif isinstance(inner_exception, RuntimeError):
            print >>sys.stderr, "ERROR(runtime): %s - %s" % (message, evalue)
        elif type(inner_exception) is Exception:
            print >>sys.stderr, "ERROR(exception): %s - %s" % (message, evalue)
            force_traceback = True
        elif inner_exception is None:
            print >>sys.stderr, "ERROR: %s" % (message)
        else:
            print >>sys.stderr, "ERROR(%s): %s - %s" % (str(etype), message, evalue)
            force_traceback = True

        if force_traceback or samba.get_debug_level() >= 3:
            traceback.print_tb(etraceback)
        sys.exit(1)

    def _create_parser(self):
        parser = optparse.OptionParser(usage=self.synopsis, epilog=self.epilog, 
                                       description=self.long_description)
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

        # Check for a min a max number of allowed arguments, whenever possible
        # The suffix "?" means zero or one occurence
        # The suffix "+" means at least one occurence
        min_args = 0
        max_args = 0
        undetermined_max_args = False
        for i, arg in enumerate(self.takes_args):
            if arg[-1] != "?":
               min_args += 1
            if arg[-1] == "+":
               undetermined_max_args = True
            else:
               max_args += 1
        if (len(args) < min_args) or (undetermined_max_args == False and len(args) > max_args):
            parser.print_usage()
            return -1

        try:
            return self.run(*args, **kwargs)
        except Exception, e:
            self.show_command_error(e)
            return -1

    def run(self):
        """Run the command. This should be overriden by all subclasses."""
        raise NotImplementedError(self.run)



class SuperCommand(Command):
    """A samba-tool command with subcommands."""

    subcommands = {}

    def _run(self, myname, subcommand=None, *args):
        if subcommand in self.subcommands:
            return self.subcommands[subcommand]._run(subcommand, *args)
        
        if (myname == "samba-tool"):
            usage = "samba-tool <subcommand>"
        else:
            usage = "samba-tool %s <subcommand>" % myname
        print "Usage: %s [options]" %usage        
        print "Available subcommands:"
        subcmds = self.subcommands.keys()
        subcmds.sort()
        max_length = len(max(subcmds, key=len))
        for cmd in subcmds:
            print "  %*s  - %s" % (-max_length, cmd, self.subcommands[cmd].description)
        print " *  server connection needed"
        if subcommand in [None]:
            raise CommandError("You must specify a subcommand")
        if subcommand in ['help', '-h', '--help']:
            print "For more help on a specific subcommand, please type: %s (-h|--help)" % usage
            return 0
        raise CommandError("No such subcommand '%s'" % subcommand)



class CommandError(Exception):
    '''an exception class for samba-tool cmd errors'''
    def __init__(self, message, inner_exception=None):
        self.message = message
        self.inner_exception = inner_exception
        self.exception_info = sys.exc_info()

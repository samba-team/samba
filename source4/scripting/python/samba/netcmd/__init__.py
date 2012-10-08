# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2009-2012
# Copyright (C) Theresa Halloran <theresahalloran@gmail.com> 2011
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
import textwrap

class Option(optparse.Option):
    pass

# This help formatter does text wrapping and preserves newlines
class PlainHelpFormatter(optparse.IndentedHelpFormatter):
    def format_description(self,description=""):
            desc_width = self.width - self.current_indent
            indent = " "*self.current_indent
            paragraphs = description.split('\n')
            wrapped_paragraphs = [
                textwrap.fill(p,
                        desc_width,
                        initial_indent=indent,
                        subsequent_indent=indent)
                for p in paragraphs]
            result = "\n".join(wrapped_paragraphs) + "\n"
            return result

    def format_epilog(self, epilog):
        if epilog:
            return "\n" + epilog + "\n"
        else:
            return ""

class Command(object):
    """A samba-tool command."""

    def _get_short_description(self):
        return self.__doc__.splitlines()[0].rstrip("\n")

    short_description = property(_get_short_description)

    def _get_full_description(self):
        lines = self.__doc__.split("\n")
        return lines[0] + "\n" + textwrap.dedent("\n".join(lines[1:]))

    full_description = property(_get_full_description)

    def _get_name(self):
        name = self.__class__.__name__
        if name.startswith("cmd_"):
            return name[4:]
        return name

    name = property(_get_name)

    # synopsis must be defined in all subclasses in order to provide the
    # command usage
    synopsis = None
    takes_args = []
    takes_options = []
    takes_optiongroups = {}

    hidden = False

    raw_argv = None
    raw_args = None
    raw_kwargs = None

    def __init__(self, outf=sys.stdout, errf=sys.stderr):
        self.outf = outf
        self.errf = errf

    def usage(self, prog, *args):
        parser, _ = self._create_parser(prog)
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
            self.errf.write("ERROR(ldb): %s - %s\n" % (message, ldb_emsg))
        elif isinstance(inner_exception, AssertionError):
            self.errf.write("ERROR(assert): %s\n" % message)
            force_traceback = True
        elif isinstance(inner_exception, RuntimeError):
            self.errf.write("ERROR(runtime): %s - %s\n" % (message, evalue))
        elif type(inner_exception) is Exception:
            self.errf.write("ERROR(exception): %s - %s\n" % (message, evalue))
            force_traceback = True
        elif inner_exception is None:
            self.errf.write("ERROR: %s\n" % (message))
        else:
            self.errf.write("ERROR(%s): %s - %s\n" % (str(etype), message, evalue))
            force_traceback = True

        if force_traceback or samba.get_debug_level() >= 3:
            traceback.print_tb(etraceback)

    def _create_parser(self, prog, epilog=None):
        parser = optparse.OptionParser(
            usage=self.synopsis,
            description=self.full_description,
            formatter=PlainHelpFormatter(),
            prog=prog,epilog=epilog)
        parser.add_options(self.takes_options)
        optiongroups = {}
        for name, optiongroup in self.takes_optiongroups.iteritems():
            optiongroups[name] = optiongroup(parser)
            parser.add_option_group(optiongroups[name])
        return parser, optiongroups

    def message(self, text):
        self.outf.write(text+"\n")

    def _run(self, *argv):
        parser, optiongroups = self._create_parser(argv[0])
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
        if (len(args) < min_args) or (not undetermined_max_args and len(args) > max_args):
            parser.print_usage()
            return -1

        self.raw_argv = list(argv)
        self.raw_args = args
        self.raw_kwargs = kwargs

        try:
            return self.run(*args, **kwargs)
        except Exception, e:
            self.show_command_error(e)
            return -1

    def run(self):
        """Run the command. This should be overriden by all subclasses."""
        raise NotImplementedError(self.run)

    def get_logger(self, name="netcmd"):
        """Get a logger object."""
        import logging
        logger = logging.getLogger(name)
        logger.addHandler(logging.StreamHandler(self.errf))
        return logger


class SuperCommand(Command):
    """A samba-tool command with subcommands."""

    synopsis = "%prog <subcommand>"

    subcommands = {}

    def _run(self, myname, subcommand=None, *args):
        if subcommand in self.subcommands:
            return self.subcommands[subcommand]._run(
                "%s %s" % (myname, subcommand), *args)

        epilog = "\nAvailable subcommands:\n"
        subcmds = self.subcommands.keys()
        subcmds.sort()
        max_length = max([len(c) for c in subcmds])
        for cmd_name in subcmds:
            cmd = self.subcommands[cmd_name]
            if not cmd.hidden:
                epilog += "  %*s  - %s\n" % (
                    -max_length, cmd_name, cmd.short_description)
        epilog += "For more help on a specific subcommand, please type: %s <subcommand> (-h|--help)\n" % myname

        parser, optiongroups = self._create_parser(myname, epilog=epilog)
        args_list = list(args)
        if subcommand:
            args_list.insert(0, subcommand)
        opts, args = parser.parse_args(args_list)

        parser.print_help()
        return -1


class CommandError(Exception):
    """An exception class for samba-tool Command errors."""

    def __init__(self, message, inner_exception=None):
        self.message = message
        self.inner_exception = inner_exception
        self.exception_info = sys.exc_info()

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

import json
import optparse
import sys
import textwrap
import traceback

import samba
from ldb import ERR_INVALID_CREDENTIALS, ERR_INSUFFICIENT_ACCESS_RIGHTS, LdbError
from samba import colour
from samba.auth import system_session
from samba.getopt import Option, OptionParser
from samba.logger import get_samba_logger
from samba.samdb import SamDB
from samba.dcerpc.security import SDDLValueError
from samba import getopt as options

from .encoders import JSONEncoder


class PlainHelpFormatter(optparse.IndentedHelpFormatter):
    """This help formatter does text wrapping and preserves newlines."""

    def format_description(self, description=""):
        desc_width = self.width - self.current_indent
        indent = " " * self.current_indent
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
    takes_args = ()
    takes_options = ()
    takes_optiongroups = {}

    hidden = False
    use_colour = True
    requested_colour = None

    raw_argv = None
    raw_args = None
    raw_kwargs = None
    preferred_output_format = None

    def _set_files(self, outf=None, errf=None):
        if outf is not None:
            self.outf = outf
        if errf is not None:
            self.errf = errf

    def __init__(self, outf=sys.stdout, errf=sys.stderr):
        self._set_files(outf, errf)

    def usage(self, prog=None):
        parser, _ = self._create_parser(prog or self.command_name)
        parser.print_usage()

    def _print_error(self, msg, evalue=None, klass=None):
        if self.preferred_output_format == 'json':
            if evalue is None:
                evalue = 1
            else:
                msg = f"{msg} - {evalue}"
            if klass is not None:
                kwargs = {'error class': klass}
            else:
                kwargs = {}

            self.print_json_status(evalue, msg, **kwargs)
            return

        err = colour.c_DARK_RED("ERROR")
        klass = '' if klass is None else f'({klass})'

        if evalue is None:
            print(f"{err}{klass}: {msg}", file=self.errf)
        else:
            print(f"{err}{klass}: {msg} - {evalue}", file=self.errf)

    def _print_sddl_value_error(self, e):
        generic_msg, specific_msg, position, sddl = e.args
        print(f"{colour.c_DARK_RED('ERROR')}: {generic_msg}\n",
              file=self.errf)
        print(f' {sddl}', file=self.errf)
        # If the SDDL contains non-ascii characters, the byte offset
        # provided by the exception won't agree with the visual offset
        # because those characters will be encoded as multiple bytes.
        #
        # To account for this we'll attempt to measure the string
        # length of the specified number of bytes. That is not quite
        # the same as the visual length, because the SDDL could
        # contain zero-width, full-width, or combining characters, but
        # it is closer.
        try:
            position = len((sddl.encode()[:position]).decode())
        except ValueError:
            # use the original position
            pass

        print(f"{colour.c_DARK_YELLOW('^'):>{position + 2}}", file=self.errf)
        print(f' {specific_msg}', file=self.errf)

    def ldb_connect(self, hostopts, sambaopts, credopts):
        """Helper to connect to Ldb database using command line opts."""
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        return SamDB(hostopts.H, credentials=creds,
                     session_info=system_session(lp), lp=lp)

    def print_json(self, data):
        """Print json on the screen using consistent formatting and sorting.

        A custom JSONEncoder class is used to help with serializing unknown
        objects such as Dn for example.
        """
        json.dump(data, self.outf, cls=JSONEncoder, indent=2, sort_keys=True)
        self.outf.write("\n")

    def print_json_status(self, error=None, message=None, **kwargs):
        """For commands that really have nothing to say when they succeed
        (`samba-tool foo delete --json`), we can still emit
        '{"status": "OK"}\n'. And if they fail they can say:
        '{"status": "error"}\n'.
        This function hopes to keep things consistent.

        If error is true-ish but not True, it is stringified and added
        as a message. For example, if error is an LdbError with an
        OBJECT_NOT_FOUND code, self.print_json_status(error) results
        in this:

            '{"status": "error", "message": "object not found"}\n'

        unless an explicit message is added, in which case that is
        used. A message can be provided on success, like this:

            '{"status": "OK", "message": "thanks for asking!"}\n'

        Extra keywords can be added too.

        In summary, you might go:

            try:
                samdb.delete(dn)
            except Exception as e:
                print_json_status(e)
                return
            print_json_status()
        """
        data = {}
        if error:
            data['status'] = 'error'
            if error is not True:
                data['message'] = str(error)
        else:
            data['status'] = 'OK'

        if message is not None:
            data['message'] = message

        data.update(kwargs)
        self.print_json(data)

    def show_command_error(self, e):
        """display a command error"""
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

        if isinstance(e, optparse.OptParseError):
            print(evalue, file=self.errf)
            self.usage()
            force_traceback = False

        elif isinstance(inner_exception, LdbError):
            (ldb_ecode, ldb_emsg) = inner_exception.args
            if ldb_ecode == ERR_INVALID_CREDENTIALS:
                print("Invalid username or password", file=self.errf)
                force_traceback = False
            elif ldb_emsg == 'LDAP client internal error: NT_STATUS_NETWORK_UNREACHABLE':
                print("Could not reach remote server", file=self.errf)
                force_traceback = False
            elif ldb_emsg.startswith("Unable to open tdb "):
                self._print_error(message, ldb_emsg, 'ldb')
                force_traceback = False
            elif ldb_ecode == ERR_INSUFFICIENT_ACCESS_RIGHTS:
                self._print_error("User has insufficient access rights")
                force_traceback = False
            elif ldb_emsg == "Operation unavailable without authentication":
                self._print_error(ldb_emsg)
                force_traceback = False
            else:
                self._print_error(message, ldb_emsg, 'ldb')

        elif isinstance(inner_exception, SDDLValueError):
            self._print_sddl_value_error(inner_exception)
            force_traceback = False

        elif isinstance(inner_exception, AssertionError):
            self._print_error(message, klass='assert')
            force_traceback = True
        elif isinstance(inner_exception, RuntimeError):
            self._print_error(message, evalue, 'runtime')
        elif type(inner_exception) is Exception:
            self._print_error(message, evalue, 'exception')
            force_traceback = True
        elif inner_exception is None:
            self._print_error(message)
        else:
            self._print_error(message, evalue, str(etype))

        if force_traceback or samba.get_debug_level() >= 3:
            traceback.print_tb(etraceback, file=self.errf)

    def _create_parser(self, prog=None, epilog=None):
        parser = OptionParser(
            usage=self.synopsis,
            description=self.full_description,
            formatter=PlainHelpFormatter(),
            prog=prog,
            epilog=epilog,
            option_class=Option)
        parser.add_options(self.takes_options)
        optiongroups = {}

        # let samba-tool subcommands process --version
        if "versionopts" not in self.takes_optiongroups:
            self.takes_optiongroups["_versionopts"] = options.VersionOptions

        for name in sorted(self.takes_optiongroups.keys()):
            optiongroup = self.takes_optiongroups[name]
            optiongroups[name] = optiongroup(parser)
            parser.add_option_group(optiongroups[name])

        if self.use_colour:
            parser.add_option("--color",
                              help="use colour if available (default: auto)",
                              metavar="always|never|auto",
                              default="auto")

        return parser, optiongroups

    def message(self, text):
        self.outf.write(text + "\n")

    def _resolve(self, path, *argv, outf=None, errf=None):
        """This is a leaf node, the command that will actually run."""
        self._set_files(outf, errf)
        self.command_name = path
        return (self, argv)

    def _run(self, *argv):
        parser, optiongroups = self._create_parser(self.command_name)

        # Handle possible validation errors raised by parser
        try:
            opts, args = parser.parse_args(list(argv))
        except Exception as e:
            self.show_command_error(e)
            return -1

        # Filter out options from option groups
        #
        # run() methods on subclasses receive all direct options as
        # keyword arguments, but options that come from OptionGroups
        # (for example, --configfile from SambaOpts group) are removed
        # from the direct keyword arguments list, and the option group
        # itself becomes a keyword argument. The option can be
        # accessed as an attribute of that (e.g. sambaopts.configfile).
        #
        # This allows for option groups to grow without needing to
        # change the signature for all samba-tool tools.
        #
        # _versionopts special case.
        # ==========================
        #
        # The _versionopts group was added automatically, and is
        # removed here. It only has the -V/--version option, and that
        # will have triggered already if given (as will --help, and
        # errors on unknown options).
        #
        # Some subclasses take 'versionopts' which they expect to
        # receive but never use.

        kwargs = dict(opts.__dict__)

        for og_name, option_group in optiongroups.items():
            for option in option_group.option_list:
                if option.dest is not None and option.dest in kwargs:
                    del kwargs[option.dest]
            if og_name != '_versionopts':
                kwargs[og_name] = option_group

        if kwargs.get('output_format') == 'json':
            self.preferred_output_format = 'json'
        else:
            # we need to reset this for the tests that reuse the
            # samba-tool object.
            self.preferred_output_format = None

        if self.use_colour:
            self.apply_colour_choice(kwargs.pop('color', 'auto'))

        # Check for a min a max number of allowed arguments, whenever possible
        # The suffix "?" means zero or one occurrence
        # The suffix "+" means at least one occurrence
        # The suffix "*" means zero or more occurrences
        min_args = 0
        max_args = 0
        undetermined_max_args = False
        for i, arg in enumerate(self.takes_args):
            if arg[-1] != "?" and arg[-1] != "*":
                min_args += 1
            if arg[-1] == "+" or arg[-1] == "*":
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
        except Exception as e:
            self.show_command_error(e)
            return -1

    def run(self, *args, **kwargs):
        """Run the command. This should be overridden by all subclasses."""
        raise NotImplementedError(f"'{self.command_name}' run method not implemented")

    def get_logger(self, name="", verbose=False, quiet=False, **kwargs):
        """Get a logger object."""
        return get_samba_logger(
            name=name or self.name, stream=self.errf,
            verbose=verbose, quiet=quiet,
            **kwargs)

    def apply_colour_choice(self, requested):
        """Heuristics to work out whether the user wants colour output, from a
        --color=yes|no|auto option. This alters the ANSI 16 bit colour
        "constants" in the colour module to be either real colours or empty
        strings.
        """
        self.requested_colour = requested
        try:
            colour.colour_if_wanted(self.outf,
                                    self.errf,
                                    hint=requested)
        except ValueError as e:
            raise CommandError(f"Unknown --color option: {requested} "
                               "please choose from always|never|auto")


class SuperCommand(Command):
    """A samba-tool command with subcommands."""

    synopsis = "%prog <subcommand>"

    subcommands = {}

    def _resolve(self, path, *args, outf=None, errf=None):
        """This is an internal node. We need to consume one of the args and
        find the relevant child, returning an instance of that Command.

        If there are no children, this SuperCommand will be returned
        and its _run() will do a --help like thing.
        """
        self.command_name = path
        self._set_files(outf, errf)

        # We collect up certain option arguments and pass them to the
        # leaf, which is why we iterate over args, though we really
        # expect to return in the first iteration.
        deferred_args = []

        for i, a in enumerate(args):
            if a in self.subcommands:
                sub_args = args[i + 1:] + tuple(deferred_args)
                sub_path = f'{path} {a}'

                sub = self.subcommands[a]
                return sub._resolve(sub_path, *sub_args, outf=outf, errf=errf)

            if a in ['-V', '--version']:
                return (self, [a])

            if a in ['--help', 'help', None, '-h']:
                # we pass these to the leaf node.
                if a == 'help':
                    a = '--help'
                deferred_args.append(a)
                continue

            # they are talking nonsense
            print("%s: no such subcommand: %s\n" % (path, a), file=self.outf)
            return (self, [])

        # We didn't find a subcommand, but maybe we found e.g. --help
        if not deferred_args:
            print("%s: missing subcommand\n" % (path), file=self.outf)
        return (self, deferred_args)

    def _run(self, *argv):
        epilog = "\nAvailable subcommands:\n"

        subcmds = sorted(self.subcommands.keys())
        max_length = max([len(c) for c in subcmds], default=0)
        for cmd_name in subcmds:
            cmd = self.subcommands[cmd_name]
            if cmd.hidden:
                continue
            epilog += "  %*s  - %s\n" % (
                -max_length, cmd_name, cmd.short_description)

        epilog += ("\nFor more help on a specific subcommand, please type: "
                   f"{self.command_name} <subcommand> (-h|--help)\n")

        parser, optiongroups = self._create_parser(self.command_name, epilog=epilog)
        opts, args = parser.parse_args(list(argv))

        # note: if argv had --help, parser.parse_args() will have
        # already done the .print_help() and attempted to exit with
        # return code 0, so we won't get here.
        parser.print_help()
        return -1


class CommandError(Exception):
    """An exception class for samba-tool Command errors."""

    def __init__(self, message, inner_exception=None):
        self.message = message
        self.inner_exception = inner_exception
        self.exception_info = sys.exc_info()

    def __repr__(self):
        return "CommandError(%s)" % self.message


def exception_to_command_error(*exceptions):
    """If you think all instances of a particular exceptions can be
    turning to a CommandError, do this:

    @exception_to_command_error(ValueError, LdbError):
    def run(self, username, ...):
        # continue as normal
    """
    def wrap2(f):
        def wrap(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except exceptions as e:
                raise CommandError(e)
        return wrap
    return wrap2

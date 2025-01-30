# Samba-specific bits for optparse
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

"""Support for parsing Samba-related command-line options."""

__docformat__ = "restructuredText"

import optparse
import os
import sys
from abc import ABCMeta, abstractmethod
from copy import copy

from samba.credentials import (
    Credentials,
    AUTO_USE_KERBEROS,
    DONT_USE_KERBEROS,
    MUST_USE_KERBEROS,
)
from samba._glue import get_burnt_commandline
import samba


def check_bytes(option, opt, value):
    """Custom option type to allow the input of sizes using byte, kb, mb ...

    units, e.g. 2Gb, 4KiB ...
       e.g. Option("--size", type="bytes", metavar="SIZE")
    """

    multipliers = {"B": 1,
                   "KB": 1024,
                   "MB": 1024 * 1024,
                   "GB": 1024 * 1024 * 1024}

    # strip out any spaces
    v = value.replace(" ", "")

    # extract the numeric prefix
    digits = ""
    while v and v[0:1].isdigit() or v[0:1] == '.':
        digits += v[0]
        v = v[1:]

    try:
        m = float(digits)
    except ValueError:
        msg = ("{0} option requires a numeric value, "
               "with an optional unit suffix").format(opt)
        raise optparse.OptionValueError(msg)

    # strip out the 'i' and convert to upper case so
    # kib Kib kb KB are all equivalent
    suffix = v.upper().replace("I", "")
    try:
        return m * multipliers[suffix]
    except KeyError as k:
        msg = ("{0} invalid suffix '{1}', "
               "should be B, Kb, Mb or Gb").format(opt, v)
        raise optparse.OptionValueError(msg)


class OptionMissingError(optparse.OptionValueError):
    """One or more Options with required=True is missing."""

    def __init__(self, options):
        """Raised when required Options are missing from the command line.

        :param options: list of 1 or more option
        """
        self.options = options

    def __str__(self):
        if len(self.options) == 1:
            missing = self.options[0]
            return f"Argument {missing} is required."
        else:
            options = sorted([str(option) for option in self.options])
            missing = ", ".join(options)
            return f"The arguments {missing} are required."


class ValidationError(Exception):
    """ValidationError is the exception raised by validators.

    Should be raised from the __call__ method of the Validator subclass.
    """
    pass


class Validator(metaclass=ABCMeta):
    """Base class for Validators used by SambaOption.

    Subclass this to make custom validators and implement __call__.
    """

    @abstractmethod
    def __call__(self, field, value):
        pass


class Option(optparse.Option):
    ATTRS = optparse.Option.ATTRS + ["required", "validators"]
    TYPES = optparse.Option.TYPES + ("bytes",)
    TYPE_CHECKER = copy(optparse.Option.TYPE_CHECKER)
    TYPE_CHECKER["bytes"] = check_bytes

    def run_validators(self, opt, value):
        """Runs the list of validators on the current option."""
        validators = getattr(self, "validators") or []
        for validator in validators:
            validator(opt, value)

    def convert_value(self, opt, value):
        """Override convert_value to run validators just after.

        This can also be done in process() but there we would have to
        replace the entire method.
        """
        value = super().convert_value(opt, value)
        self.run_validators(opt, value)
        return value


class OptionParser(optparse.OptionParser):
    """Samba OptionParser, adding support for required=True on Options."""

    def __init__(self,
                 usage=None,
                 option_list=None,
                 option_class=Option,
                 version=None,
                 conflict_handler="error",
                 description=None,
                 formatter=None,
                 add_help_option=True,
                 prog=None,
                 epilog=None):
        """
        Ensure that option_class defaults to the Samba one.
        """
        super().__init__(usage, option_list, option_class, version,
                         conflict_handler, description, formatter,
                         add_help_option, prog, epilog)

    def check_values(self, values, args):
        """Loop through required options if value is missing raise exception."""
        missing = []
        for option in self._get_all_options():
            if option.required:
                value = getattr(values, option.dest)
                if value is None:
                    missing.append(option)

        if missing:
            raise OptionMissingError(missing)

        return super().check_values(values, args)


class OptionGroup(optparse.OptionGroup):
    """Samba OptionGroup base class.

    Provides a generic set_option method to be used as Option callback,
    so that one doesn't need to be created for every available Option.

    Also overrides the add_option method, so it correctly initialises
    the defaults on the OptionGroup.
    """

    def add_option(self, *args, **kwargs):
        """Override add_option so it applies defaults during constructor."""
        opt = super().add_option(*args, **kwargs)
        default = None if opt.default == optparse.NO_DEFAULT else opt.default
        self.set_option(opt, opt.get_opt_string(), default, self.parser)
        return opt

    def set_option(self, option, opt_str, arg, parser):
        """Callback to set the attribute based on the Option dest name."""
        dest = option.dest or option._long_opts[0][2:].replace("-", "_")
        setattr(self, dest, arg)


class SambaOptions(OptionGroup):
    """General Samba-related command line options."""

    def __init__(self, parser):
        from samba import fault_setup
        fault_setup()

        # This removes passwords from the commandline via
        # setproctitle() but makes no change to python sys.argv so we
        # can continue to process as normal
        #
        # get_burnt_commandline returns None if no change is needed
        new_proctitle = get_burnt_commandline(sys.argv)
        if new_proctitle is not None:
            try:
                import setproctitle
                setproctitle.setproctitle(new_proctitle)

            except ModuleNotFoundError:
                msg = ("WARNING: Using passwords on command line is insecure. "
                       "Installing the setproctitle python module will hide "
                       "these from shortly after program start.\n")
                sys.stderr.write(msg)
                sys.stderr.flush()

        from samba.param import LoadParm
        super().__init__(parser, "Samba Common Options")
        self.add_option("-s", "--configfile", action="callback",
                        type=str, metavar="FILE", help="Configuration file",
                        callback=self._load_configfile)
        self.add_option("-d", "--debuglevel", action="callback",
                        type=str, metavar="DEBUGLEVEL", help="debug level",
                        callback=self._set_debuglevel)
        self.add_option("--option", action="callback",
                        type=str, metavar="OPTION",
                        help="set smb.conf option from command line",
                        callback=self._set_option)
        self.add_option("--realm", action="callback",
                        type=str, metavar="REALM", help="set the realm name",
                        callback=self._set_realm)
        self._configfile = None
        self._lp = LoadParm()
        self.realm = None

    def get_loadparm_path(self):
        """Return path to the smb.conf file specified on the command line."""
        return self._configfile

    def _load_configfile(self, option, opt_str, arg, parser):
        self._configfile = arg

    def _set_debuglevel(self, option, opt_str, arg, parser):
        try:
            self._lp.set('debug level', arg)
        except RuntimeError:
            raise optparse.OptionValueError(
                f"invalid -d/--debug value: '{arg}'")
        parser.values.debuglevel = arg

    def _set_realm(self, option, opt_str, arg, parser):
        try:
            self._lp.set('realm', arg)
        except RuntimeError:
            raise optparse.OptionValueError(
                f"invalid --realm value: '{arg}'")
        self.realm = arg

    def _set_option(self, option, opt_str, arg, parser):
        if arg.find('=') == -1:
            raise optparse.OptionValueError(
                "--option option takes a 'a=b' argument")
        a = arg.split('=', 1)
        try:
            self._lp.set(a[0], a[1])
        except Exception as e:
            raise optparse.OptionValueError(
                "invalid --option option value %r: %s" % (arg, e))

    def get_loadparm(self):
        """Return loadparm object with data specified on the command line."""
        if self._configfile is not None:
            self._lp.load(self._configfile)
        elif os.getenv("SMB_CONF_PATH") is not None:
            self._lp.load(os.getenv("SMB_CONF_PATH"))
        else:
            self._lp.load_default()
        return self._lp


class Samba3Options(SambaOptions):
    """General Samba-related command line options with an s3 param."""

    def __init__(self, parser):
        super().__init__(parser)
        from samba.samba3 import param as s3param
        self._lp = s3param.get_context()


class HostOptions(OptionGroup):
    """Command line options for connecting to target host or database."""

    def __init__(self, parser):
        super().__init__(parser, "Host Options")

        self.add_option("-H", "--URL",
                        help="LDB URL for database or target server",
                        type=str, metavar="URL", action="callback",
                        callback=self.set_option, dest="H")


class VersionOptions(OptionGroup):
    """Command line option for printing Samba version."""
    def __init__(self, parser):
        super().__init__(parser, "Version Options")
        self.add_option("-V", "--version", action="callback",
                        callback=self._display_version,
                        help=f"Display version number ({samba.version})")

    def _display_version(self, option, opt_str, arg, parser):
        print(samba.version)
        sys.exit(0)


def parse_kerberos_arg_legacy(arg, opt_str):
    if arg.lower() in ["yes", 'true', '1']:
        return MUST_USE_KERBEROS
    elif arg.lower() in ["no", 'false', '0']:
        return DONT_USE_KERBEROS
    elif arg.lower() in ["auto"]:
        return AUTO_USE_KERBEROS
    else:
        raise optparse.OptionValueError("invalid %s option value: %s" %
                                        (opt_str, arg))


def parse_kerberos_arg(arg, opt_str):
    if arg.lower() == 'required':
        return MUST_USE_KERBEROS
    elif arg.lower() == 'desired':
        return AUTO_USE_KERBEROS
    elif arg.lower() == 'off':
        return DONT_USE_KERBEROS
    else:
        raise optparse.OptionValueError("invalid %s option value: %s" %
                                        (opt_str, arg))


class CredentialsOptions(OptionGroup):
    """Command line options for specifying credentials."""

    def __init__(self, parser, special_name=None):
        self.special_name = special_name
        if special_name is not None:
            self.section = "Credentials Options (%s)" % special_name
        else:
            self.section = "Credentials Options"

        self.ask_for_password = True
        self.ipaddress = None
        self.machine_pass = False
        super().__init__(parser, self.section)
        self._add_option("--simple-bind-dn", metavar="DN", action="callback",
                         callback=self._set_simple_bind_dn, type=str,
                         help="DN to use for a simple bind")
        self._add_option("--password", metavar="PASSWORD", action="callback",
                         help="Password", type=str, callback=self._set_password)
        self._add_option("-U", "--username", metavar="USERNAME",
                         action="callback", type=str,
                         help="Username", callback=self._parse_username)
        self._add_option("-W", "--workgroup", metavar="WORKGROUP",
                         action="callback", type=str,
                         help="Workgroup", callback=self._parse_workgroup)
        self._add_option("-N", "--no-pass", action="callback",
                         help="Don't ask for a password",
                         callback=self._set_no_password)
        self._add_option("", "--ipaddress", metavar="IPADDRESS",
                         action="callback", type=str,
                         help="IP address of server",
                         callback=self._set_ipaddress)
        self._add_option("-P", "--machine-pass",
                         action="callback",
                         help="Use stored machine account password",
                         callback=self._set_machine_pass)
        self._add_option("--use-kerberos", metavar="desired|required|off",
                         action="callback", type=str,
                         help="Use Kerberos authentication", callback=self._set_kerberos)
        self._add_option("--use-krb5-ccache", metavar="KRB5CCNAME",
                         action="callback", type=str,
                         help="Kerberos Credentials cache",
                         callback=self._set_krb5_ccache)
        self._add_option("-A", "--authentication-file", metavar="AUTHFILE",
                         action="callback", type=str,
                         help="Authentication file",
                         callback=self._set_auth_file)

        # LEGACY
        self._add_option("-k", "--kerberos", metavar="KERBEROS",
                         action="callback", type=str,
                         help="DEPRECATED: Migrate to --use-kerberos", callback=self._set_kerberos_legacy)
        self.creds = Credentials()

    def _add_option(self, *args1, **kwargs):
        if self.special_name is None:
            return self.add_option(*args1, **kwargs)

        args2 = ()
        for a in args1:
            if not a.startswith("--"):
                continue
            args2 += (a.replace("--", "--%s-" % self.special_name),)
        self.add_option(*args2, **kwargs)

    def _parse_username(self, option, opt_str, arg, parser):
        self.creds.parse_string(arg)
        self.machine_pass = False

    def _parse_workgroup(self, option, opt_str, arg, parser):
        self.creds.set_domain(arg)

    def _set_password(self, option, opt_str, arg, parser):
        self.creds.set_password(arg)
        self.ask_for_password = False
        self.machine_pass = False

    def _set_no_password(self, option, opt_str, arg, parser):
        self.ask_for_password = False

    def _set_machine_pass(self, option, opt_str, arg, parser):
        self.machine_pass = True

    def _set_ipaddress(self, option, opt_str, arg, parser):
        self.ipaddress = arg

    def _set_kerberos_legacy(self, option, opt_str, arg, parser):
        print('WARNING: The option -k|--kerberos is deprecated!')
        self.creds.set_kerberos_state(parse_kerberos_arg_legacy(arg, opt_str))

    def _set_kerberos(self, option, opt_str, arg, parser):
        self.creds.set_kerberos_state(parse_kerberos_arg(arg, opt_str))

    def _set_simple_bind_dn(self, option, opt_str, arg, parser):
        self.creds.set_bind_dn(arg)

    def _set_krb5_ccache(self, option, opt_str, arg, parser):
        self.ask_for_password = False
        self.creds.set_kerberos_state(MUST_USE_KERBEROS)
        self.creds.set_named_ccache(arg)

    def _set_auth_file(self, option, opt_str, arg, parser):
        if os.path.exists(arg):
            self.creds.parse_file(arg)
            self.ask_for_password = False
            self.machine_pass = False

    def get_credentials(self, lp, fallback_machine=False):
        """Obtain the credentials set on the command-line.

        :param lp: Loadparm object to use.
        :return: Credentials object
        """
        self.creds.guess(lp)
        if self.machine_pass:
            self.creds.set_machine_account(lp)
        elif self.ask_for_password:
            self.creds.set_cmdline_callbacks()

        # possibly fallback to using the machine account, if we have
        # access to the secrets db
        if fallback_machine and not self.creds.authentication_requested():
            try:
                self.creds.set_machine_account(lp)
            except Exception:
                pass

        return self.creds


class CredentialsOptionsDouble(CredentialsOptions):
    """Command line options for specifying credentials of two servers."""

    def __init__(self, parser):
        super().__init__(parser)
        self.no_pass2 = True
        self.add_option("--simple-bind-dn2", metavar="DN2", action="callback",
                        callback=self._set_simple_bind_dn2, type=str,
                        help="DN to use for a simple bind")
        self.add_option("--password2", metavar="PASSWORD2", action="callback",
                        help="Password", type=str,
                        callback=self._set_password2)
        self.add_option("--username2", metavar="USERNAME2",
                        action="callback", type=str,
                        help="Username for second server",
                        callback=self._parse_username2)
        self.add_option("--workgroup2", metavar="WORKGROUP2",
                        action="callback", type=str,
                        help="Workgroup for second server",
                        callback=self._parse_workgroup2)
        self.add_option("--no-pass2", action="store_true",
                        help="Don't ask for a password for the second server")
        self.add_option("--use-kerberos2", metavar="desired|required|off",
                        action="callback", type=str,
                        help="Use Kerberos authentication", callback=self._set_kerberos2)

        # LEGACY
        self.add_option("--kerberos2", metavar="KERBEROS2",
                        action="callback", type=str,
                        help="Use Kerberos", callback=self._set_kerberos2_legacy)
        self.creds2 = Credentials()

    def _parse_username2(self, option, opt_str, arg, parser):
        self.creds2.parse_string(arg)

    def _parse_workgroup2(self, option, opt_str, arg, parser):
        self.creds2.set_domain(arg)

    def _set_password2(self, option, opt_str, arg, parser):
        self.creds2.set_password(arg)
        self.no_pass2 = False

    def _set_kerberos2_legacy(self, option, opt_str, arg, parser):
        self.creds2.set_kerberos_state(parse_kerberos_arg(arg, opt_str))

    def _set_kerberos2(self, option, opt_str, arg, parser):
        self.creds2.set_kerberos_state(parse_kerberos_arg(arg, opt_str))

    def _set_simple_bind_dn2(self, option, opt_str, arg, parser):
        self.creds2.set_bind_dn(arg)

    def get_credentials2(self, lp, guess=True):
        """Obtain the credentials set on the command-line.

        :param lp: Loadparm object to use.
        :param guess: Try guess Credentials from environment
        :return: Credentials object
        """
        if guess:
            self.creds2.guess(lp)
        elif not self.creds2.get_username():
            self.creds2.set_anonymous()

        if self.no_pass2:
            self.creds2.set_cmdline_callbacks()
        return self.creds2

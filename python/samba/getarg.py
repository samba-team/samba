# Samba-specific bits for argparse
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
# Copyright (C) David Mulder <dmulder@suse.com> 2018
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

import argparse
import os
from samba.credentials import (
    Credentials,
    AUTO_USE_KERBEROS,
    DONT_USE_KERBEROS,
    MUST_USE_KERBEROS,
    )
import sys


def add_argument_group(parser, argument_group):
    parser._action_groups.append(argument_group)


def store_true(func):
    class StoreTrue(argparse._StoreConstAction):
        def __init__(self,
                     option_strings,
                     dest,
                     default=False,
                     required=False,
                     help=None):
            super(StoreTrue, self).__init__(
                option_strings=option_strings,
                dest=dest,
                const=True,
                default=default,
                required=required,
                help=help)
        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, True)
            func(self, option_string, values, parser)
    return StoreTrue

def store(func):
    class Store(argparse._StoreAction):
        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, values)
            func(self, option_string, values, parser)
    return Store


class SambaOptions(argparse._ArgumentGroup):
    """General Samba-related command line options."""

    def __init__(self, parser):
        from samba.param import LoadParm
        super(SambaOptions, self).__init__(parser, "Samba Common Options")
        self.add_argument("-s", "--configfile", type=str, metavar="FILE",
                          help="Configuration file",
                          action=store(self._load_configfile))
        self.add_argument("-d", "--debuglevel", type=str, metavar="DEBUGLEVEL",
                          help="debug level",
                          action=store(self._set_debuglevel))
        self.add_argument("--option", type=str, metavar="OPTION",
                          help="set smb.conf option from command line",
                          action=store(self._set_option))
        self.add_argument("--realm", type=str, metavar="REALM",
                          help="set the realm name",
                          action=store(self._set_realm))
        self._configfile = None
        self._lp = LoadParm()
        self.realm = None

    def get_loadparm_path(self):
        """Return path to the smb.conf file specified on the command line."""
        return self._configfile

    def _load_configfile(self, option, opt_str, arg, parser):
        self._configfile = arg

    def _set_debuglevel(self, option, opt_str, arg, parser):
        if arg < 0:
            raise argparse.ArgumentError(option, "invalid option value: %s" %
                                         arg)
        self._lp.set('debug level', arg)
        parser.values.debuglevel = arg

    def _set_realm(self, option, opt_str, arg, parser):
        self._lp.set('realm', arg)
        self.realm = arg

    def _set_option(self, option, opt_str, arg, parser):
        if arg.find('=') == -1:
            raise argparse.ArgumentError(option,
                "--option option takes a 'a=b' argument")
        a = arg.split('=')
        try:
            self._lp.set(a[0], a[1])
        except Exception as e:
            raise argparse.ArgumentError(option,
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


class VersionOptions(argparse._ArgumentGroup):
    """Command line option for printing Samba version."""
    def __init__(self, parser):
        super(VersionOptions, self).__init__(parser, "Version Options")
        self.add_argument("-V", "--version",
                          action=store_true(self._display_version),
                          help="Display version number")

    def _display_version(self, option, opt_str, arg, parser):
        import samba
        print(samba.version)
        sys.exit(0)


def parse_kerberos_arg(arg, opt_str):
    if arg.lower() in ["yes", 'true', '1']:
        return MUST_USE_KERBEROS
    elif arg.lower() in ["no", 'false', '0']:
        return DONT_USE_KERBEROS
    elif arg.lower() in ["auto"]:
        return AUTO_USE_KERBEROS
    else:
        raise argparse.ArgumentError(option, "invalid option value: %s" %
                                     arg)


class CredentialsOptions(argparse._ArgumentGroup):
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
        super(CredentialsOptions, self).__init__(parser, self.section)
        self._add_argument("--simple-bind-dn", metavar="DN",
                           action=store(self._set_simple_bind_dn), type=str,
                           help="DN to use for a simple bind")
        self._add_argument("--password", metavar="PASSWORD", help="Password",
                           type=str, action=store(self._set_password))
        self._add_argument("-U", "--username", metavar="USERNAME", type=str,
                           help="Username", action=store(self._parse_username))
        self._add_argument("-W", "--workgroup", metavar="WORKGROUP", type=str,
                           help="Workgroup",
                           action=store(self._parse_workgroup))
        self._add_argument("-N", "--no-pass", help="Don't ask for a password",
                           action=store_true(self._set_no_password))
        self._add_argument("-k", "--kerberos", metavar="KERBEROS", type=str,
                           help="Use Kerberos",
                           action=store(self._set_kerberos))
        self._add_argument("--ipaddress", metavar="IPADDRESS", type=str,
                           help="IP address of server",
                           action=store(self._set_ipaddress))
        self._add_argument("-P", "--machine-pass",
                           help="Use stored machine account password",
                           action=store_true(self._set_machine_pass))
        self._add_argument("--krb5-ccache", metavar="KRB5CCNAME", type=str,
                           help="Kerberos Credentials cache",
                           action=store(self._set_krb5_ccache))
        self.creds = Credentials()

    def _add_argument(self, *args1, **kwargs):
        if self.special_name is None:
            return self.add_argument(*args1, **kwargs)

        args2 = ()
        for a in args1:
            if not a.startswith("--"):
                continue
            args2 += (a.replace("--", "--%s-" % self.special_name),)
        self.add_argument(*args2, **kwargs)

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

    def _set_kerberos(self, option, opt_str, arg, parser):
        self.creds.set_kerberos_state(parse_kerberos_arg(arg, opt_str))

    def _set_simple_bind_dn(self, option, opt_str, arg, parser):
        self.creds.set_bind_dn(arg)

    def _set_krb5_ccache(self, option, opt_str, arg, parser):
        self.creds.set_named_ccache(arg)

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
        CredentialsOptions.__init__(self, parser)
        self.no_pass2 = True
        self.add_argument("--simple-bind-dn2", metavar="DN2",
                          action=store(self._set_simple_bind_dn2), type=str,
                          help="DN to use for a simple bind")
        self.add_argument("--password2", metavar="PASSWORD2",
                          help="Password", type=str,
                          action=store(self._set_password2))
        self.add_argument("--username2", metavar="USERNAME2", type=str,
                          help="Username for second server",
                          action=store(self._parse_username2))
        self.add_argument("--workgroup2", metavar="WORKGROUP2", type=str,
                          help="Workgroup for second server",
                          action=store(self._parse_workgroup2))
        self.add_argument("--no-pass2",
                          help="Don't ask for a password for the second server")
        self.add_argument("--kerberos2", metavar="KERBEROS2", type=str,
                          help="Use Kerberos",
                          action=store(self._set_kerberos2))
        self.creds2 = Credentials()

    def _parse_username2(self, option, opt_str, arg, parser):
        self.creds2.parse_string(arg)

    def _parse_workgroup2(self, option, opt_str, arg, parser):
        self.creds2.set_domain(arg)

    def _set_password2(self, option, opt_str, arg, parser):
        self.creds2.set_password(arg)
        self.no_pass2 = False

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

# Unix SMB/CIFS implementation.
#
# samba-tool commands for Key Distribution Services
#
# Copyright © Catalyst.Net Ltd. 2024
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


import samba.getopt as options
from ldb import SCOPE_SUBTREE
from samba.netcmd import Command, CommandError, Option, SuperCommand
from samba.dcerpc import misc
from ldb import MessageElement, LdbError
from samba import string_is_guid


from samba.nt_time import (string_from_nt_time,
                           nt_time_from_string,
                           nt_now,
                           timedelta_from_nt_time_delta)


def root_key_base_dn(ldb):
    base_dn = ldb.get_config_basedn()
    base_dn.add_child(
        "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services")
    return base_dn


def get_root_key_by_name_or_dn(ldb, name, attrs=None):
    if string_is_guid(str(name)):
        key = 'name'
    else:
        key = 'dn'

    if attrs is None:
        attrs = ['*']

    base_dn = root_key_base_dn(ldb)

    expression = ("(&(objectClass = msKds-ProvRootKey)"
                  f"({key} = {name}))")

    res = ldb.search(base_dn,
                     scope=SCOPE_SUBTREE,
                     expression=expression,
                     attrs=attrs)

    if len(res) == 0:
        raise CommandError(f"no such root key: {name}")
    if len(res) != 1:
        # the database is in a sorry state
        raise CommandError(f"duplicate root keys matching {name}")

    return res[0]


def get_sorted_root_keys(ldb, attrs=None, n=None):
    if attrs is None:
        attrs = ['*']

    base_dn = root_key_base_dn(ldb)

    res = ldb.search(base_dn,
                     scope=SCOPE_SUBTREE,
                     expression="(objectClass = msKds-ProvRootKey)",
                     attrs=attrs,
                     controls=["server_sort:1:1:msKds-UseStartTime"])

    return res


def delta_string(d):
    """Turn a datetime.timedelta into an approximate string."""
    td = timedelta_from_nt_time_delta(d)
    secs = td.total_seconds()
    absolute = abs(secs)
    if absolute < 2:
        return 'about now'
    s = 'about '
    if absolute < 120:
        s += f'{int(absolute)} seconds'
    elif absolute < 7200:
        s += f'{int(absolute / 60)} minutes'
    elif absolute < 48 * 3600:
        s += f'{int(absolute / 3600)} hours'
    else:
        s += f'{int(absolute / (24 * 3600))} days'

    if secs <= 0:
        s += ' ago'
    else:
        s += ' in the FUTURE'

    return s


# These next ridiculously simple looking functions are for the
# ENCODERS mapping below.

def guid_to_string(v):
    return str(misc.GUID(v))


def string_from_nt_time_string(nt_time):
    nt_time = int(nt_time)
    return string_from_nt_time(nt_time)


# ENCODERS is a mapping of attribute names to encoding functions for
# the corresponding values. Anything not mentioned will go through
# str(), which for MessageElements is the same as bytes.decode().
ENCODERS = {
    "msKds-UseStartTime": string_from_nt_time_string,
    "msKds-CreateTime": string_from_nt_time_string,
    "msKds-RootKeyData": bytes.hex,
    "msKds-SecretAgreementParam": bytes.hex,
    "objectGUID": guid_to_string,
    "msKds-KDFParam": bytes.hex,
    "msKds-PublicKeyLength": int,
    "msKds-PrivateKeyLength": int,
    "msKds-Version": int,
}


def encode_by_key(k, v):
    """Convert an attribute into a printable form, using the attribute
    name to guess the best format."""
    fn = ENCODERS.get(k, lambda x: str(x))

    if not isinstance(v, MessageElement):  # probably Dn
        return fn(v)

    if len(v) == 1:
        return fn(v[0])

    return [fn(x) for x in v]


# these attributes we normally wany to show. 'name' is a GUID string
# (and has the same value as cn, the rdn).
BASE_ATTRS = ["name",
              "msKds-UseStartTime",
              "msKds-CreateTime",
              ]

# these attributes are secret, and also pretty opaque and useless to
# look at (unless you want to steal the secret).
SECRET_ATTRS = ["msKds-RootKeyData",
                "msKds-SecretAgreementParam"]

# these are things you might want to look at, but  generally don't.
VERBOSE_ATTRS = ["whenCreated",
                 "whenChanged",
                 "objectGUID",
                 "msKds-KDFAlgorithmID",
                 "msKds-KDFParam",
                 "msKds-SecretAgreementAlgorithmID",
                 "msKds-PublicKeyLength",
                 "msKds-PrivateKeyLength",
                 "msKds-Version",
                 "msKds-DomainID",
                 "cn",
                 ]


class RootKeyCommand(Command):
    """Base class with a common method for presenting root key data."""
    def show_root_key_message(self, msg,
                              output_format=None,
                              show_secrets=False,
                              preamble=None,
                              now=None):
        if output_format == 'json':
            out = {}
            if preamble is not None:
                out['message'] = preamble
            for k, v in msg.items():
                if not show_secrets and k in SECRET_ATTRS:
                    continue
                out[k] = encode_by_key(k, v)
            self.print_json(out)
            return

        if now is None:
            now = nt_now()
        create_time = int(msg['msKds-createTime'][0])
        start_time = int(msg['msKds-UseStartTime'][0])
        create_delta_string = delta_string(create_time - now)
        start_delta_string = delta_string(start_time - now)

        if preamble is not None:
            self.message(preamble)

        self.message(f"name {msg['name']}")
        self.message(f"   created        {string_from_nt_time(create_time)} ({create_delta_string})")
        self.message(f"   usable from    {string_from_nt_time(start_time)} ({start_delta_string})")

        if show_secrets:
            for k in SECRET_ATTRS:
                v = msg[k][0].hex()
                self.message(f"   {k:14} {v}")

        remaining_keys = [k for k in msg if k not in BASE_ATTRS + SECRET_ATTRS]

        for k in remaining_keys:
            v = encode_by_key(k, msg[k])
            self.message(f"   {k:14} {v}")

        self.message('')


class cmd_domain_kds_root_key_create(RootKeyCommand):
    """Create a KDS root key object."""

    synopsis = "%prog [-H <URL>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
        Option("--use-start-time", help="Use of the key begins at this time."),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            output_format=None, use_start_time=None, verbose=None):
        kwargs = {}
        if use_start_time is not None:
            try:
                nt_use = nt_time_from_string(use_start_time)
                kwargs['use_start_time'] = nt_use
            except ValueError as e:
                raise CommandError(e) from None

        ldb = self.ldb_connect(hostopts, sambaopts, credopts)
        dn = ldb.new_gkdi_root_key(**kwargs)
        guid = dn.get_rdn_value()

        attrs = BASE_ATTRS[:]
        if verbose:
            attrs += VERBOSE_ATTRS

        msg = get_root_key_by_name_or_dn(ldb, guid, attrs=attrs)
        start_time = int(msg['msKds-UseStartTime'][0])
        used_from_string = (f"usable from {string_from_nt_time(start_time)} "
                            f"({delta_string(start_time - nt_now())})")

        message = f"created root key {guid}, {used_from_string}"

        if verbose:
            self.show_root_key_message(msg,
                                       output_format,
                                       preamble=f"{message}\n")

        elif output_format == 'json':
            kwargs = {k: msg[k] for k in attrs}
            self.print_json_status(message=message, dn=str(dn), **kwargs)
        else:
            self.message(message)


class cmd_domain_kds_root_key_delete(RootKeyCommand):
    """Delete a KDS root key."""

    synopsis = "%prog [-H <URL>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="The key to delete"),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, name=None, output_format=None):
        ldb = self.ldb_connect(hostopts, sambaopts, credopts)
        try:
            root_key = get_root_key_by_name_or_dn(ldb, name)
        except LdbError as e:
            raise CommandError(e)

        ldb.delete(root_key.dn)

        guid = root_key.dn.get_rdn_value()
        message = f"deleted root key {guid}"

        if output_format == 'json':
            self.print_json_status(message)
        else:
            self.message(message)


class cmd_domain_kds_root_key_list(RootKeyCommand):
    """List KDS root keys."""

    synopsis = "%prog [-H <URL>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--show-secrets", help="Show root key hash", action="store_true"),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None, verbose=None,
            show_secrets=None, output_format=None):
        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        attrs = BASE_ATTRS[:]

        if show_secrets:
            attrs += SECRET_ATTRS

        if verbose:
            attrs += VERBOSE_ATTRS

        res = get_sorted_root_keys(ldb, attrs)

        if output_format == 'json':
            out = []
            for msg in res.msgs:
                m = {}
                out.append(m)
                for k, v in msg.items():
                    m[k] = encode_by_key(k, v)

            self.print_json(out)
            return

        if len(res) == 0:
            self.message("no root keys found.")
            return

        self.message(f"{len(res)} root key{'s' if len(res) > 1 else ''} found.\n")

        now = nt_now()
        for msg in res:
            self.show_root_key_message(msg,
                                       output_format,
                                       show_secrets=show_secrets,
                                       now=now)
            self.message('')


class cmd_domain_kds_root_key_view(RootKeyCommand):
    """View a root key object."""

    synopsis = "%prog [-H <URL>] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--name", help="Choose thhe key to view (by GUID)"),
        Option("--latest", help="View the latest key", action="store_true"),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--show-secrets", help="Show root key hash", action="store_true"),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, hostopts=None, sambaopts=None, credopts=None,
            name=None, output_format=None, show_secrets=None, verbose=None,
            latest=None):
        ldb = self.ldb_connect(hostopts, sambaopts, credopts)

        # The default behaviour is to show quite a lot of information,
        # equal to that seen with `list --verbose`, but leaving out
        # uninteresting attributes like "showInAdvancedViewOnly" and
        # tautological ones like "objectClass".
        #
        #  <no extra flags>          -> selected attributes
        #  --show-secrets            -> selected attributes and secrets
        #  --verbose                 -> all attributes EXCEPT secrets
        #  --verbose --show-secrets  -> all attributes
        attrs = BASE_ATTRS + VERBOSE_ATTRS
        if show_secrets:
            attrs += SECRET_ATTRS
        if verbose:
            attrs += ["*"]

        if latest:
            if name is not None:
                raise CommandError("It makes no sense to combine --name and --latest")
            res = get_sorted_root_keys(ldb, attrs)
            if len(res) == 0:
                raise CommandError("no root keys found")
            msg = res[0]

        elif name is not None:
            msg = get_root_key_by_name_or_dn(ldb, name, attrs)
        else:
            raise CommandError("PLease use '--name <GUID>' or '--latest' "
                               " (try the 'list' command to find names)")

        self.show_root_key_message(msg,
                                   output_format,
                                   show_secrets=show_secrets)


class cmd_domain_kds_root_key(SuperCommand):
    """Manage key distribution service root keys."""

    subcommands = {
        "create": cmd_domain_kds_root_key_create(),
        "delete": cmd_domain_kds_root_key_delete(),
        "list": cmd_domain_kds_root_key_list(),
        "view": cmd_domain_kds_root_key_view(),
    }

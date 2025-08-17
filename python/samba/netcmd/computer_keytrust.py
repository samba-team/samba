# samba-tool commands to manager Key Credential Links on a computer
#
# Copyright © Douglas Bagnall <dbagnall@samba.org> 2025
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

import ldb
import samba.getopt as options
from samba.domain.models import Computer
from samba.domain.models.exceptions import ModelError
from samba.netcmd import Command, CommandError, Option, SuperCommand
from samba.netcmd import exception_to_command_error
from samba.key_credential_link import (create_key_credential_link,
                                       kcl_in_list,
                                       filter_kcl_list)


class cmd_computer_keycredentiallink_add(Command):
    """Add a key-credential-link."""

    synopsis = "%prog <computername> [options] <pubkey>"

    takes_args = ["computername", "pubkey"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--link-target", metavar="DN",
               help="link to this DN (default: this computer's DN)"),
        Option("--encoding", default='auto', choices=('pem', 'der', 'auto'),
               help="Key format (optional)"),
        Option("--force", default=False, action='store_true',
               help="proceed with operations that seems ill-fated"),
    ]

    @exception_to_command_error(ValueError, ModelError, FileNotFoundError)
    def run(self, computername, pubkey,
            hostopts=None, sambaopts=None, credopts=None,
            link_target=None, encoding='auto', force=False):

        samdb = self.ldb_connect(hostopts, sambaopts, credopts)
        computer = Computer.find(samdb, computername)

        if link_target is None:
            link_target = computer.dn

        with open(pubkey, 'rb') as f:
            data = f.read()

        try:
            link = create_key_credential_link(samdb,
                                              link_target,
                                              data,
                                              encoding=encoding,
                                              force=force)
        except ldb.LdbError as e:
            # with --force, we will end up with CONSTRAINT_VIOLATION
            # at computer.save(), rather than NO_SUCH_OBJECT now.
            if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise CommandError(f"Link target '{link_target}' does not exist")
            raise

        if not force and kcl_in_list(link, computer.key_credential_link):
            # It is not allowed to have duplicate linked attributes,
            # which in the case of key credential links means having
            # the same key blob and the same DN target.
            #
            # It is still possible to have the same key material and
            # DN target if other fields (e.g. creation date) in the
            # blob differ. The creation date is set with one second
            # resolution in create_key_credential_link() just above,
            # which puts us in the awkward position of creating a race
            # if people are running samba-tool in a script.
            #
            # While the uniqueness invariant is a feature of AD/DSDB,
            # not of key credential links, duplicates are not going to
            # be useful, so we try to avoid this by checking first
            # unless --force is used.
            #
            # if --force is used to add a key for the second time in
            # the same second, computer.save() below will raise an
            # ERR_ATTRIBUTE_OR_VALUE_EXISTS LdbError.
            raise CommandError(f"Computer {computername} "
                               "already has this key credential link")

        computer.key_credential_link.append(link)
        computer.save(samdb)


class cmd_computer_keycredentiallink_delete(Command):
    """Delete a key-credential-link."""

    synopsis = "%prog <computername> [options]"

    takes_args = ["computername"]

    takes_options = [
        Option("--link-target", metavar="DN",
               help="Delete this key credential link (a DN)"),
        Option("--fingerprint", metavar="HH:HH:..",
               help="Delete the key credential link with this key fingerprint"),
        Option("--all", action='store_true',
               help="Delete all key credential links"),
        Option("-n", "--dry-run", action='store_true',
               help="Do nothing but print what would happen"),
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    @exception_to_command_error(ValueError, ModelError)
    def run(self, computername, hostopts=None, sambaopts=None, credopts=None,
            link_target=None, fingerprint=None, all=False, dry_run=False):

        samdb = self.ldb_connect(hostopts, sambaopts, credopts)
        computer = Computer.find(samdb, computername)

        keycredlinks = computer.key_credential_link

        if all:
            goners = keycredlinks
        else:
            goners = filter_kcl_list(samdb,
                                     keycredlinks,
                                     link_target=link_target,
                                     fingerprint=fingerprint)

        keepers = [x for x in keycredlinks if x not in goners]
        nk = len(keepers)

        if dry_run:
            self.message("Without --dry-run, this would happen:")
            if not goners:
                self.message("NO key credential links are deleted")
            for x in goners:
                self.message(f"DELETE {x} (fingerprint {x.fingerprint()})")
            self.message('')
            for x in keepers:
                self.message(f"KEEP {x} (fingerprint {x.fingerprint()})")

            self.message(f"{computername} would now have {nk} key credential link"
                         f"{'' if nk == 1 else 's'}")
            return

        if not goners:
            # fail without traceback if the filter matches no links
            raise CommandError("no key credential links deleted")

        computer.key_credential_link = keepers
        computer.save(samdb)

        for x in goners:
            self.message(f"Deleted {x} (fingerprint {x.fingerprint()})")
        self.message('')
        for x in keepers:
            self.message(f"Keeping {x} (fingerprint {x.fingerprint()})")

        self.message(f"{computername} now has {nk} key credential link"
                     f"{'' if nk == 1 else 's'}")


class cmd_computer_keycredentiallink_view(Command):
    """View a computer's key credential links."""
    synopsis = "%prog <computername> [options]"

    takes_args = ["computername"]

    takes_options = [
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    @exception_to_command_error(ValueError, ModelError)
    def run(self, computername, hostopts=None, sambaopts=None, credopts=None,
            verbose=False):

        samdb = self.ldb_connect(hostopts, sambaopts, credopts)
        computer = Computer.find(samdb, computername)

        if verbose:
            verbosity = 3
        else:
            verbosity = 2

        n = len(computer.key_credential_link)
        self.message(f"{computername} has {n} key credential link"
                     f"{'' if n == 1 else 's'}\n")

        for kcl in computer.key_credential_link:
            self.message(kcl.description(verbosity), '')


class cmd_computer_keytrust(SuperCommand):
    """Manage key-credential links on a computer."""

    subcommands = {
        "add": cmd_computer_keycredentiallink_add(),
        "delete": cmd_computer_keycredentiallink_delete(),
        "view": cmd_computer_keycredentiallink_view(),
    }

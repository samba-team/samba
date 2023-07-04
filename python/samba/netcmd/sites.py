# sites management
#
# Copyright Matthieu Patou <mat@matws.net> 2011
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

from samba import sites, subnets
import samba.getopt as options
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
)
from samba.netcmd.domain.models import Site, Subnet
from samba.netcmd.domain.models.exceptions import ModelError


class cmd_sites_list(Command):
    """List sites."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, ldap_url=None, sambaopts=None, credopts=None,
            versionopts=None, output_format=None):

        ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        # sites by cn.
        try:
            sites_dict = {site.cn: site.as_dict()
                          for site in Site.query(ldb)}
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json(sites_dict)
        else:
            for site in sites_dict.keys():
                self.outf.write(f"{site}\n")


class cmd_sites_view(Command):
    """View one site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="ldap_url"),
    ]

    def run(self, sitename, ldap_url=None, sambaopts=None, credopts=None,
            versionopts=None):

        ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        try:
            site = Site.get(ldb, cn=sitename)
        except ModelError as e:
            raise CommandError(e)

        # Check if site exists first.
        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        # Display site as JSON.
        self.print_json(site.as_dict())


class cmd_sites_create(Command):
    """Create a new site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    def run(self, sitename, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        samdb = self.ldb_connect(H, sambaopts, credopts)

        samdb.transaction_start()
        try:
            sites.create_site(samdb, samdb.get_config_basedn(), sitename)
            samdb.transaction_commit()
        except sites.SiteAlreadyExistsException as e:
            samdb.transaction_cancel()
            raise CommandError("Error while creating site %s, error: %s" %
                               (sitename, str(e)))

        self.outf.write("Site %s created !\n" % sitename)


class cmd_sites_delete(Command):
    """Delete an existing site."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    def run(self, sitename, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        samdb = self.ldb_connect(H, sambaopts, credopts)

        samdb.transaction_start()
        try:
            sites.delete_site(samdb, samdb.get_config_basedn(), sitename)
            samdb.transaction_commit()
        except sites.SiteException as e:
            samdb.transaction_cancel()
            raise CommandError(
                "Error while removing site %s, error: %s" % (sitename, str(e)))

        self.outf.write("Site %s removed!\n" % sitename)


class cmd_sites_subnet_list(Command):
    """List subnets."""

    synopsis = "%prog <site> [options]"

    takes_args = ["sitename"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="ldap_url"),
        Option("--json", help="Output results in JSON format.",
               dest="output_format", action="store_const", const="json"),
    ]

    def run(self, sitename, ldap_url=None, sambaopts=None, credopts=None,
            versionopts=None, output_format=None):

        ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        try:
            site = Site.get(ldb, cn=sitename)
        except ModelError as e:
            raise CommandError(e)

        # Check if site exists first.
        if site is None:
            raise CommandError(f"Site {sitename} not found.")

        # subnets by cn.
        try:
            subnets_dict = {subnet.cn: subnet.as_dict()
                            for subnet in Subnet.query(ldb,
                                                       site_object=str(site.dn))}
        except ModelError as e:
            raise CommandError(e)

        # Using json output format gives more detail.
        if output_format == "json":
            self.print_json(subnets_dict)
        else:
            for subnet in subnets_dict.keys():
                self.outf.write(f"{subnet}\n")


class cmd_sites_subnet_view(Command):
    """View subnet details."""

    synopsis = "%prog <subnet> [options]"

    takes_args = ["subnetname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="ldap_url"),
    ]

    def run(self, subnetname, ldap_url=None, sambaopts=None, credopts=None,
            versionopts=None):

        ldb = self.ldb_connect(ldap_url, sambaopts, credopts)

        try:
            subnet = Subnet.get(ldb, cn=subnetname)
        except ModelError as e:
            raise CommandError(e)

        # Check if subnet exists first.
        if subnet is None:
            raise CommandError(f"Subnet {subnetname} not found.")

        # Display subnet as JSON.
        self.print_json(subnet.as_dict())


class cmd_sites_subnet_create(Command):
    """Create a new subnet."""
    synopsis = "%prog <subnet> <site-of-subnet> [options]"
    takes_args = ["subnetname", "site_of_subnet"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    def run(self, subnetname, site_of_subnet, H=None, sambaopts=None,
            credopts=None, versionopts=None):
        samdb = self.ldb_connect(H, sambaopts, credopts)

        samdb.transaction_start()
        try:
            subnets.create_subnet(samdb, samdb.get_config_basedn(), subnetname,
                                  site_of_subnet)
            samdb.transaction_commit()
        except subnets.SubnetException as e:
            samdb.transaction_cancel()
            raise CommandError("Error while creating subnet %s: %s" %
                               (subnetname, e))

        self.outf.write("Subnet %s created !\n" % subnetname)


class cmd_sites_subnet_delete(Command):
    """Delete an existing subnet."""

    synopsis = "%prog <subnet> [options]"

    takes_args = ["subnetname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    def run(self, subnetname, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        samdb = self.ldb_connect(H, sambaopts, credopts)

        samdb.transaction_start()
        try:
            subnets.delete_subnet(samdb, samdb.get_config_basedn(), subnetname)
            samdb.transaction_commit()
        except subnets.SubnetException as e:
            samdb.transaction_cancel()
            raise CommandError("Error while removing subnet %s, error: %s" %
                               (subnetname, e))

        self.outf.write("Subnet %s removed!\n" % subnetname)


class cmd_sites_subnet_set_site(Command):
    """Assign a subnet to a site."""
    synopsis = "%prog <subnet> <site-of-subnet> [options]"
    takes_args = ["subnetname", "site_of_subnet"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    def run(self, subnetname, site_of_subnet, H=None, sambaopts=None,
            credopts=None, versionopts=None):
        samdb = self.ldb_connect(H, sambaopts, credopts)

        samdb.transaction_start()
        try:
            subnets.set_subnet_site(samdb, samdb.get_config_basedn(),
                                    subnetname, site_of_subnet)
            samdb.transaction_commit()
        except subnets.SubnetException as e:
            samdb.transaction_cancel()
            raise CommandError("Error assigning subnet %s to site %s: %s" %
                               (subnetname, site_of_subnet, e))

        print(("Subnet %s shifted to site %s" %
               (subnetname, site_of_subnet)), file=self.outf)


class cmd_sites_subnet(SuperCommand):
    """Subnet management subcommands."""
    subcommands = {
        "create": cmd_sites_subnet_create(),
        "remove": cmd_sites_subnet_delete(),
        "list": cmd_sites_subnet_list(),
        "view": cmd_sites_subnet_view(),
        "set-site": cmd_sites_subnet_set_site(),
    }


class cmd_sites(SuperCommand):
    """Sites management."""
    subcommands = {}
    subcommands["list"] = cmd_sites_list()
    subcommands["view"] = cmd_sites_view()
    subcommands["create"] = cmd_sites_create()
    subcommands["remove"] = cmd_sites_delete()
    subcommands["subnet"] = cmd_sites_subnet()

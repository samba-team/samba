# domain management - domain provision
#
# Copyright Matthias Dieter Wallnoefer 2009
# Copyright Andrew Kroeger 2009
# Copyright Jelmer Vernooij 2007-2012
# Copyright Giampaolo Lauria 2011
# Copyright Matthieu Patou <mat@matws.net> 2011
# Copyright Andrew Bartlett 2008-2015
# Copyright Stefan Metzmacher 2012
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

import os
import sys
import tempfile

import samba
import samba.getopt as options
from samba.auth import system_session
from samba.auth_util import system_session_unix
from samba.dcerpc import security
from samba.dsdb import (
    DS_DOMAIN_FUNCTION_2000,
    DS_DOMAIN_FUNCTION_2003,
    DS_DOMAIN_FUNCTION_2008,
    DS_DOMAIN_FUNCTION_2008_R2,
    DS_DOMAIN_FUNCTION_2012,
    DS_DOMAIN_FUNCTION_2012_R2,
    DS_DOMAIN_FUNCTION_2016
)
from samba.netcmd import Command, CommandError, Option
from samba.provision import DEFAULT_MIN_PWD_LENGTH, ProvisioningError, provision
from samba.provision.common import FILL_DRS, FILL_FULL, FILL_NT4SYNC
from samba.samdb import get_default_backend_store
from samba import functional_level

from .common import common_ntvfs_options, common_provision_join_options


class cmd_domain_provision(Command):
    """Provision a domain."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("--interactive", help="Ask for names", action="store_true"),
        Option("--domain", type="string", metavar="DOMAIN",
               help="NetBIOS domain name to use"),
        Option("--domain-guid", type="string", metavar="GUID",
               help="set domainguid (otherwise random)"),
        Option("--domain-sid", type="string", metavar="SID",
               help="set domainsid (otherwise random)"),
        Option("--ntds-guid", type="string", metavar="GUID",
               help="set NTDS object GUID (otherwise random)"),
        Option("--invocationid", type="string", metavar="GUID",
               help="set invocationid (otherwise random)"),
        Option("--host-name", type="string", metavar="HOSTNAME",
               help="set hostname"),
        Option("--host-ip", type="string", metavar="IPADDRESS",
               help="set IPv4 ipaddress"),
        Option("--host-ip6", type="string", metavar="IP6ADDRESS",
               help="set IPv6 ipaddress"),
        Option("--site", type="string", metavar="SITENAME",
               help="set site name"),
        Option("--adminpass", type="string", metavar="PASSWORD",
               help="choose admin password (otherwise random)"),
        Option("--krbtgtpass", type="string", metavar="PASSWORD",
               help="choose krbtgt password (otherwise random)"),
        Option("--dns-backend", type="choice", metavar="NAMESERVER-BACKEND",
               choices=["SAMBA_INTERNAL", "BIND9_FLATFILE", "BIND9_DLZ", "NONE"],
               help="The DNS server backend. SAMBA_INTERNAL is the builtin name server (default), "
               "BIND9_FLATFILE uses bind9 text database to store zone information, "
               "BIND9_DLZ uses samba4 AD to store zone information, "
               "NONE skips the DNS setup entirely (not recommended)",
               default="SAMBA_INTERNAL"),
        Option("--dnspass", type="string", metavar="PASSWORD",
               help="choose dns password (otherwise random)"),
        Option("--root", type="string", metavar="USERNAME",
               help="choose 'root' unix username"),
        Option("--nobody", type="string", metavar="USERNAME",
               help="choose 'nobody' user"),
        Option("--users", type="string", metavar="GROUPNAME",
               help="choose 'users' group"),
        Option("--blank", action="store_true",
               help="do not add users or groups, just the structure"),
        Option("--server-role", type="choice", metavar="ROLE",
               choices=["domain controller", "dc", "member server", "member", "standalone"],
               help="The server role (domain controller | dc | member server | member | standalone). Default is dc.",
               default="domain controller"),
        Option("--function-level", type="choice", metavar="FOR-FUN-LEVEL",
               choices=["2000", "2003", "2008", "2008_R2", "2016"],
               help="The domain and forest function level (2000 | 2003 | 2008 | 2008_R2 - always native | 2016). Default is (Windows) 2008_R2 Native.",
               default="2008_R2"),
        Option("--base-schema", type="choice", metavar="BASE-SCHEMA",
               choices=["2008_R2", "2008_R2_old", "2012", "2012_R2", "2016", "2019"],
               help="The base schema files to use. Default is (Windows) 2019.",
               default="2019"),
        Option("--adprep-level", type="choice", metavar="FUNCTION_LEVEL",
               choices=["SKIP", "2008_R2", "2012", "2012_R2", "2016"],
               help="The highest functional level to prepare for. Default is based on --base-schema",
               default=None),
        Option("--next-rid", type="int", metavar="NEXTRID", default=1000,
               help="The initial nextRid value (only needed for upgrades).  Default is 1000."),
        Option("--partitions-only",
               help="Configure Samba's partitions, but do not modify them (ie, join a BDC)", action="store_true"),
        Option("--use-rfc2307", action="store_true", help="Use AD to store posix attributes (default = no)"),
    ]

    ntvfs_options = [
        Option("--use-xattrs", type="choice", choices=["yes", "no", "auto"],
               metavar="[yes|no|auto]",
               help="Define if we should use the native fs capabilities or a tdb file for "
               "storing attributes likes ntacl when --use-ntvfs is set. "
               "auto tries to make an inteligent guess based on the user rights and system capabilities",
               default="auto")
    ]

    takes_options.extend(common_provision_join_options)

    if samba.is_ntvfs_fileserver_built():
        takes_options.extend(common_ntvfs_options)
        takes_options.extend(ntvfs_options)

    takes_args = []

    def run(self, sambaopts=None, versionopts=None,
            interactive=None,
            domain=None,
            domain_guid=None,
            domain_sid=None,
            ntds_guid=None,
            invocationid=None,
            host_name=None,
            host_ip=None,
            host_ip6=None,
            adminpass=None,
            site=None,
            krbtgtpass=None,
            machinepass=None,
            dns_backend=None,
            dns_forwarder=None,
            dnspass=None,
            ldapadminpass=None,
            root=None,
            nobody=None,
            users=None,
            quiet=None,
            blank=None,
            server_role=None,
            function_level=None,
            adprep_level=None,
            next_rid=None,
            partitions_only=None,
            targetdir=None,
            use_xattrs="auto",
            use_ntvfs=False,
            use_rfc2307=None,
            base_schema=None,
            plaintext_secrets=False,
            backend_store=None,
            backend_store_size=None):

        self.logger = self.get_logger(name="provision", quiet=quiet)

        lp = sambaopts.get_loadparm()
        smbconf = lp.configfile

        if dns_forwarder is not None:
            suggested_forwarder = dns_forwarder
        else:
            suggested_forwarder = self._get_nameserver_ip()
            if suggested_forwarder is None:
                suggested_forwarder = "none"

        if not self.raw_argv:
            interactive = True

        if interactive:
            from getpass import getpass
            import socket

            def ask(prompt, default=None):
                if default is not None:
                    print("%s [%s]: " % (prompt, default), end=' ')
                else:
                    print("%s: " % (prompt,), end=' ')
                sys.stdout.flush()
                return sys.stdin.readline().rstrip("\n") or default

            try:
                default = socket.getfqdn().split(".", 1)[1].upper()
            except IndexError:
                default = None
            realm = ask("Realm", default)
            if realm in (None, ""):
                raise CommandError("No realm set!")

            try:
                default = realm.split(".")[0]
            except IndexError:
                default = None
            domain = ask("Domain", default)
            if domain is None:
                raise CommandError("No domain set!")

            server_role = ask("Server Role (dc, member, standalone)", "dc")

            dns_backend = ask("DNS backend (SAMBA_INTERNAL, BIND9_FLATFILE, BIND9_DLZ, NONE)", "SAMBA_INTERNAL")
            if dns_backend in (None, ''):
                raise CommandError("No DNS backend set!")

            if dns_backend == "SAMBA_INTERNAL":
                dns_forwarder = ask("DNS forwarder IP address (write 'none' to disable forwarding)", suggested_forwarder)
                if dns_forwarder.lower() in (None, 'none'):
                    suggested_forwarder = None
                    dns_forwarder = None

            while True:
                adminpassplain = getpass("Administrator password: ")
                issue = self._adminpass_issue(adminpassplain)
                if issue:
                    self.errf.write("%s.\n" % issue)
                else:
                    adminpassverify = getpass("Retype password: ")
                    if not adminpassplain == adminpassverify:
                        self.errf.write("Sorry, passwords do not match.\n")
                    else:
                        adminpass = adminpassplain
                        break

        else:
            realm = sambaopts._lp.get('realm')
            if realm is None:
                raise CommandError("No realm set!")
            if domain is None:
                raise CommandError("No domain set!")

        if adminpass:
            issue = self._adminpass_issue(adminpass)
            if issue:
                raise CommandError(issue)
        else:
            self.logger.info("Administrator password will be set randomly!")

        try:
            dom_for_fun_level = functional_level.string_to_level(function_level)
        except KeyError as e:
            raise CommandError(f"'{function_level}' is not a valid domain level")

        if adprep_level is None:
            # Select the adprep_level default based
            # on what the base schema premits
            if base_schema in ["2008_R2", "2008_R2_old"]:
                # without explicit --adprep-level=2008_R2
                # we will skip the adprep step on
                # provision
                adprep_level = "SKIP"
            elif base_schema in ["2012"]:
                adprep_level = "2012"
            elif base_schema in ["2012_R2"]:
                adprep_level = "2012_R2"
            else:
                adprep_level = "2016"

        if adprep_level == "SKIP":
            provision_adprep_level = None
        elif adprep_level == "2008R2":
            provision_adprep_level = DS_DOMAIN_FUNCTION_2008_R2
        elif adprep_level == "2012":
            provision_adprep_level = DS_DOMAIN_FUNCTION_2012
        elif adprep_level == "2012_R2":
            provision_adprep_level = DS_DOMAIN_FUNCTION_2012_R2
        elif adprep_level == "2016":
            provision_adprep_level = DS_DOMAIN_FUNCTION_2016

        if dns_backend == "SAMBA_INTERNAL" and dns_forwarder is None:
            dns_forwarder = suggested_forwarder

        samdb_fill = FILL_FULL
        if blank:
            samdb_fill = FILL_NT4SYNC
        elif partitions_only:
            samdb_fill = FILL_DRS

        if targetdir is not None:
            if not os.path.isdir(targetdir):
                os.makedirs(targetdir)

        eadb = True

        if use_xattrs == "yes":
            eadb = False
        elif use_xattrs == "auto" and use_ntvfs == False:
            eadb = False
        elif use_ntvfs == False:
            raise CommandError("--use-xattrs=no requires --use-ntvfs (not supported for production use).  "
                               "Please re-run with --use-xattrs omitted.")
        elif use_xattrs == "auto" and not lp.get("posix:eadb"):
            if targetdir:
                file = tempfile.NamedTemporaryFile(dir=os.path.abspath(targetdir))
            else:
                file = tempfile.NamedTemporaryFile(dir=os.path.abspath(os.path.dirname(lp.get("private dir"))))
            try:
                try:
                    samba.ntacls.setntacl(lp, file.name,
                                          "O:S-1-5-32G:S-1-5-32",
                                          "S-1-5-32",
                                          system_session_unix(),
                                          "native")
                    eadb = False
                except Exception:
                    self.logger.info("You are not root or your system does not support xattr, using tdb backend for attributes. ")
            finally:
                file.close()

        if eadb:
            self.logger.info("not using extended attributes to store ACLs and other metadata. If you intend to use this provision in production, rerun the script as root on a system supporting xattrs.")

        if domain_sid is not None:
            domain_sid = security.dom_sid(domain_sid)

        session = system_session()
        if backend_store is None:
            backend_store = get_default_backend_store()
        try:
            result = provision(self.logger,
                               session, smbconf=smbconf, targetdir=targetdir,
                               samdb_fill=samdb_fill, realm=realm, domain=domain,
                               domainguid=domain_guid, domainsid=domain_sid,
                               hostname=host_name,
                               hostip=host_ip, hostip6=host_ip6,
                               sitename=site, ntdsguid=ntds_guid,
                               invocationid=invocationid, adminpass=adminpass,
                               krbtgtpass=krbtgtpass, machinepass=machinepass,
                               dns_backend=dns_backend, dns_forwarder=dns_forwarder,
                               dnspass=dnspass, root=root, nobody=nobody,
                               users=users,
                               serverrole=server_role, dom_for_fun_level=dom_for_fun_level,
                               useeadb=eadb, next_rid=next_rid, lp=lp, use_ntvfs=use_ntvfs,
                               use_rfc2307=use_rfc2307, skip_sysvolacl=False,
                               base_schema=base_schema,
                               adprep_level=provision_adprep_level,
                               plaintext_secrets=plaintext_secrets,
                               backend_store=backend_store,
                               backend_store_size=backend_store_size)

        except ProvisioningError as e:
            raise CommandError("Provision failed", e)

        result.report_logger(self.logger)

    def _get_nameserver_ip(self):
        """Grab the nameserver IP address from /etc/resolv.conf."""
        from os import path
        RESOLV_CONF = "/etc/resolv.conf"

        if not path.isfile(RESOLV_CONF):
            self.logger.warning("Failed to locate %s" % RESOLV_CONF)
            return None

        handle = None
        try:
            handle = open(RESOLV_CONF, 'r')
            for line in handle:
                if not line.startswith('nameserver'):
                    continue
                # we want the last non-space continuous string of the line
                return line.strip().split()[-1]
        finally:
            if handle is not None:
                handle.close()

        self.logger.warning("No nameserver found in %s" % RESOLV_CONF)

    def _adminpass_issue(self, adminpass):
        """Returns error string for a bad administrator password,
        or None if acceptable"""
        if isinstance(adminpass, bytes):
            adminpass = adminpass.decode('utf8')
        if len(adminpass) < DEFAULT_MIN_PWD_LENGTH:
            return "Administrator password does not meet the default minimum" \
                " password length requirement (%d characters)" \
                % DEFAULT_MIN_PWD_LENGTH
        elif not samba.check_password_quality(adminpass):
            return "Administrator password does not meet the default" \
                " quality standards"
        else:
            return None

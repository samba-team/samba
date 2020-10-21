# domain management
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

from __future__ import print_function
from __future__ import division
import samba.getopt as options
import ldb
import os
import sys
import ctypes
import random
import tempfile
import logging
import subprocess
import time
import shutil
from samba import ntstatus
from samba import NTSTATUSError
from samba import werror
from getpass import getpass
from samba.net import Net, LIBNET_JOIN_AUTOMATIC
import samba.ntacls
from samba.join import join_RODC, join_DC
from samba.auth import system_session
from samba.samdb import SamDB, get_default_backend_store
from samba.ndr import ndr_pack, ndr_print
from samba.dcerpc import drsuapi
from samba.dcerpc import drsblobs
from samba.dcerpc import lsa
from samba.dcerpc import netlogon
from samba.dcerpc import security
from samba.dcerpc import nbt
from samba.dcerpc import misc
from samba.dcerpc.samr import DOMAIN_PASSWORD_COMPLEX, DOMAIN_PASSWORD_STORE_CLEARTEXT
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option
)
from samba.netcmd.fsmo import get_fsmo_roleowner
from samba.netcmd.common import netcmd_get_domain_infos_via_cldap
from samba.samba3 import Samba3
from samba.samba3 import param as s3param
from samba.upgrade import upgrade_from_samba3
from samba.drs_utils import drsuapi_connect
from samba import remove_dc, arcfour_encrypt, string_to_byte_array
from samba.auth_util import system_session_unix

from samba.dsdb import (
    DS_DOMAIN_FUNCTION_2000,
    DS_DOMAIN_FUNCTION_2003,
    DS_DOMAIN_FUNCTION_2003_MIXED,
    DS_DOMAIN_FUNCTION_2008,
    DS_DOMAIN_FUNCTION_2008_R2,
    DS_DOMAIN_FUNCTION_2012,
    DS_DOMAIN_FUNCTION_2012_R2,
    DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL,
    DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL,
    UF_WORKSTATION_TRUST_ACCOUNT,
    UF_SERVER_TRUST_ACCOUNT,
    UF_TRUSTED_FOR_DELEGATION,
    UF_PARTIAL_SECRETS_ACCOUNT
)

from samba.provision import (
    provision,
    ProvisioningError,
    DEFAULT_MIN_PWD_LENGTH,
    setup_path
)

from samba.provision.common import (
    FILL_FULL,
    FILL_NT4SYNC,
    FILL_DRS
)

from samba.netcmd.pso import cmd_domain_passwordsettings_pso
from samba.netcmd.domain_backup import cmd_domain_backup

from samba.compat import binary_type
from samba.compat import get_string

string_version_to_constant = {
    "2008_R2": DS_DOMAIN_FUNCTION_2008_R2,
    "2012": DS_DOMAIN_FUNCTION_2012,
    "2012_R2": DS_DOMAIN_FUNCTION_2012_R2,
}

common_provision_join_options = [
    Option("--machinepass", type="string", metavar="PASSWORD",
           help="choose machine password (otherwise random)"),
    Option("--plaintext-secrets", action="store_true",
           help="Store secret/sensitive values as plain text on disk" +
           "(default is to encrypt secret/ensitive values)"),
    Option("--backend-store", type="choice", metavar="BACKENDSTORE",
           choices=["tdb", "mdb"],
           help="Specify the database backend to be used "
           "(default is %s)" % get_default_backend_store()),
    Option("--backend-store-size", type="bytes", metavar="SIZE",
           help="Specify the size of the backend database, currently only " +
                "supported by lmdb backends (default is 8 Gb)."),
    Option("--targetdir", metavar="DIR",
           help="Set target directory (where to store provision)", type=str),
    Option("-q", "--quiet", help="Be quiet", action="store_true"),
]

common_join_options = [
    Option("--server", help="DC to join", type=str),
    Option("--site", help="site to join", type=str),
    Option("--domain-critical-only",
           help="only replicate critical domain objects",
           action="store_true"),
    Option("--dns-backend", type="choice", metavar="NAMESERVER-BACKEND",
           choices=["SAMBA_INTERNAL", "BIND9_DLZ", "NONE"],
           help="The DNS server backend. SAMBA_INTERNAL is the builtin name server (default), "
           "BIND9_DLZ uses samba4 AD to store zone information, "
           "NONE skips the DNS setup entirely (this DC will not be a DNS server)",
           default="SAMBA_INTERNAL"),
    Option("-v", "--verbose", help="Be verbose", action="store_true")
]

common_ntvfs_options = [
    Option("--use-ntvfs", help="Use NTVFS for the fileserver (default = no)",
           action="store_true")
]


def get_testparm_var(testparm, smbconf, varname):
    errfile = open(os.devnull, 'w')
    p = subprocess.Popen([testparm, '-s', '-l',
                          '--parameter-name=%s' % varname, smbconf],
                         stdout=subprocess.PIPE, stderr=errfile)
    (out, err) = p.communicate()
    errfile.close()
    lines = out.split(b'\n')
    if lines:
        return get_string(lines[0]).strip()
    return ""


try:
    import samba.dckeytab
except ImportError:
    cmd_domain_export_keytab = None
else:
    class cmd_domain_export_keytab(Command):
        """Dump Kerberos keys of the domain into a keytab."""

        synopsis = "%prog <keytab> [options]"

        takes_optiongroups = {
            "sambaopts": options.SambaOptions,
            "credopts": options.CredentialsOptions,
            "versionopts": options.VersionOptions,
        }

        takes_options = [
            Option("--principal", help="extract only this principal", type=str),
        ]

        takes_args = ["keytab"]

        def run(self, keytab, credopts=None, sambaopts=None, versionopts=None, principal=None):
            lp = sambaopts.get_loadparm()
            net = Net(None, lp)
            net.export_keytab(keytab=keytab, principal=principal)


class cmd_domain_info(Command):
    """Print basic info about a domain and the DC passed as parameter."""

    synopsis = "%prog <ip_address> [options]"

    takes_options = [
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_args = ["address"]

    def run(self, address, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        try:
            res = netcmd_get_domain_infos_via_cldap(lp, None, address)
        except RuntimeError:
            raise CommandError("Invalid IP address '" + address + "'!")
        self.outf.write("Forest           : %s\n" % res.forest)
        self.outf.write("Domain           : %s\n" % res.dns_domain)
        self.outf.write("Netbios domain   : %s\n" % res.domain_name)
        self.outf.write("DC name          : %s\n" % res.pdc_dns_name)
        self.outf.write("DC netbios name  : %s\n" % res.pdc_name)
        self.outf.write("Server site      : %s\n" % res.server_site)
        self.outf.write("Client site      : %s\n" % res.client_site)


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
               choices=["2000", "2003", "2008", "2008_R2"],
               help="The domain and forest function level (2000 | 2003 | 2008 | 2008_R2 - always native). Default is (Windows) 2008_R2 Native.",
               default="2008_R2"),
        Option("--base-schema", type="choice", metavar="BASE-SCHEMA",
               choices=["2008_R2", "2008_R2_old", "2012", "2012_R2"],
               help="The base schema files to use. Default is (Windows) 2012_R2.",
               default="2012_R2"),
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

        if len(self.raw_argv) == 1:
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

        if function_level == "2000":
            dom_for_fun_level = DS_DOMAIN_FUNCTION_2000
        elif function_level == "2003":
            dom_for_fun_level = DS_DOMAIN_FUNCTION_2003
        elif function_level == "2008":
            dom_for_fun_level = DS_DOMAIN_FUNCTION_2008
        elif function_level == "2008_R2":
            dom_for_fun_level = DS_DOMAIN_FUNCTION_2008_R2

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
        if isinstance(adminpass, binary_type):
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


class cmd_domain_dcpromo(Command):
    """Promote an existing domain member or NT4 PDC to an AD DC."""

    synopsis = "%prog <dnsdomain> [DC|RODC] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = []
    takes_options.extend(common_join_options)

    takes_options.extend(common_provision_join_options)

    if samba.is_ntvfs_fileserver_built():
        takes_options.extend(common_ntvfs_options)

    takes_args = ["domain", "role?"]

    def run(self, domain, role=None, sambaopts=None, credopts=None,
            versionopts=None, server=None, site=None, targetdir=None,
            domain_critical_only=False, machinepass=None,
            use_ntvfs=False, dns_backend=None,
            quiet=False, verbose=False, plaintext_secrets=False,
            backend_store=None, backend_store_size=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        net = Net(creds, lp, server=credopts.ipaddress)

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        netbios_name = lp.get("netbios name")

        if role is not None:
            role = role.upper()

        if role == "DC":
            join_DC(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                    site=site, netbios_name=netbios_name, targetdir=targetdir,
                    domain_critical_only=domain_critical_only,
                    machinepass=machinepass, use_ntvfs=use_ntvfs,
                    dns_backend=dns_backend,
                    promote_existing=True, plaintext_secrets=plaintext_secrets,
                    backend_store=backend_store,
                    backend_store_size=backend_store_size)
        elif role == "RODC":
            join_RODC(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                      site=site, netbios_name=netbios_name, targetdir=targetdir,
                      domain_critical_only=domain_critical_only,
                      machinepass=machinepass, use_ntvfs=use_ntvfs, dns_backend=dns_backend,
                      promote_existing=True, plaintext_secrets=plaintext_secrets,
                      backend_store=backend_store,
                      backend_store_size=backend_store_size)
        else:
            raise CommandError("Invalid role '%s' (possible values: DC, RODC)" % role)


class cmd_domain_join(Command):
    """Join domain as either member or backup domain controller."""

    synopsis = "%prog <dnsdomain> [DC|RODC|MEMBER] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    ntvfs_options = [
        Option(
            "--use-ntvfs", help="Use NTVFS for the fileserver (default = no)",
            action="store_true")
    ]

    takes_options = []
    takes_options.extend(common_join_options)
    takes_options.extend(common_provision_join_options)

    if samba.is_ntvfs_fileserver_built():
        takes_options.extend(ntvfs_options)

    takes_args = ["domain", "role?"]

    def run(self, domain, role=None, sambaopts=None, credopts=None,
            versionopts=None, server=None, site=None, targetdir=None,
            domain_critical_only=False, machinepass=None,
            use_ntvfs=False, dns_backend=None,
            quiet=False, verbose=False,
            plaintext_secrets=False,
            backend_store=None, backend_store_size=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        net = Net(creds, lp, server=credopts.ipaddress)

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        netbios_name = lp.get("netbios name")

        if role is not None:
            role = role.upper()

        if role is None or role == "MEMBER":
            (join_password, sid, domain_name) = net.join_member(
                domain, netbios_name, LIBNET_JOIN_AUTOMATIC,
                machinepass=machinepass)

            self.errf.write("Joined domain %s (%s)\n" % (domain_name, sid))
        elif role == "DC":
            join_DC(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                    site=site, netbios_name=netbios_name, targetdir=targetdir,
                    domain_critical_only=domain_critical_only,
                    machinepass=machinepass, use_ntvfs=use_ntvfs,
                    dns_backend=dns_backend,
                    plaintext_secrets=plaintext_secrets,
                    backend_store=backend_store,
                    backend_store_size=backend_store_size)
        elif role == "RODC":
            join_RODC(logger=logger, server=server, creds=creds, lp=lp, domain=domain,
                      site=site, netbios_name=netbios_name, targetdir=targetdir,
                      domain_critical_only=domain_critical_only,
                      machinepass=machinepass, use_ntvfs=use_ntvfs,
                      dns_backend=dns_backend,
                      plaintext_secrets=plaintext_secrets,
                      backend_store=backend_store,
                      backend_store_size=backend_store_size)
        else:
            raise CommandError("Invalid role '%s' (possible values: MEMBER, DC, RODC)" % role)


class cmd_domain_demote(Command):
    """Demote ourselves from the role of Domain Controller."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("--server", help="writable DC to write demotion changes on", type=str),
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--remove-other-dead-server", help="Dead DC (name or NTDS GUID) "
               "to remove ALL references to (rather than this DC)", type=str),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, sambaopts=None, credopts=None,
            versionopts=None, server=None,
            remove_other_dead_server=None, H=None,
            verbose=False, quiet=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        net = Net(creds, lp, server=credopts.ipaddress)

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        if remove_other_dead_server is not None:
            if server is not None:
                samdb = SamDB(url="ldap://%s" % server,
                              session_info=system_session(),
                              credentials=creds, lp=lp)
            else:
                samdb = SamDB(url=H, session_info=system_session(), credentials=creds, lp=lp)
            try:
                remove_dc.remove_dc(samdb, logger, remove_other_dead_server)
            except remove_dc.DemoteException as err:
                raise CommandError("Demote failed: %s" % err)
            return

        netbios_name = lp.get("netbios name")
        samdb = SamDB(url=H, session_info=system_session(), credentials=creds, lp=lp)
        if not server:
            res = samdb.search(expression='(&(objectClass=computer)(serverReferenceBL=*))', attrs=["dnsHostName", "name"])
            if (len(res) == 0):
                raise CommandError("Unable to search for servers")

            if (len(res) == 1):
                raise CommandError("You are the last server in the domain")

            server = None
            for e in res:
                if str(e["name"]).lower() != netbios_name.lower():
                    server = e["dnsHostName"]
                    break

        ntds_guid = samdb.get_ntds_GUID()
        msg = samdb.search(base=str(samdb.get_config_basedn()),
                           scope=ldb.SCOPE_SUBTREE, expression="(objectGUID=%s)" % ntds_guid,
                           attrs=['options'])
        if len(msg) == 0 or "options" not in msg[0]:
            raise CommandError("Failed to find options on %s" % ntds_guid)

        ntds_dn = msg[0].dn
        dsa_options = int(str(msg[0]['options']))

        res = samdb.search(expression="(fSMORoleOwner=%s)" % str(ntds_dn),
                           controls=["search_options:1:2"])

        if len(res) != 0:
            raise CommandError("Current DC is still the owner of %d role(s), "
                               "use the role command to transfer roles to "
                               "another DC" %
                               len(res))

        self.errf.write("Using %s as partner server for the demotion\n" %
                        server)
        (drsuapiBind, drsuapi_handle, supportedExtensions) = drsuapi_connect(server, lp, creds)

        self.errf.write("Deactivating inbound replication\n")

        nmsg = ldb.Message()
        nmsg.dn = msg[0].dn

        if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
            dsa_options |= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
            nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
            samdb.modify(nmsg)

            self.errf.write("Asking partner server %s to synchronize from us\n"
                            % server)
            for part in (samdb.get_schema_basedn(),
                         samdb.get_config_basedn(),
                         samdb.get_root_basedn()):
                nc = drsuapi.DsReplicaObjectIdentifier()
                nc.dn = str(part)

                req1 = drsuapi.DsReplicaSyncRequest1()
                req1.naming_context = nc
                req1.options = drsuapi.DRSUAPI_DRS_WRIT_REP
                req1.source_dsa_guid = misc.GUID(ntds_guid)

                try:
                    drsuapiBind.DsReplicaSync(drsuapi_handle, 1, req1)
                except RuntimeError as e1:
                    (werr, string) = e1.args
                    if werr == werror.WERR_DS_DRA_NO_REPLICA:
                        pass
                    else:
                        self.errf.write(
                            "Error while replicating out last local changes from '%s' for demotion, "
                            "re-enabling inbound replication\n" % part)
                        dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                        nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                        samdb.modify(nmsg)
                        raise CommandError("Error while sending a DsReplicaSync for partition '%s'" % str(part), string)
        try:
            remote_samdb = SamDB(url="ldap://%s" % server,
                                 session_info=system_session(),
                                 credentials=creds, lp=lp)

            self.errf.write("Changing userControl and container\n")
            res = remote_samdb.search(base=str(remote_samdb.domain_dn()),
                                      expression="(&(objectClass=user)(sAMAccountName=%s$))" %
                                      netbios_name.upper(),
                                      attrs=["userAccountControl"])
            dc_dn = res[0].dn
            uac = int(str(res[0]["userAccountControl"]))

        except Exception as e:
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication\n")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)
            raise CommandError("Error while changing account control", e)

        if (len(res) != 1):
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)
            raise CommandError("Unable to find object with samaccountName = %s$"
                               " in the remote dc" % netbios_name.upper())

        olduac = uac

        uac &= ~(UF_SERVER_TRUST_ACCOUNT |
                 UF_TRUSTED_FOR_DELEGATION |
                 UF_PARTIAL_SECRETS_ACCOUNT)
        uac |= UF_WORKSTATION_TRUST_ACCOUNT

        msg = ldb.Message()
        msg.dn = dc_dn

        msg["userAccountControl"] = ldb.MessageElement("%d" % uac,
                                                       ldb.FLAG_MOD_REPLACE,
                                                       "userAccountControl")
        try:
            remote_samdb.modify(msg)
        except Exception as e:
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)

            raise CommandError("Error while changing account control", e)

        parent = msg.dn.parent()
        dc_name = res[0].dn.get_rdn_value()
        rdn = "CN=%s" % dc_name

        # Let's move to the Computer container
        i = 0
        newrdn = str(rdn)

        computer_dn = ldb.Dn(remote_samdb, "CN=Computers,%s" % str(remote_samdb.domain_dn()))
        res = remote_samdb.search(base=computer_dn, expression=rdn, scope=ldb.SCOPE_ONELEVEL)

        if (len(res) != 0):
            res = remote_samdb.search(base=computer_dn, expression="%s-%d" % (rdn, i),
                                      scope=ldb.SCOPE_ONELEVEL)
            while(len(res) != 0 and i < 100):
                i = i + 1
                res = remote_samdb.search(base=computer_dn, expression="%s-%d" % (rdn, i),
                                          scope=ldb.SCOPE_ONELEVEL)

            if i == 100:
                if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                    self.errf.write(
                        "Error while demoting, re-enabling inbound replication\n")
                    dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                    nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                    samdb.modify(nmsg)

                msg = ldb.Message()
                msg.dn = dc_dn

                msg["userAccountControl"] = ldb.MessageElement("%d" % uac,
                                                               ldb.FLAG_MOD_REPLACE,
                                                               "userAccountControl")

                remote_samdb.modify(msg)

                raise CommandError("Unable to find a slot for renaming %s,"
                                   " all names from %s-1 to %s-%d seemed used" %
                                   (str(dc_dn), rdn, rdn, i - 9))

            newrdn = "%s-%d" % (rdn, i)

        try:
            newdn = ldb.Dn(remote_samdb, "%s,%s" % (newrdn, str(computer_dn)))
            remote_samdb.rename(dc_dn, newdn)
        except Exception as e:
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication\n")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)

            msg = ldb.Message()
            msg.dn = dc_dn

            msg["userAccountControl"] = ldb.MessageElement("%d" % uac,
                                                           ldb.FLAG_MOD_REPLACE,
                                                           "userAccountControl")

            remote_samdb.modify(msg)
            raise CommandError("Error while renaming %s to %s" % (str(dc_dn), str(newdn)), e)

        server_dsa_dn = samdb.get_serverName()
        domain = remote_samdb.get_root_basedn()

        try:
            req1 = drsuapi.DsRemoveDSServerRequest1()
            req1.server_dn = str(server_dsa_dn)
            req1.domain_dn = str(domain)
            req1.commit = 1

            drsuapiBind.DsRemoveDSServer(drsuapi_handle, 1, req1)
        except RuntimeError as e3:
            (werr, string) = e3.args
            if not (dsa_options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) and not samdb.am_rodc():
                self.errf.write(
                    "Error while demoting, re-enabling inbound replication\n")
                dsa_options ^= DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL
                nmsg["options"] = ldb.MessageElement(str(dsa_options), ldb.FLAG_MOD_REPLACE, "options")
                samdb.modify(nmsg)

            msg = ldb.Message()
            msg.dn = newdn

            msg["userAccountControl"] = ldb.MessageElement("%d" % uac,
                                                           ldb.FLAG_MOD_REPLACE,
                                                           "userAccountControl")
            remote_samdb.modify(msg)
            remote_samdb.rename(newdn, dc_dn)
            if werr == werror.WERR_DS_DRA_NO_REPLICA:
                raise CommandError("The DC %s is not present on (already "
                                   "removed from) the remote server: %s" %
                                   (server_dsa_dn, e3))
            else:
                raise CommandError("Error while sending a removeDsServer "
                                   "of %s: %s" %
                                   (server_dsa_dn, e3))

        remove_dc.remove_sysvol_references(remote_samdb, logger, dc_name)

        # These are objects under the computer account that should be deleted
        for s in ("CN=Enterprise,CN=NTFRS Subscriptions",
                  "CN=%s, CN=NTFRS Subscriptions" % lp.get("realm"),
                  "CN=Domain system Volumes (SYSVOL Share), CN=NTFRS Subscriptions",
                  "CN=NTFRS Subscriptions"):
            try:
                remote_samdb.delete(ldb.Dn(remote_samdb,
                                           "%s,%s" % (s, str(newdn))))
            except ldb.LdbError as l:
                pass

        # get dns host name for target server to demote, remove dns references
        remove_dc.remove_dns_references(remote_samdb, logger, samdb.host_dns_name(),
                                        ignore_no_name=True)

        self.errf.write("Demote successful\n")


class cmd_domain_level(Command):
    """Raise domain and forest function levels."""

    synopsis = "%prog (show|raise <options>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),  # unused
        Option("--forest-level", type="choice", choices=["2003", "2008", "2008_R2", "2012", "2012_R2"],
               help="The forest function level (2003 | 2008 | 2008_R2 | 2012 | 2012_R2)"),
        Option("--domain-level", type="choice", choices=["2003", "2008", "2008_R2", "2012", "2012_R2"],
               help="The domain function level (2003 | 2008 | 2008_R2 | 2012 | 2012_R2)")
    ]

    takes_args = ["subcommand"]

    def run(self, subcommand, H=None, forest_level=None, domain_level=None,
            quiet=False, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()

        res_forest = samdb.search("CN=Partitions,%s" % samdb.get_config_basedn(),
                                  scope=ldb.SCOPE_BASE, attrs=["msDS-Behavior-Version"])
        assert len(res_forest) == 1

        res_domain = samdb.search(domain_dn, scope=ldb.SCOPE_BASE,
                                  attrs=["msDS-Behavior-Version", "nTMixedDomain"])
        assert len(res_domain) == 1

        res_dc_s = samdb.search("CN=Sites,%s" % samdb.get_config_basedn(),
                                scope=ldb.SCOPE_SUBTREE, expression="(objectClass=nTDSDSA)",
                                attrs=["msDS-Behavior-Version"])
        assert len(res_dc_s) >= 1

        # default values, since "msDS-Behavior-Version" does not exist on Windows 2000 AD
        level_forest = DS_DOMAIN_FUNCTION_2000
        level_domain = DS_DOMAIN_FUNCTION_2000

        if "msDS-Behavior-Version" in res_forest[0]:
            level_forest = int(res_forest[0]["msDS-Behavior-Version"][0])
        if "msDS-Behavior-Version" in res_domain[0]:
            level_domain = int(res_domain[0]["msDS-Behavior-Version"][0])
        level_domain_mixed = int(res_domain[0]["nTMixedDomain"][0])

        min_level_dc = None
        for msg in res_dc_s:
            if "msDS-Behavior-Version" in msg:
                if min_level_dc is None or int(msg["msDS-Behavior-Version"][0]) < min_level_dc:
                    min_level_dc = int(msg["msDS-Behavior-Version"][0])
            else:
                min_level_dc = DS_DOMAIN_FUNCTION_2000
                # well, this is the least
                break

        if level_forest < DS_DOMAIN_FUNCTION_2000 or level_domain < DS_DOMAIN_FUNCTION_2000:
            raise CommandError("Domain and/or forest function level(s) is/are invalid. Correct them or reprovision!")
        if min_level_dc < DS_DOMAIN_FUNCTION_2000:
            raise CommandError("Lowest function level of a DC is invalid. Correct this or reprovision!")
        if level_forest > level_domain:
            raise CommandError("Forest function level is higher than the domain level(s). Correct this or reprovision!")
        if level_domain > min_level_dc:
            raise CommandError("Domain function level is higher than the lowest function level of a DC. Correct this or reprovision!")

        if subcommand == "show":
            self.message("Domain and forest function level for domain '%s'" % domain_dn)
            if level_forest == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed != 0:
                self.message("\nATTENTION: You run SAMBA 4 on a forest function level lower than Windows 2000 (Native). This isn't supported! Please raise!")
            if level_domain == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed != 0:
                self.message("\nATTENTION: You run SAMBA 4 on a domain function level lower than Windows 2000 (Native). This isn't supported! Please raise!")
            if min_level_dc == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed != 0:
                self.message("\nATTENTION: You run SAMBA 4 on a lowest function level of a DC lower than Windows 2003. This isn't supported! Please step-up or upgrade the concerning DC(s)!")

            self.message("")

            if level_forest == DS_DOMAIN_FUNCTION_2000:
                outstr = "2000"
            elif level_forest == DS_DOMAIN_FUNCTION_2003_MIXED:
                outstr = "2003 with mixed domains/interim (NT4 DC support)"
            elif level_forest == DS_DOMAIN_FUNCTION_2003:
                outstr = "2003"
            elif level_forest == DS_DOMAIN_FUNCTION_2008:
                outstr = "2008"
            elif level_forest == DS_DOMAIN_FUNCTION_2008_R2:
                outstr = "2008 R2"
            elif level_forest == DS_DOMAIN_FUNCTION_2012:
                outstr = "2012"
            elif level_forest == DS_DOMAIN_FUNCTION_2012_R2:
                outstr = "2012 R2"
            else:
                outstr = "higher than 2012 R2"
            self.message("Forest function level: (Windows) " + outstr)

            if level_domain == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed != 0:
                outstr = "2000 mixed (NT4 DC support)"
            elif level_domain == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed == 0:
                outstr = "2000"
            elif level_domain == DS_DOMAIN_FUNCTION_2003_MIXED:
                outstr = "2003 with mixed domains/interim (NT4 DC support)"
            elif level_domain == DS_DOMAIN_FUNCTION_2003:
                outstr = "2003"
            elif level_domain == DS_DOMAIN_FUNCTION_2008:
                outstr = "2008"
            elif level_domain == DS_DOMAIN_FUNCTION_2008_R2:
                outstr = "2008 R2"
            elif level_domain == DS_DOMAIN_FUNCTION_2012:
                outstr = "2012"
            elif level_domain == DS_DOMAIN_FUNCTION_2012_R2:
                outstr = "2012 R2"
            else:
                outstr = "higher than 2012 R2"
            self.message("Domain function level: (Windows) " + outstr)

            if min_level_dc == DS_DOMAIN_FUNCTION_2000:
                outstr = "2000"
            elif min_level_dc == DS_DOMAIN_FUNCTION_2003:
                outstr = "2003"
            elif min_level_dc == DS_DOMAIN_FUNCTION_2008:
                outstr = "2008"
            elif min_level_dc == DS_DOMAIN_FUNCTION_2008_R2:
                outstr = "2008 R2"
            elif min_level_dc == DS_DOMAIN_FUNCTION_2012:
                outstr = "2012"
            elif min_level_dc == DS_DOMAIN_FUNCTION_2012_R2:
                outstr = "2012 R2"
            else:
                outstr = "higher than 2012 R2"
            self.message("Lowest function level of a DC: (Windows) " + outstr)

        elif subcommand == "raise":
            msgs = []

            if domain_level is not None:
                if domain_level == "2003":
                    new_level_domain = DS_DOMAIN_FUNCTION_2003
                elif domain_level == "2008":
                    new_level_domain = DS_DOMAIN_FUNCTION_2008
                elif domain_level == "2008_R2":
                    new_level_domain = DS_DOMAIN_FUNCTION_2008_R2
                elif domain_level == "2012":
                    new_level_domain = DS_DOMAIN_FUNCTION_2012
                elif domain_level == "2012_R2":
                    new_level_domain = DS_DOMAIN_FUNCTION_2012_R2

                if new_level_domain <= level_domain and level_domain_mixed == 0:
                    raise CommandError("Domain function level can't be smaller than or equal to the actual one!")
                if new_level_domain > min_level_dc:
                    raise CommandError("Domain function level can't be higher than the lowest function level of a DC!")

                # Deactivate mixed/interim domain support
                if level_domain_mixed != 0:
                    # Directly on the base DN
                    m = ldb.Message()
                    m.dn = ldb.Dn(samdb, domain_dn)
                    m["nTMixedDomain"] = ldb.MessageElement("0",
                                                            ldb.FLAG_MOD_REPLACE, "nTMixedDomain")
                    samdb.modify(m)
                    # Under partitions
                    m = ldb.Message()
                    m.dn = ldb.Dn(samdb, "CN=" + lp.get("workgroup") + ",CN=Partitions,%s" % samdb.get_config_basedn())
                    m["nTMixedDomain"] = ldb.MessageElement("0",
                                                            ldb.FLAG_MOD_REPLACE, "nTMixedDomain")
                    try:
                        samdb.modify(m)
                    except ldb.LdbError as e:
                        (enum, emsg) = e.args
                        if enum != ldb.ERR_UNWILLING_TO_PERFORM:
                            raise

                # Directly on the base DN
                m = ldb.Message()
                m.dn = ldb.Dn(samdb, domain_dn)
                m["msDS-Behavior-Version"] = ldb.MessageElement(
                    str(new_level_domain), ldb.FLAG_MOD_REPLACE,
                    "msDS-Behavior-Version")
                samdb.modify(m)
                # Under partitions
                m = ldb.Message()
                m.dn = ldb.Dn(samdb, "CN=" + lp.get("workgroup")
                              + ",CN=Partitions,%s" % samdb.get_config_basedn())
                m["msDS-Behavior-Version"] = ldb.MessageElement(
                    str(new_level_domain), ldb.FLAG_MOD_REPLACE,
                    "msDS-Behavior-Version")
                try:
                    samdb.modify(m)
                except ldb.LdbError as e2:
                    (enum, emsg) = e2.args
                    if enum != ldb.ERR_UNWILLING_TO_PERFORM:
                        raise

                level_domain = new_level_domain
                msgs.append("Domain function level changed!")

            if forest_level is not None:
                if forest_level == "2003":
                    new_level_forest = DS_DOMAIN_FUNCTION_2003
                elif forest_level == "2008":
                    new_level_forest = DS_DOMAIN_FUNCTION_2008
                elif forest_level == "2008_R2":
                    new_level_forest = DS_DOMAIN_FUNCTION_2008_R2
                elif forest_level == "2012":
                    new_level_forest = DS_DOMAIN_FUNCTION_2012
                elif forest_level == "2012_R2":
                    new_level_forest = DS_DOMAIN_FUNCTION_2012_R2

                if new_level_forest <= level_forest:
                    raise CommandError("Forest function level can't be smaller than or equal to the actual one!")
                if new_level_forest > level_domain:
                    raise CommandError("Forest function level can't be higher than the domain function level(s). Please raise it/them first!")

                m = ldb.Message()
                m.dn = ldb.Dn(samdb, "CN=Partitions,%s" % samdb.get_config_basedn())
                m["msDS-Behavior-Version"] = ldb.MessageElement(
                    str(new_level_forest), ldb.FLAG_MOD_REPLACE,
                    "msDS-Behavior-Version")
                samdb.modify(m)
                msgs.append("Forest function level changed!")
            msgs.append("All changes applied successfully!")
            self.message("\n".join(msgs))
        else:
            raise CommandError("invalid argument: '%s' (choose from 'show', 'raise')" % subcommand)


# In MS AD, setting a timeout to '(never)' corresponds to this value
NEVER_TIMESTAMP = int(-0x8000000000000000)


def timestamp_to_mins(timestamp_str):
    """Converts a timestamp in -100 nanosecond units to minutes"""
    # treat a timestamp of 'never' the same as zero (this should work OK for
    # most settings, and it displays better than trying to convert
    # -0x8000000000000000 to minutes)
    if int(timestamp_str) == NEVER_TIMESTAMP:
        return 0
    else:
        return abs(int(timestamp_str)) / (1e7 * 60)


def timestamp_to_days(timestamp_str):
    """Converts a timestamp in -100 nanosecond units to days"""
    return timestamp_to_mins(timestamp_str) / (60 * 24)


class cmd_domain_passwordsettings_show(Command):
    """Display current password settings for the domain."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
          ]

    def run(self, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        res = samdb.search(domain_dn, scope=ldb.SCOPE_BASE,
                           attrs=["pwdProperties", "pwdHistoryLength", "minPwdLength",
                                  "minPwdAge", "maxPwdAge", "lockoutDuration", "lockoutThreshold",
                                  "lockOutObservationWindow"])
        assert(len(res) == 1)
        try:
            pwd_props = int(res[0]["pwdProperties"][0])
            pwd_hist_len = int(res[0]["pwdHistoryLength"][0])
            cur_min_pwd_len = int(res[0]["minPwdLength"][0])
            # ticks -> days
            cur_min_pwd_age = timestamp_to_days(res[0]["minPwdAge"][0])
            cur_max_pwd_age = timestamp_to_days(res[0]["maxPwdAge"][0])

            cur_account_lockout_threshold = int(res[0]["lockoutThreshold"][0])

            # ticks -> mins
            cur_account_lockout_duration = timestamp_to_mins(res[0]["lockoutDuration"][0])
            cur_reset_account_lockout_after = timestamp_to_mins(res[0]["lockOutObservationWindow"][0])
        except Exception as e:
            raise CommandError("Could not retrieve password properties!", e)

        self.message("Password information for domain '%s'" % domain_dn)
        self.message("")
        if pwd_props & DOMAIN_PASSWORD_COMPLEX != 0:
            self.message("Password complexity: on")
        else:
            self.message("Password complexity: off")
        if pwd_props & DOMAIN_PASSWORD_STORE_CLEARTEXT != 0:
            self.message("Store plaintext passwords: on")
        else:
            self.message("Store plaintext passwords: off")
        self.message("Password history length: %d" % pwd_hist_len)
        self.message("Minimum password length: %d" % cur_min_pwd_len)
        self.message("Minimum password age (days): %d" % cur_min_pwd_age)
        self.message("Maximum password age (days): %d" % cur_max_pwd_age)
        self.message("Account lockout duration (mins): %d" % cur_account_lockout_duration)
        self.message("Account lockout threshold (attempts): %d" % cur_account_lockout_threshold)
        self.message("Reset account lockout after (mins): %d" % cur_reset_account_lockout_after)


class cmd_domain_passwordsettings_set(Command):
    """Set password settings.

    Password complexity, password lockout policy, history length,
    minimum password length, the minimum and maximum password age) on
    a Samba AD DC server.

    Use against a Windows DC is possible, but group policy will override it.
    """

    synopsis = "%prog <options> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),  # unused
        Option("--complexity", type="choice", choices=["on", "off", "default"],
               help="The password complexity (on | off | default). Default is 'on'"),
        Option("--store-plaintext", type="choice", choices=["on", "off", "default"],
               help="Store plaintext passwords where account have 'store passwords with reversible encryption' set (on | off | default). Default is 'off'"),
        Option("--history-length",
               help="The password history length (<integer> | default).  Default is 24.", type=str),
        Option("--min-pwd-length",
               help="The minimum password length (<integer> | default).  Default is 7.", type=str),
        Option("--min-pwd-age",
               help="The minimum password age (<integer in days> | default).  Default is 1.", type=str),
        Option("--max-pwd-age",
               help="The maximum password age (<integer in days> | default).  Default is 43.", type=str),
        Option("--account-lockout-duration",
               help="The the length of time an account is locked out after exeeding the limit on bad password attempts (<integer in mins> | default).  Default is 30 mins.", type=str),
        Option("--account-lockout-threshold",
               help="The number of bad password attempts allowed before locking out the account (<integer> | default).  Default is 0 (never lock out).", type=str),
        Option("--reset-account-lockout-after",
               help="After this time is elapsed, the recorded number of attempts restarts from zero (<integer> | default).  Default is 30.", type=str),
    ]

    def run(self, H=None, min_pwd_age=None, max_pwd_age=None,
            quiet=False, complexity=None, store_plaintext=None, history_length=None,
            min_pwd_length=None, account_lockout_duration=None, account_lockout_threshold=None,
            reset_account_lockout_after=None, credopts=None, sambaopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        msgs = []
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, domain_dn)
        pwd_props = int(samdb.get_pwdProperties())

        # get the current password age settings
        max_pwd_age_ticks = samdb.get_maxPwdAge()
        min_pwd_age_ticks = samdb.get_minPwdAge()

        if complexity is not None:
            if complexity == "on" or complexity == "default":
                pwd_props = pwd_props | DOMAIN_PASSWORD_COMPLEX
                msgs.append("Password complexity activated!")
            elif complexity == "off":
                pwd_props = pwd_props & (~DOMAIN_PASSWORD_COMPLEX)
                msgs.append("Password complexity deactivated!")

        if store_plaintext is not None:
            if store_plaintext == "on" or store_plaintext == "default":
                pwd_props = pwd_props | DOMAIN_PASSWORD_STORE_CLEARTEXT
                msgs.append("Plaintext password storage for changed passwords activated!")
            elif store_plaintext == "off":
                pwd_props = pwd_props & (~DOMAIN_PASSWORD_STORE_CLEARTEXT)
                msgs.append("Plaintext password storage for changed passwords deactivated!")

        if complexity is not None or store_plaintext is not None:
            m["pwdProperties"] = ldb.MessageElement(str(pwd_props),
                                                    ldb.FLAG_MOD_REPLACE, "pwdProperties")

        if history_length is not None:
            if history_length == "default":
                pwd_hist_len = 24
            else:
                pwd_hist_len = int(history_length)

            if pwd_hist_len < 0 or pwd_hist_len > 24:
                raise CommandError("Password history length must be in the range of 0 to 24!")

            m["pwdHistoryLength"] = ldb.MessageElement(str(pwd_hist_len),
                                                       ldb.FLAG_MOD_REPLACE, "pwdHistoryLength")
            msgs.append("Password history length changed!")

        if min_pwd_length is not None:
            if min_pwd_length == "default":
                min_pwd_len = 7
            else:
                min_pwd_len = int(min_pwd_length)

            if min_pwd_len < 0 or min_pwd_len > 14:
                raise CommandError("Minimum password length must be in the range of 0 to 14!")

            m["minPwdLength"] = ldb.MessageElement(str(min_pwd_len),
                                                   ldb.FLAG_MOD_REPLACE, "minPwdLength")
            msgs.append("Minimum password length changed!")

        if min_pwd_age is not None:
            if min_pwd_age == "default":
                min_pwd_age = 1
            else:
                min_pwd_age = int(min_pwd_age)

            if min_pwd_age < 0 or min_pwd_age > 998:
                raise CommandError("Minimum password age must be in the range of 0 to 998!")

            # days -> ticks
            min_pwd_age_ticks = -int(min_pwd_age * (24 * 60 * 60 * 1e7))

            m["minPwdAge"] = ldb.MessageElement(str(min_pwd_age_ticks),
                                                ldb.FLAG_MOD_REPLACE, "minPwdAge")
            msgs.append("Minimum password age changed!")

        if max_pwd_age is not None:
            if max_pwd_age == "default":
                max_pwd_age = 43
            else:
                max_pwd_age = int(max_pwd_age)

            if max_pwd_age < 0 or max_pwd_age > 999:
                raise CommandError("Maximum password age must be in the range of 0 to 999!")

            # days -> ticks
            if max_pwd_age == 0:
                max_pwd_age_ticks = NEVER_TIMESTAMP
            else:
                max_pwd_age_ticks = -int(max_pwd_age * (24 * 60 * 60 * 1e7))

            m["maxPwdAge"] = ldb.MessageElement(str(max_pwd_age_ticks),
                                                ldb.FLAG_MOD_REPLACE, "maxPwdAge")
            msgs.append("Maximum password age changed!")

        if account_lockout_duration is not None:
            if account_lockout_duration == "default":
                account_lockout_duration = 30
            else:
                account_lockout_duration = int(account_lockout_duration)

            if account_lockout_duration < 0 or account_lockout_duration > 99999:
                raise CommandError("Maximum password age must be in the range of 0 to 99999!")

            # minutes -> ticks
            if account_lockout_duration == 0:
                account_lockout_duration_ticks = NEVER_TIMESTAMP
            else:
                account_lockout_duration_ticks = -int(account_lockout_duration * (60 * 1e7))

            m["lockoutDuration"] = ldb.MessageElement(str(account_lockout_duration_ticks),
                                                      ldb.FLAG_MOD_REPLACE, "lockoutDuration")
            msgs.append("Account lockout duration changed!")

        if account_lockout_threshold is not None:
            if account_lockout_threshold == "default":
                account_lockout_threshold = 0
            else:
                account_lockout_threshold = int(account_lockout_threshold)

            m["lockoutThreshold"] = ldb.MessageElement(str(account_lockout_threshold),
                                                       ldb.FLAG_MOD_REPLACE, "lockoutThreshold")
            msgs.append("Account lockout threshold changed!")

        if reset_account_lockout_after is not None:
            if reset_account_lockout_after == "default":
                reset_account_lockout_after = 30
            else:
                reset_account_lockout_after = int(reset_account_lockout_after)

            if reset_account_lockout_after < 0 or reset_account_lockout_after > 99999:
                raise CommandError("Maximum password age must be in the range of 0 to 99999!")

            # minutes -> ticks
            if reset_account_lockout_after == 0:
                reset_account_lockout_after_ticks = NEVER_TIMESTAMP
            else:
                reset_account_lockout_after_ticks = -int(reset_account_lockout_after * (60 * 1e7))

            m["lockOutObservationWindow"] = ldb.MessageElement(str(reset_account_lockout_after_ticks),
                                                               ldb.FLAG_MOD_REPLACE, "lockOutObservationWindow")
            msgs.append("Duration to reset account lockout after changed!")

        if max_pwd_age or min_pwd_age:
            # If we're setting either min or max password, make sure the max is
            # still greater overall. As either setting could be None, we use the
            # ticks here (which are always set) and work backwards.
            max_pwd_age = timestamp_to_days(max_pwd_age_ticks)
            min_pwd_age = timestamp_to_days(min_pwd_age_ticks)
            if max_pwd_age != 0 and min_pwd_age >= max_pwd_age:
                raise CommandError("Maximum password age (%d) must be greater than minimum password age (%d)!" % (max_pwd_age, min_pwd_age))

        if len(m) == 0:
            raise CommandError("You must specify at least one option to set. Try --help")
        samdb.modify(m)
        msgs.append("All changes applied successfully!")
        self.message("\n".join(msgs))


class cmd_domain_passwordsettings(SuperCommand):
    """Manage password policy settings."""

    subcommands = {}
    subcommands["pso"] = cmd_domain_passwordsettings_pso()
    subcommands["show"] = cmd_domain_passwordsettings_show()
    subcommands["set"] = cmd_domain_passwordsettings_set()


class cmd_domain_classicupgrade(Command):
    """Upgrade from Samba classic (NT4-like) database to Samba AD DC database.

    Specify either a directory with all Samba classic DC databases and state files (with --dbdir) or
    the testparm utility from your classic installation (with --testparm).
    """

    synopsis = "%prog [options] <classic_smb_conf>"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions
    }

    takes_options = [
        Option("--dbdir", type="string", metavar="DIR",
               help="Path to samba classic DC database directory"),
        Option("--testparm", type="string", metavar="PATH",
               help="Path to samba classic DC testparm utility from the previous installation.  This allows the default paths of the previous installation to be followed"),
        Option("--targetdir", type="string", metavar="DIR",
               help="Path prefix where the new Samba 4.0 AD domain should be initialised"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--dns-backend", type="choice", metavar="NAMESERVER-BACKEND",
               choices=["SAMBA_INTERNAL", "BIND9_FLATFILE", "BIND9_DLZ", "NONE"],
               help="The DNS server backend. SAMBA_INTERNAL is the builtin name server (default), "
               "BIND9_FLATFILE uses bind9 text database to store zone information, "
               "BIND9_DLZ uses samba4 AD to store zone information, "
               "NONE skips the DNS setup entirely (this DC will not be a DNS server)",
               default="SAMBA_INTERNAL")
    ]

    ntvfs_options = [
        Option("--use-xattrs", type="choice", choices=["yes", "no", "auto"],
               metavar="[yes|no|auto]",
               help="Define if we should use the native fs capabilities or a tdb file for "
               "storing attributes likes ntacl when --use-ntvfs is set. "
               "auto tries to make an inteligent guess based on the user rights and system capabilities",
               default="auto")
    ]
    if samba.is_ntvfs_fileserver_built():
        takes_options.extend(common_ntvfs_options)
        takes_options.extend(ntvfs_options)

    takes_args = ["smbconf"]

    def run(self, smbconf=None, targetdir=None, dbdir=None, testparm=None,
            quiet=False, verbose=False, use_xattrs="auto", sambaopts=None, versionopts=None,
            dns_backend=None, use_ntvfs=False):

        if not os.path.exists(smbconf):
            raise CommandError("File %s does not exist" % smbconf)

        if testparm and not os.path.exists(testparm):
            raise CommandError("Testparm utility %s does not exist" % testparm)

        if dbdir and not os.path.exists(dbdir):
            raise CommandError("Directory %s does not exist" % dbdir)

        if not dbdir and not testparm:
            raise CommandError("Please specify either dbdir or testparm")

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        if dbdir and testparm:
            logger.warning("both dbdir and testparm specified, ignoring dbdir.")
            dbdir = None

        lp = sambaopts.get_loadparm()

        s3conf = s3param.get_context()

        if sambaopts.realm:
            s3conf.set("realm", sambaopts.realm)

        if targetdir is not None:
            if not os.path.isdir(targetdir):
                os.mkdir(targetdir)

        eadb = True
        if use_xattrs == "yes":
            eadb = False
        elif use_xattrs == "auto" and use_ntvfs == False:
            eadb = False
        elif use_ntvfs == False:
            raise CommandError("--use-xattrs=no requires --use-ntvfs (not supported for production use).  "
                               "Please re-run with --use-xattrs omitted.")
        elif use_xattrs == "auto" and not s3conf.get("posix:eadb"):
            if targetdir:
                tmpfile = tempfile.NamedTemporaryFile(dir=os.path.abspath(targetdir))
            else:
                tmpfile = tempfile.NamedTemporaryFile(dir=os.path.abspath(os.path.dirname(lp.get("private dir"))))
            try:
                try:
                    samba.ntacls.setntacl(lp, tmpfile.name,
                                          "O:S-1-5-32G:S-1-5-32",
                                          "S-1-5-32",
                                          system_session_unix(),
                                          "native")
                    eadb = False
                except Exception:
                    # FIXME: Don't catch all exceptions here
                    logger.info("You are not root or your system does not support xattr, using tdb backend for attributes. "
                                "If you intend to use this provision in production, rerun the script as root on a system supporting xattrs.")
            finally:
                tmpfile.close()

        # Set correct default values from dbdir or testparm
        paths = {}
        if dbdir:
            paths["state directory"] = dbdir
            paths["private dir"] = dbdir
            paths["lock directory"] = dbdir
            paths["smb passwd file"] = dbdir + "/smbpasswd"
        else:
            paths["state directory"] = get_testparm_var(testparm, smbconf, "state directory")
            paths["private dir"] = get_testparm_var(testparm, smbconf, "private dir")
            paths["smb passwd file"] = get_testparm_var(testparm, smbconf, "smb passwd file")
            paths["lock directory"] = get_testparm_var(testparm, smbconf, "lock directory")
            # "testparm" from Samba 3 < 3.4.x is not aware of the parameter
            # "state directory", instead make use of "lock directory"
            if len(paths["state directory"]) == 0:
                paths["state directory"] = paths["lock directory"]

        for p in paths:
            s3conf.set(p, paths[p])

        # load smb.conf parameters
        logger.info("Reading smb.conf")
        s3conf.load(smbconf)
        samba3 = Samba3(smbconf, s3conf)

        logger.info("Provisioning")
        upgrade_from_samba3(samba3, logger, targetdir, session_info=system_session(),
                            useeadb=eadb, dns_backend=dns_backend, use_ntvfs=use_ntvfs)


class cmd_domain_samba3upgrade(cmd_domain_classicupgrade):
    __doc__ = cmd_domain_classicupgrade.__doc__

    # This command is present for backwards compatibility only,
    # and should not be shown.

    hidden = True


class LocalDCCredentialsOptions(options.CredentialsOptions):
    def __init__(self, parser):
        options.CredentialsOptions.__init__(self, parser, special_name="local-dc")


class DomainTrustCommand(Command):
    """List domain trusts."""

    def __init__(self):
        Command.__init__(self)
        self.local_lp = None

        self.local_server = None
        self.local_binding_string = None
        self.local_creds = None

        self.remote_server = None
        self.remote_binding_string = None
        self.remote_creds = None

    def _uint32(self, v):
        return ctypes.c_uint32(v).value

    def check_runtime_error(self, runtime, val):
        if runtime is None:
            return False

        err32 = self._uint32(runtime.args[0])
        if err32 == val:
            return True

        return False

    class LocalRuntimeError(CommandError):
        def __init__(exception_self, self, runtime, message):
            err32 = self._uint32(runtime.args[0])
            errstr = runtime.args[1]
            msg = "LOCAL_DC[%s]: %s - ERROR(0x%08X) - %s" % (
                  self.local_server, message, err32, errstr)
            CommandError.__init__(exception_self, msg)

    class RemoteRuntimeError(CommandError):
        def __init__(exception_self, self, runtime, message):
            err32 = self._uint32(runtime.args[0])
            errstr = runtime.args[1]
            msg = "REMOTE_DC[%s]: %s - ERROR(0x%08X) - %s" % (
                  self.remote_server, message, err32, errstr)
            CommandError.__init__(exception_self, msg)

    class LocalLdbError(CommandError):
        def __init__(exception_self, self, ldb_error, message):
            errval = ldb_error.args[0]
            errstr = ldb_error.args[1]
            msg = "LOCAL_DC[%s]: %s - ERROR(%d) - %s" % (
                  self.local_server, message, errval, errstr)
            CommandError.__init__(exception_self, msg)

    def setup_local_server(self, sambaopts, localdcopts):
        if self.local_server is not None:
            return self.local_server

        lp = sambaopts.get_loadparm()

        local_server = localdcopts.ipaddress
        if local_server is None:
            server_role = lp.server_role()
            if server_role != "ROLE_ACTIVE_DIRECTORY_DC":
                raise CommandError("Invalid server_role %s" % (server_role))
            local_server = lp.get('netbios name')
            local_transport = "ncalrpc"
            local_binding_options = ""
            local_binding_options += ",auth_type=ncalrpc_as_system"
            local_ldap_url = None
            local_creds = None
        else:
            local_transport = "ncacn_np"
            local_binding_options = ""
            local_ldap_url = "ldap://%s" % local_server
            local_creds = localdcopts.get_credentials(lp)

        self.local_lp = lp

        self.local_server = local_server
        self.local_binding_string = "%s:%s[%s]" % (local_transport, local_server, local_binding_options)
        self.local_ldap_url = local_ldap_url
        self.local_creds = local_creds
        return self.local_server

    def new_local_lsa_connection(self):
        return lsa.lsarpc(self.local_binding_string, self.local_lp, self.local_creds)

    def new_local_netlogon_connection(self):
        return netlogon.netlogon(self.local_binding_string, self.local_lp, self.local_creds)

    def new_local_ldap_connection(self):
        return SamDB(url=self.local_ldap_url,
                     session_info=system_session(),
                     credentials=self.local_creds,
                     lp=self.local_lp)

    def setup_remote_server(self, credopts, domain,
                            require_pdc=True,
                            require_writable=True):

        if require_pdc:
            assert require_writable

        if self.remote_server is not None:
            return self.remote_server

        self.remote_server = "__unknown__remote_server__.%s" % domain
        assert self.local_server is not None

        remote_creds = credopts.get_credentials(self.local_lp)
        remote_server = credopts.ipaddress
        remote_binding_options = ""

        # TODO: we should also support NT4 domains
        # we could use local_netlogon.netr_DsRGetDCNameEx2() with the remote domain name
        # and delegate NBT or CLDAP to the local netlogon server
        try:
            remote_net = Net(remote_creds, self.local_lp, server=remote_server)
            remote_flags = nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS
            if require_writable:
                remote_flags |= nbt.NBT_SERVER_WRITABLE
            if require_pdc:
                remote_flags |= nbt.NBT_SERVER_PDC
            remote_info = remote_net.finddc(flags=remote_flags, domain=domain, address=remote_server)
        except NTSTATUSError as error:
            raise CommandError("Failed to find a writeable DC for domain '%s': %s" %
                               (domain, error.args[1]))
        except Exception:
            raise CommandError("Failed to find a writeable DC for domain '%s'" % domain)
        flag_map = {
            nbt.NBT_SERVER_PDC: "PDC",
            nbt.NBT_SERVER_GC: "GC",
            nbt.NBT_SERVER_LDAP: "LDAP",
            nbt.NBT_SERVER_DS: "DS",
            nbt.NBT_SERVER_KDC: "KDC",
            nbt.NBT_SERVER_TIMESERV: "TIMESERV",
            nbt.NBT_SERVER_CLOSEST: "CLOSEST",
            nbt.NBT_SERVER_WRITABLE: "WRITABLE",
            nbt.NBT_SERVER_GOOD_TIMESERV: "GOOD_TIMESERV",
            nbt.NBT_SERVER_NDNC: "NDNC",
            nbt.NBT_SERVER_SELECT_SECRET_DOMAIN_6: "SELECT_SECRET_DOMAIN_6",
            nbt.NBT_SERVER_FULL_SECRET_DOMAIN_6: "FULL_SECRET_DOMAIN_6",
            nbt.NBT_SERVER_ADS_WEB_SERVICE: "ADS_WEB_SERVICE",
            nbt.NBT_SERVER_DS_8: "DS_8",
            nbt.NBT_SERVER_HAS_DNS_NAME: "HAS_DNS_NAME",
            nbt.NBT_SERVER_IS_DEFAULT_NC: "IS_DEFAULT_NC",
            nbt.NBT_SERVER_FOREST_ROOT: "FOREST_ROOT",
        }
        server_type_string = self.generic_bitmap_to_string(flag_map,
                                                           remote_info.server_type, names_only=True)
        self.outf.write("RemoteDC Netbios[%s] DNS[%s] ServerType[%s]\n" % (
                        remote_info.pdc_name,
                        remote_info.pdc_dns_name,
                        server_type_string))

        self.remote_server = remote_info.pdc_dns_name
        self.remote_binding_string = "ncacn_np:%s[%s]" % (self.remote_server, remote_binding_options)
        self.remote_creds = remote_creds
        return self.remote_server

    def new_remote_lsa_connection(self):
        return lsa.lsarpc(self.remote_binding_string, self.local_lp, self.remote_creds)

    def new_remote_netlogon_connection(self):
        return netlogon.netlogon(self.remote_binding_string, self.local_lp, self.remote_creds)

    def get_lsa_info(self, conn, policy_access):
        objectAttr = lsa.ObjectAttribute()
        objectAttr.sec_qos = lsa.QosInfo()

        policy = conn.OpenPolicy2(b''.decode('utf-8'),
                                  objectAttr, policy_access)

        info = conn.QueryInfoPolicy2(policy, lsa.LSA_POLICY_INFO_DNS)

        return (policy, info)

    def get_netlogon_dc_unc(self, conn, server, domain):
        try:
            info = conn.netr_DsRGetDCNameEx2(server,
                                             None, 0, None, None, None,
                                             netlogon.DS_RETURN_DNS_NAME)
            return info.dc_unc
        except RuntimeError:
            return conn.netr_GetDcName(server, domain)

    def get_netlogon_dc_info(self, conn, server):
        info = conn.netr_DsRGetDCNameEx2(server,
                                         None, 0, None, None, None,
                                         netlogon.DS_RETURN_DNS_NAME)
        return info

    def netr_DomainTrust_to_name(self, t):
        if t.trust_type == lsa.LSA_TRUST_TYPE_DOWNLEVEL:
            return t.netbios_name

        return t.dns_name

    def netr_DomainTrust_to_type(self, a, t):
        primary = None
        primary_parent = None
        for _t in a:
            if _t.trust_flags & netlogon.NETR_TRUST_FLAG_PRIMARY:
                primary = _t
                if not _t.trust_flags & netlogon.NETR_TRUST_FLAG_TREEROOT:
                    primary_parent = a[_t.parent_index]
                break

        if t.trust_flags & netlogon.NETR_TRUST_FLAG_IN_FOREST:
            if t is primary_parent:
                return "Parent"

            if t.trust_flags & netlogon.NETR_TRUST_FLAG_TREEROOT:
                return "TreeRoot"

            parent = a[t.parent_index]
            if parent is primary:
                return "Child"

            return "Shortcut"

        if t.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            return "Forest"

        return "External"

    def netr_DomainTrust_to_transitive(self, t):
        if t.trust_flags & netlogon.NETR_TRUST_FLAG_IN_FOREST:
            return "Yes"

        if t.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE:
            return "No"

        if t.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            return "Yes"

        return "No"

    def netr_DomainTrust_to_direction(self, t):
        if t.trust_flags & netlogon.NETR_TRUST_FLAG_INBOUND and \
           t.trust_flags & netlogon.NETR_TRUST_FLAG_OUTBOUND:
            return "BOTH"

        if t.trust_flags & netlogon.NETR_TRUST_FLAG_INBOUND:
            return "INCOMING"

        if t.trust_flags & netlogon.NETR_TRUST_FLAG_OUTBOUND:
            return "OUTGOING"

        return "INVALID"

    def generic_enum_to_string(self, e_dict, v, names_only=False):
        try:
            w = e_dict[v]
        except KeyError:
            v32 = self._uint32(v)
            w = "__unknown__%08X__" % v32

        r = "0x%x (%s)" % (v, w)
        return r

    def generic_bitmap_to_string(self, b_dict, v, names_only=False):

        s = []

        c = v
        for b in sorted(b_dict.keys()):
            if not (c & b):
                continue
            c &= ~b
            s += [b_dict[b]]

        if c != 0:
            c32 = self._uint32(c)
            s += ["__unknown_%08X__" % c32]

        w = ",".join(s)
        if names_only:
            return w
        r = "0x%x (%s)" % (v, w)
        return r

    def trustType_string(self, v):
        types = {
            lsa.LSA_TRUST_TYPE_DOWNLEVEL: "DOWNLEVEL",
            lsa.LSA_TRUST_TYPE_UPLEVEL: "UPLEVEL",
            lsa.LSA_TRUST_TYPE_MIT: "MIT",
            lsa.LSA_TRUST_TYPE_DCE: "DCE",
        }
        return self.generic_enum_to_string(types, v)

    def trustDirection_string(self, v):
        directions = {
            lsa.LSA_TRUST_DIRECTION_INBOUND |
            lsa.LSA_TRUST_DIRECTION_OUTBOUND: "BOTH",
            lsa.LSA_TRUST_DIRECTION_INBOUND: "INBOUND",
            lsa.LSA_TRUST_DIRECTION_OUTBOUND: "OUTBOUND",
        }
        return self.generic_enum_to_string(directions, v)

    def trustAttributes_string(self, v):
        attributes = {
            lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE: "NON_TRANSITIVE",
            lsa.LSA_TRUST_ATTRIBUTE_UPLEVEL_ONLY: "UPLEVEL_ONLY",
            lsa.LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN: "QUARANTINED_DOMAIN",
            lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE: "FOREST_TRANSITIVE",
            lsa.LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION: "CROSS_ORGANIZATION",
            lsa.LSA_TRUST_ATTRIBUTE_WITHIN_FOREST: "WITHIN_FOREST",
            lsa.LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL: "TREAT_AS_EXTERNAL",
            lsa.LSA_TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION: "USES_RC4_ENCRYPTION",
        }
        return self.generic_bitmap_to_string(attributes, v)

    def kerb_EncTypes_string(self, v):
        enctypes = {
            security.KERB_ENCTYPE_DES_CBC_CRC: "DES_CBC_CRC",
            security.KERB_ENCTYPE_DES_CBC_MD5: "DES_CBC_MD5",
            security.KERB_ENCTYPE_RC4_HMAC_MD5: "RC4_HMAC_MD5",
            security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96: "AES128_CTS_HMAC_SHA1_96",
            security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96: "AES256_CTS_HMAC_SHA1_96",
            security.KERB_ENCTYPE_FAST_SUPPORTED: "FAST_SUPPORTED",
            security.KERB_ENCTYPE_COMPOUND_IDENTITY_SUPPORTED: "COMPOUND_IDENTITY_SUPPORTED",
            security.KERB_ENCTYPE_CLAIMS_SUPPORTED: "CLAIMS_SUPPORTED",
            security.KERB_ENCTYPE_RESOURCE_SID_COMPRESSION_DISABLED: "RESOURCE_SID_COMPRESSION_DISABLED",
        }
        return self.generic_bitmap_to_string(enctypes, v)

    def entry_tln_status(self, e_flags, ):
        if e_flags == 0:
            return "Status[Enabled]"

        flags = {
            lsa.LSA_TLN_DISABLED_NEW: "Disabled-New",
            lsa.LSA_TLN_DISABLED_ADMIN: "Disabled",
            lsa.LSA_TLN_DISABLED_CONFLICT: "Disabled-Conflicting",
        }
        return "Status[%s]" % self.generic_bitmap_to_string(flags, e_flags, names_only=True)

    def entry_dom_status(self, e_flags):
        if e_flags == 0:
            return "Status[Enabled]"

        flags = {
            lsa.LSA_SID_DISABLED_ADMIN: "Disabled-SID",
            lsa.LSA_SID_DISABLED_CONFLICT: "Disabled-SID-Conflicting",
            lsa.LSA_NB_DISABLED_ADMIN: "Disabled-NB",
            lsa.LSA_NB_DISABLED_CONFLICT: "Disabled-NB-Conflicting",
        }
        return "Status[%s]" % self.generic_bitmap_to_string(flags, e_flags, names_only=True)

    def write_forest_trust_info(self, fti, tln=None, collisions=None):
        if tln is not None:
            tln_string = " TDO[%s]" % tln
        else:
            tln_string = ""

        self.outf.write("Namespaces[%d]%s:\n" % (
                        len(fti.entries), tln_string))

        for i, e in enumerate(fti.entries):

            flags = e.flags
            collision_string = ""

            if collisions is not None:
                for c in collisions.entries:
                    if c.index != i:
                        continue
                    flags = c.flags
                    collision_string = " Collision[%s]" % (c.name.string)

            d = e.forest_trust_data
            if e.type == lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                self.outf.write("TLN: %-32s DNS[*.%s]%s\n" % (
                                self.entry_tln_status(flags),
                                d.string, collision_string))
            elif e.type == lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
                self.outf.write("TLN_EX: %-29s DNS[*.%s]\n" % (
                                "", d.string))
            elif e.type == lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                self.outf.write("DOM: %-32s DNS[%s] Netbios[%s] SID[%s]%s\n" % (
                                self.entry_dom_status(flags),
                                d.dns_domain_name.string,
                                d.netbios_domain_name.string,
                                d.domain_sid, collision_string))
        return


class cmd_domain_trust_list(DomainTrustCommand):
    """List domain trusts."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
    ]

    def run(self, sambaopts=None, versionopts=None, localdcopts=None):

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_netlogon = self.new_local_netlogon_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

        try:
            local_netlogon_trusts = \
                local_netlogon.netr_DsrEnumerateDomainTrusts(local_server,
                                                             netlogon.NETR_TRUST_FLAG_IN_FOREST |
                                                             netlogon.NETR_TRUST_FLAG_OUTBOUND |
                                                             netlogon.NETR_TRUST_FLAG_INBOUND)
        except RuntimeError as error:
            if self.check_runtime_error(error, werror.WERR_RPC_S_PROCNUM_OUT_OF_RANGE):
                # TODO: we could implement a fallback to lsa.EnumTrustDom()
                raise CommandError("LOCAL_DC[%s]: netr_DsrEnumerateDomainTrusts not supported." % (
                                   self.local_server))
            raise self.LocalRuntimeError(self, error, "netr_DsrEnumerateDomainTrusts failed")

        a = local_netlogon_trusts.array
        for t in a:
            if t.trust_flags & netlogon.NETR_TRUST_FLAG_PRIMARY:
                continue
            self.outf.write("%-14s %-15s %-19s %s\n" % (
                            "Type[%s]" % self.netr_DomainTrust_to_type(a, t),
                            "Transitive[%s]" % self.netr_DomainTrust_to_transitive(t),
                            "Direction[%s]" % self.netr_DomainTrust_to_direction(t),
                            "Name[%s]" % self.netr_DomainTrust_to_name(t)))
        return


class cmd_domain_trust_show(DomainTrustCommand):
    """Show trusted domain details."""

    synopsis = "%prog NAME [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, versionopts=None, localdcopts=None):

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
            (local_policy, local_lsa_info) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        lsaString = lsa.String()
        lsaString.string = domain
        try:
            local_tdo_full = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
            local_tdo_info = local_tdo_full.info_ex
            local_tdo_posix = local_tdo_full.posix_offset
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise CommandError("trusted domain object does not exist for domain [%s]" % domain)

            raise self.LocalRuntimeError(self, error, "QueryTrustedDomainInfoByName(FULL_INFO) failed")

        try:
            local_tdo_enctypes = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES)
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_INVALID_PARAMETER):
                error = None
            if self.check_runtime_error(error, ntstatus.NT_STATUS_INVALID_INFO_CLASS):
                error = None

            if error is not None:
                raise self.LocalRuntimeError(self, error,
                                             "QueryTrustedDomainInfoByName(SUPPORTED_ENCRYPTION_TYPES) failed")

            local_tdo_enctypes = lsa.TrustDomainInfoSupportedEncTypes()
            local_tdo_enctypes.enc_types = 0

        try:
            local_tdo_forest = None
            if local_tdo_info.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
                local_tdo_forest = \
                    local_lsa.lsaRQueryForestTrustInformation(local_policy,
                                                              lsaString,
                                                              lsa.LSA_FOREST_TRUST_DOMAIN_INFO)
        except RuntimeError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE):
                error = None
            if self.check_runtime_error(error, ntstatus.NT_STATUS_NOT_FOUND):
                error = None
            if error is not None:
                raise self.LocalRuntimeError(self, error, "lsaRQueryForestTrustInformation failed")

            local_tdo_forest = lsa.ForestTrustInformation()
            local_tdo_forest.count = 0
            local_tdo_forest.entries = []

        self.outf.write("TrustedDomain:\n\n")
        self.outf.write("NetbiosName:    %s\n" % local_tdo_info.netbios_name.string)
        if local_tdo_info.netbios_name.string != local_tdo_info.domain_name.string:
            self.outf.write("DnsName:        %s\n" % local_tdo_info.domain_name.string)
        self.outf.write("SID:            %s\n" % local_tdo_info.sid)
        self.outf.write("Type:           %s\n" % self.trustType_string(local_tdo_info.trust_type))
        self.outf.write("Direction:      %s\n" % self.trustDirection_string(local_tdo_info.trust_direction))
        self.outf.write("Attributes:     %s\n" % self.trustAttributes_string(local_tdo_info.trust_attributes))
        posix_offset_u32 = ctypes.c_uint32(local_tdo_posix.posix_offset).value
        posix_offset_i32 = ctypes.c_int32(local_tdo_posix.posix_offset).value
        self.outf.write("PosixOffset:    0x%08X (%d)\n" % (posix_offset_u32, posix_offset_i32))
        self.outf.write("kerb_EncTypes:  %s\n" % self.kerb_EncTypes_string(local_tdo_enctypes.enc_types))

        if local_tdo_info.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            self.write_forest_trust_info(local_tdo_forest,
                                         tln=local_tdo_info.domain_name.string)

        return


class cmd_domain_trust_create(DomainTrustCommand):
    """Create a domain or forest trust."""

    synopsis = "%prog DOMAIN [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--type", type="choice", metavar="TYPE",
               choices=["external", "forest"],
               help="The type of the trust: 'external' or 'forest'.",
               dest='trust_type',
               default="external"),
        Option("--direction", type="choice", metavar="DIRECTION",
               choices=["incoming", "outgoing", "both"],
               help="The trust direction: 'incoming', 'outgoing' or 'both'.",
               dest='trust_direction',
               default="both"),
        Option("--create-location", type="choice", metavar="LOCATION",
               choices=["local", "both"],
               help="Where to create the trusted domain object: 'local' or 'both'.",
               dest='create_location',
               default="both"),
        Option("--cross-organisation", action="store_true",
               help="The related domains does not belong to the same organisation.",
               dest='cross_organisation',
               default=False),
        Option("--quarantined", type="choice", metavar="yes|no",
               choices=["yes", "no", None],
               help="Special SID filtering rules are applied to the trust. "
                    "With --type=external the default is yes. "
                    "With --type=forest the default is no.",
               dest='quarantined_arg',
               default=None),
        Option("--not-transitive", action="store_true",
               help="The forest trust is not transitive.",
               dest='not_transitive',
               default=False),
        Option("--treat-as-external", action="store_true",
               help="The treat the forest trust as external.",
               dest='treat_as_external',
               default=False),
        Option("--no-aes-keys", action="store_false",
               help="The trust uses aes kerberos keys.",
               dest='use_aes_keys',
               default=True),
        Option("--skip-validation", action="store_false",
               help="Skip validation of the trust.",
               dest='validate',
               default=True),
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, localdcopts=None, credopts=None, versionopts=None,
            trust_type=None, trust_direction=None, create_location=None,
            cross_organisation=False, quarantined_arg=None,
            not_transitive=False, treat_as_external=False,
            use_aes_keys=False, validate=True):

        lsaString = lsa.String()

        quarantined = False
        if quarantined_arg is None:
            if trust_type == 'external':
                quarantined = True
        elif quarantined_arg == 'yes':
            quarantined = True

        if trust_type != 'forest':
            if not_transitive:
                raise CommandError("--not-transitive requires --type=forest")
            if treat_as_external:
                raise CommandError("--treat-as-external requires --type=forest")

        enc_types = None
        if use_aes_keys:
            enc_types = lsa.TrustDomainInfoSupportedEncTypes()
            enc_types.enc_types = security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
            enc_types.enc_types |= security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96

        local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
        local_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN
        local_policy_access |= lsa.LSA_POLICY_CREATE_SECRET

        local_trust_info = lsa.TrustDomainInfoInfoEx()
        local_trust_info.trust_type = lsa.LSA_TRUST_TYPE_UPLEVEL
        local_trust_info.trust_direction = 0
        if trust_direction == "both":
            local_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_INBOUND
            local_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
        elif trust_direction == "incoming":
            local_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_INBOUND
        elif trust_direction == "outgoing":
            local_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
        local_trust_info.trust_attributes = 0
        if cross_organisation:
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION
        if quarantined:
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
        if trust_type == "forest":
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE
        if not_transitive:
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE
        if treat_as_external:
            local_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL

        def get_password(name):
            password = None
            while True:
                if password is not None and password != '':
                    return password
                password = getpass("New %s Password: " % name)
                passwordverify = getpass("Retype %s Password: " % name)
                if not password == passwordverify:
                    password = None
                    self.outf.write("Sorry, passwords do not match.\n")

        incoming_secret = None
        outgoing_secret = None
        remote_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
        if create_location == "local":
            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_INBOUND:
                incoming_password = get_password("Incoming Trust")
                incoming_secret = string_to_byte_array(incoming_password.encode('utf-16-le'))
            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_OUTBOUND:
                outgoing_password = get_password("Outgoing Trust")
                outgoing_secret = string_to_byte_array(outgoing_password.encode('utf-16-le'))

            remote_trust_info = None
        else:
            # We use 240 random bytes.
            # Windows uses 28 or 240 random bytes. I guess it's
            # based on the trust type external vs. forest.
            #
            # The initial trust password can be up to 512 bytes
            # while the versioned passwords used for periodic updates
            # can only be up to 498 bytes, as netr_ServerPasswordSet2()
            # needs to pass the NL_PASSWORD_VERSION structure within the
            # 512 bytes and a 2 bytes confounder is required.
            #
            def random_trust_secret(length):
                pw = samba.generate_random_machine_password(length // 2, length // 2)
                return string_to_byte_array(pw.encode('utf-16-le'))

            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_INBOUND:
                incoming_secret = random_trust_secret(240)
            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_OUTBOUND:
                outgoing_secret = random_trust_secret(240)

            remote_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN
            remote_policy_access |= lsa.LSA_POLICY_CREATE_SECRET

            remote_trust_info = lsa.TrustDomainInfoInfoEx()
            remote_trust_info.trust_type = lsa.LSA_TRUST_TYPE_UPLEVEL
            remote_trust_info.trust_direction = 0
            if trust_direction == "both":
                remote_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_INBOUND
                remote_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
            elif trust_direction == "incoming":
                remote_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
            elif trust_direction == "outgoing":
                remote_trust_info.trust_direction |= lsa.LSA_TRUST_DIRECTION_INBOUND
            remote_trust_info.trust_attributes = 0
            if cross_organisation:
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION
            if quarantined:
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
            if trust_type == "forest":
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE
            if not_transitive:
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE
            if treat_as_external:
                remote_trust_info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            (local_policy, local_lsa_info) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        try:
            remote_server = self.setup_remote_server(credopts, domain)
        except RuntimeError as error:
            raise self.RemoteRuntimeError(self, error, "failed to locate remote server")

        try:
            remote_lsa = self.new_remote_lsa_connection()
        except RuntimeError as error:
            raise self.RemoteRuntimeError(self, error, "failed to connect lsa server")

        try:
            (remote_policy, remote_lsa_info) = self.get_lsa_info(remote_lsa, remote_policy_access)
        except RuntimeError as error:
            raise self.RemoteRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("RemoteDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        remote_lsa_info.name.string,
                        remote_lsa_info.dns_domain.string,
                        remote_lsa_info.sid))

        local_trust_info.domain_name.string = remote_lsa_info.dns_domain.string
        local_trust_info.netbios_name.string = remote_lsa_info.name.string
        local_trust_info.sid = remote_lsa_info.sid

        if remote_trust_info:
            remote_trust_info.domain_name.string = local_lsa_info.dns_domain.string
            remote_trust_info.netbios_name.string = local_lsa_info.name.string
            remote_trust_info.sid = local_lsa_info.sid

        try:
            lsaString.string = local_trust_info.domain_name.string
            local_old_netbios = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
            raise CommandError("TrustedDomain %s already exist'" % lsaString.string)
        except NTSTATUSError as error:
            if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise self.LocalRuntimeError(self, error,
                                             "QueryTrustedDomainInfoByName(%s, FULL_INFO) failed" % (
                                                 lsaString.string))

        try:
            lsaString.string = local_trust_info.netbios_name.string
            local_old_dns = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
            raise CommandError("TrustedDomain %s already exist'" % lsaString.string)
        except NTSTATUSError as error:
            if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise self.LocalRuntimeError(self, error,
                                             "QueryTrustedDomainInfoByName(%s, FULL_INFO) failed" % (
                                                 lsaString.string))

        if remote_trust_info:
            try:
                lsaString.string = remote_trust_info.domain_name.string
                remote_old_netbios = \
                    remote_lsa.QueryTrustedDomainInfoByName(remote_policy,
                                                            lsaString,
                                                            lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
                raise CommandError("TrustedDomain %s already exist'" % lsaString.string)
            except NTSTATUSError as error:
                if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                    raise self.RemoteRuntimeError(self, error,
                                                  "QueryTrustedDomainInfoByName(%s, FULL_INFO) failed" % (
                                                      lsaString.string))

            try:
                lsaString.string = remote_trust_info.netbios_name.string
                remote_old_dns = \
                    remote_lsa.QueryTrustedDomainInfoByName(remote_policy,
                                                            lsaString,
                                                            lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
                raise CommandError("TrustedDomain %s already exist'" % lsaString.string)
            except NTSTATUSError as error:
                if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                    raise self.RemoteRuntimeError(self, error,
                                                  "QueryTrustedDomainInfoByName(%s, FULL_INFO) failed" % (
                                                      lsaString.string))

        try:
            local_netlogon = self.new_local_netlogon_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

        try:
            local_netlogon_info = self.get_netlogon_dc_info(local_netlogon, local_server)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to get netlogon dc info")

        if remote_trust_info:
            try:
                remote_netlogon = self.new_remote_netlogon_connection()
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to connect netlogon server")

            try:
                remote_netlogon_dc_unc = self.get_netlogon_dc_unc(remote_netlogon,
                                                                  remote_server, domain)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to get netlogon dc info")

        def generate_AuthInOutBlob(secret, update_time):
            if secret is None:
                blob = drsblobs.trustAuthInOutBlob()
                blob.count = 0

                return blob

            clear = drsblobs.AuthInfoClear()
            clear.size = len(secret)
            clear.password = secret

            info = drsblobs.AuthenticationInformation()
            info.LastUpdateTime = samba.unix2nttime(update_time)
            info.AuthType = lsa.TRUST_AUTH_TYPE_CLEAR
            info.AuthInfo = clear

            array = drsblobs.AuthenticationInformationArray()
            array.count = 1
            array.array = [info]

            blob = drsblobs.trustAuthInOutBlob()
            blob.count = 1
            blob.current = array

            return blob

        def generate_AuthInfoInternal(session_key, incoming=None, outgoing=None):
            confounder = [0] * 512
            for i in range(len(confounder)):
                confounder[i] = random.randint(0, 255)

            trustpass = drsblobs.trustDomainPasswords()

            trustpass.confounder = confounder
            trustpass.outgoing = outgoing
            trustpass.incoming = incoming

            trustpass_blob = ndr_pack(trustpass)

            encrypted_trustpass = arcfour_encrypt(session_key, trustpass_blob)

            auth_blob = lsa.DATA_BUF2()
            auth_blob.size = len(encrypted_trustpass)
            auth_blob.data = string_to_byte_array(encrypted_trustpass)

            auth_info = lsa.TrustDomainInfoAuthInfoInternal()
            auth_info.auth_blob = auth_blob

            return auth_info

        update_time = samba.current_unix_time()
        incoming_blob = generate_AuthInOutBlob(incoming_secret, update_time)
        outgoing_blob = generate_AuthInOutBlob(outgoing_secret, update_time)

        local_tdo_handle = None
        remote_tdo_handle = None

        local_auth_info = generate_AuthInfoInternal(local_lsa.session_key,
                                                    incoming=incoming_blob,
                                                    outgoing=outgoing_blob)
        if remote_trust_info:
            remote_auth_info = generate_AuthInfoInternal(remote_lsa.session_key,
                                                         incoming=outgoing_blob,
                                                         outgoing=incoming_blob)

        try:
            if remote_trust_info:
                self.outf.write("Creating remote TDO.\n")
                current_request = {"location": "remote", "name": "CreateTrustedDomainEx2"}
                remote_tdo_handle = \
                    remote_lsa.CreateTrustedDomainEx2(remote_policy,
                                                      remote_trust_info,
                                                      remote_auth_info,
                                                      lsa.LSA_TRUSTED_DOMAIN_ALL_ACCESS)
                self.outf.write("Remote TDO created.\n")
                if enc_types:
                    self.outf.write("Setting supported encryption types on remote TDO.\n")
                    current_request = {"location": "remote", "name": "SetInformationTrustedDomain"}
                    remote_lsa.SetInformationTrustedDomain(remote_tdo_handle,
                                                           lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES,
                                                           enc_types)

            self.outf.write("Creating local TDO.\n")
            current_request = {"location": "local", "name": "CreateTrustedDomainEx2"}
            local_tdo_handle = local_lsa.CreateTrustedDomainEx2(local_policy,
                                                                local_trust_info,
                                                                local_auth_info,
                                                                lsa.LSA_TRUSTED_DOMAIN_ALL_ACCESS)
            self.outf.write("Local TDO created\n")
            if enc_types:
                self.outf.write("Setting supported encryption types on local TDO.\n")
                current_request = {"location": "local", "name": "SetInformationTrustedDomain"}
                local_lsa.SetInformationTrustedDomain(local_tdo_handle,
                                                      lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES,
                                                      enc_types)
        except RuntimeError as error:
            self.outf.write("Error: %s failed %sly - cleaning up\n" % (
                            current_request['name'], current_request['location']))
            if remote_tdo_handle:
                self.outf.write("Deleting remote TDO.\n")
                remote_lsa.DeleteObject(remote_tdo_handle)
                remote_tdo_handle = None
            if local_tdo_handle:
                self.outf.write("Deleting local TDO.\n")
                local_lsa.DeleteObject(local_tdo_handle)
                local_tdo_handle = None
            if current_request['location'] == "remote":
                raise self.RemoteRuntimeError(self, error, "%s" % (
                                              current_request['name']))
            raise self.LocalRuntimeError(self, error, "%s" % (
                                         current_request['name']))

        if validate:
            if local_trust_info.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
                self.outf.write("Setup local forest trust information...\n")
                try:
                    # get all information about the remote trust
                    # this triggers netr_GetForestTrustInformation to the remote domain
                    # and lsaRSetForestTrustInformation() locally, but new top level
                    # names are disabled by default.
                    local_forest_info = \
                        local_netlogon.netr_DsRGetForestTrustInformation(local_netlogon_info.dc_unc,
                                                                         remote_lsa_info.dns_domain.string,
                                                                         netlogon.DS_GFTI_UPDATE_TDO)
                except RuntimeError as error:
                    raise self.LocalRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

                try:
                    # here we try to enable all top level names
                    local_forest_collision = \
                        local_lsa.lsaRSetForestTrustInformation(local_policy,
                                                                remote_lsa_info.dns_domain,
                                                                lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                                                                local_forest_info,
                                                                0)
                except RuntimeError as error:
                    raise self.LocalRuntimeError(self, error, "lsaRSetForestTrustInformation() failed")

                self.write_forest_trust_info(local_forest_info,
                                             tln=remote_lsa_info.dns_domain.string,
                                             collisions=local_forest_collision)

                if remote_trust_info:
                    self.outf.write("Setup remote forest trust information...\n")
                    try:
                        # get all information about the local trust (from the perspective of the remote domain)
                        # this triggers netr_GetForestTrustInformation to our domain.
                        # and lsaRSetForestTrustInformation() remotely, but new top level
                        # names are disabled by default.
                        remote_forest_info = \
                            remote_netlogon.netr_DsRGetForestTrustInformation(remote_netlogon_dc_unc,
                                                                              local_lsa_info.dns_domain.string,
                                                                              netlogon.DS_GFTI_UPDATE_TDO)
                    except RuntimeError as error:
                        raise self.RemoteRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

                    try:
                        # here we try to enable all top level names
                        remote_forest_collision = \
                            remote_lsa.lsaRSetForestTrustInformation(remote_policy,
                                                                     local_lsa_info.dns_domain,
                                                                     lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                                                                     remote_forest_info,
                                                                     0)
                    except RuntimeError as error:
                        raise self.RemoteRuntimeError(self, error, "lsaRSetForestTrustInformation() failed")

                    self.write_forest_trust_info(remote_forest_info,
                                                 tln=local_lsa_info.dns_domain.string,
                                                 collisions=remote_forest_collision)

            if local_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_OUTBOUND:
                self.outf.write("Validating outgoing trust...\n")
                try:
                    local_trust_verify = local_netlogon.netr_LogonControl2Ex(local_netlogon_info.dc_unc,
                                                                             netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                                                             2,
                                                                             remote_lsa_info.dns_domain.string)
                except RuntimeError as error:
                    raise self.LocalRuntimeError(self, error, "NETLOGON_CONTROL_TC_VERIFY failed")

                local_trust_status = self._uint32(local_trust_verify.pdc_connection_status[0])
                local_conn_status = self._uint32(local_trust_verify.tc_connection_status[0])

                if local_trust_verify.flags & netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
                    local_validation = "LocalValidation: DC[%s] CONNECTION[%s] TRUST[%s] VERIFY_STATUS_RETURNED" % (
                                       local_trust_verify.trusted_dc_name,
                                       local_trust_verify.tc_connection_status[1],
                                       local_trust_verify.pdc_connection_status[1])
                else:
                    local_validation = "LocalValidation: DC[%s] CONNECTION[%s] TRUST[%s]" % (
                                       local_trust_verify.trusted_dc_name,
                                       local_trust_verify.tc_connection_status[1],
                                       local_trust_verify.pdc_connection_status[1])

                if local_trust_status != werror.WERR_SUCCESS or local_conn_status != werror.WERR_SUCCESS:
                    raise CommandError(local_validation)
                else:
                    self.outf.write("OK: %s\n" % local_validation)

            if remote_trust_info:
                if remote_trust_info.trust_direction & lsa.LSA_TRUST_DIRECTION_OUTBOUND:
                    self.outf.write("Validating incoming trust...\n")
                    try:
                        remote_trust_verify = \
                            remote_netlogon.netr_LogonControl2Ex(remote_netlogon_dc_unc,
                                                                 netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                                                 2,
                                                                 local_lsa_info.dns_domain.string)
                    except RuntimeError as error:
                        raise self.RemoteRuntimeError(self, error, "NETLOGON_CONTROL_TC_VERIFY failed")

                    remote_trust_status = self._uint32(remote_trust_verify.pdc_connection_status[0])
                    remote_conn_status = self._uint32(remote_trust_verify.tc_connection_status[0])

                    if remote_trust_verify.flags & netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
                        remote_validation = "RemoteValidation: DC[%s] CONNECTION[%s] TRUST[%s] VERIFY_STATUS_RETURNED" % (
                                           remote_trust_verify.trusted_dc_name,
                                           remote_trust_verify.tc_connection_status[1],
                                           remote_trust_verify.pdc_connection_status[1])
                    else:
                        remote_validation = "RemoteValidation: DC[%s] CONNECTION[%s] TRUST[%s]" % (
                                           remote_trust_verify.trusted_dc_name,
                                           remote_trust_verify.tc_connection_status[1],
                                           remote_trust_verify.pdc_connection_status[1])

                    if remote_trust_status != werror.WERR_SUCCESS or remote_conn_status != werror.WERR_SUCCESS:
                        raise CommandError(remote_validation)
                    else:
                        self.outf.write("OK: %s\n" % remote_validation)

        if remote_tdo_handle is not None:
            try:
                remote_lsa.Close(remote_tdo_handle)
            except RuntimeError as error:
                pass
            remote_tdo_handle = None
        if local_tdo_handle is not None:
            try:
                local_lsa.Close(local_tdo_handle)
            except RuntimeError as error:
                pass
            local_tdo_handle = None

        self.outf.write("Success.\n")
        return


class cmd_domain_trust_delete(DomainTrustCommand):
    """Delete a domain trust."""

    synopsis = "%prog DOMAIN [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--delete-location", type="choice", metavar="LOCATION",
               choices=["local", "both"],
               help="Where to delete the trusted domain object: 'local' or 'both'.",
               dest='delete_location',
               default="both"),
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, localdcopts=None, credopts=None, versionopts=None,
            delete_location=None):

        local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
        local_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN
        local_policy_access |= lsa.LSA_POLICY_CREATE_SECRET

        if delete_location == "local":
            remote_policy_access = None
        else:
            remote_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
            remote_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN
            remote_policy_access |= lsa.LSA_POLICY_CREATE_SECRET

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            (local_policy, local_lsa_info) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        local_tdo_info = None
        local_tdo_handle = None
        remote_tdo_info = None
        remote_tdo_handle = None

        lsaString = lsa.String()
        try:
            lsaString.string = domain
            local_tdo_info = local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                                    lsaString, lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise CommandError("Failed to find trust for domain '%s'" % domain)
            raise self.RemoteRuntimeError(self, error, "failed to locate remote server")

        if remote_policy_access is not None:
            try:
                remote_server = self.setup_remote_server(credopts, domain)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to locate remote server")

            try:
                remote_lsa = self.new_remote_lsa_connection()
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to connect lsa server")

            try:
                (remote_policy, remote_lsa_info) = self.get_lsa_info(remote_lsa, remote_policy_access)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

            self.outf.write("RemoteDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                            remote_lsa_info.name.string,
                            remote_lsa_info.dns_domain.string,
                            remote_lsa_info.sid))

            if remote_lsa_info.sid != local_tdo_info.sid or \
               remote_lsa_info.name.string != local_tdo_info.netbios_name.string or \
               remote_lsa_info.dns_domain.string != local_tdo_info.domain_name.string:
                raise CommandError("LocalTDO inconsistend: Netbios[%s] DNS[%s] SID[%s]" % (
                                   local_tdo_info.netbios_name.string,
                                   local_tdo_info.domain_name.string,
                                   local_tdo_info.sid))

            try:
                lsaString.string = local_lsa_info.dns_domain.string
                remote_tdo_info = \
                    remote_lsa.QueryTrustedDomainInfoByName(remote_policy,
                                                            lsaString,
                                                            lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
            except NTSTATUSError as error:
                if not self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                    raise self.RemoteRuntimeError(self, error, "QueryTrustedDomainInfoByName(%s)" % (
                                                  lsaString.string))
                pass

            if remote_tdo_info is not None:
                if local_lsa_info.sid != remote_tdo_info.sid or \
                   local_lsa_info.name.string != remote_tdo_info.netbios_name.string or \
                   local_lsa_info.dns_domain.string != remote_tdo_info.domain_name.string:
                    raise CommandError("RemoteTDO inconsistend: Netbios[%s] DNS[%s] SID[%s]" % (
                                       remote_tdo_info.netbios_name.string,
                                       remote_tdo_info.domain_name.string,
                                       remote_tdo_info.sid))

        if local_tdo_info is not None:
            try:
                lsaString.string = local_tdo_info.domain_name.string
                local_tdo_handle = \
                    local_lsa.OpenTrustedDomainByName(local_policy,
                                                      lsaString,
                                                      security.SEC_STD_DELETE)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "OpenTrustedDomainByName(%s)" % (
                                             lsaString.string))

            local_lsa.DeleteObject(local_tdo_handle)
            local_tdo_handle = None

        if remote_tdo_info is not None:
            try:
                lsaString.string = remote_tdo_info.domain_name.string
                remote_tdo_handle = \
                    remote_lsa.OpenTrustedDomainByName(remote_policy,
                                                       lsaString,
                                                       security.SEC_STD_DELETE)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "OpenTrustedDomainByName(%s)" % (
                                              lsaString.string))

        if remote_tdo_handle is not None:
            try:
                remote_lsa.DeleteObject(remote_tdo_handle)
                remote_tdo_handle = None
                self.outf.write("RemoteTDO deleted.\n")
            except RuntimeError as error:
                self.outf.write("%s\n" % self.RemoteRuntimeError(self, error, "DeleteObject() failed"))

        if local_tdo_handle is not None:
            try:
                local_lsa.DeleteObject(local_tdo_handle)
                local_tdo_handle = None
                self.outf.write("LocalTDO deleted.\n")
            except RuntimeError as error:
                self.outf.write("%s\n" % self.LocalRuntimeError(self, error, "DeleteObject() failed"))

        return


class cmd_domain_trust_validate(DomainTrustCommand):
    """Validate a domain trust."""

    synopsis = "%prog DOMAIN [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--validate-location", type="choice", metavar="LOCATION",
               choices=["local", "both"],
               help="Where to validate the trusted domain object: 'local' or 'both'.",
               dest='validate_location',
               default="both"),
    ]

    takes_args = ["domain"]

    def run(self, domain, sambaopts=None, versionopts=None, credopts=None, localdcopts=None,
            validate_location=None):

        local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            (local_policy, local_lsa_info) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        try:
            lsaString = lsa.String()
            lsaString.string = domain
            local_tdo_info = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise CommandError("trusted domain object does not exist for domain [%s]" % domain)

            raise self.LocalRuntimeError(self, error, "QueryTrustedDomainInfoByName(INFO_EX) failed")

        self.outf.write("LocalTDO Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_tdo_info.netbios_name.string,
                        local_tdo_info.domain_name.string,
                        local_tdo_info.sid))

        try:
            local_netlogon = self.new_local_netlogon_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

        try:
            local_trust_verify = \
                local_netlogon.netr_LogonControl2Ex(local_server,
                                                    netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                                    2,
                                                    local_tdo_info.domain_name.string)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "NETLOGON_CONTROL_TC_VERIFY failed")

        local_trust_status = self._uint32(local_trust_verify.pdc_connection_status[0])
        local_conn_status = self._uint32(local_trust_verify.tc_connection_status[0])

        if local_trust_verify.flags & netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
            local_validation = "LocalValidation: DC[%s] CONNECTION[%s] TRUST[%s] VERIFY_STATUS_RETURNED" % (
                               local_trust_verify.trusted_dc_name,
                               local_trust_verify.tc_connection_status[1],
                               local_trust_verify.pdc_connection_status[1])
        else:
            local_validation = "LocalValidation: DC[%s] CONNECTION[%s] TRUST[%s]" % (
                               local_trust_verify.trusted_dc_name,
                               local_trust_verify.tc_connection_status[1],
                               local_trust_verify.pdc_connection_status[1])

        if local_trust_status != werror.WERR_SUCCESS or local_conn_status != werror.WERR_SUCCESS:
            raise CommandError(local_validation)
        else:
            self.outf.write("OK: %s\n" % local_validation)

        try:
            server = local_trust_verify.trusted_dc_name.replace('\\', '')
            domain_and_server = "%s\\%s" % (local_tdo_info.domain_name.string, server)
            local_trust_rediscover = \
                local_netlogon.netr_LogonControl2Ex(local_server,
                                                    netlogon.NETLOGON_CONTROL_REDISCOVER,
                                                    2,
                                                    domain_and_server)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "NETLOGON_CONTROL_REDISCOVER failed")

        local_conn_status = self._uint32(local_trust_rediscover.tc_connection_status[0])
        local_rediscover = "LocalRediscover: DC[%s] CONNECTION[%s]" % (
                               local_trust_rediscover.trusted_dc_name,
                               local_trust_rediscover.tc_connection_status[1])

        if local_conn_status != werror.WERR_SUCCESS:
            raise CommandError(local_rediscover)
        else:
            self.outf.write("OK: %s\n" % local_rediscover)

        if validate_location != "local":
            try:
                remote_server = self.setup_remote_server(credopts, domain, require_pdc=False)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to locate remote server")

            try:
                remote_netlogon = self.new_remote_netlogon_connection()
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "failed to connect netlogon server")

            try:
                remote_trust_verify = \
                    remote_netlogon.netr_LogonControl2Ex(remote_server,
                                                         netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                                         2,
                                                         local_lsa_info.dns_domain.string)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "NETLOGON_CONTROL_TC_VERIFY failed")

            remote_trust_status = self._uint32(remote_trust_verify.pdc_connection_status[0])
            remote_conn_status = self._uint32(remote_trust_verify.tc_connection_status[0])

            if remote_trust_verify.flags & netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
                remote_validation = "RemoteValidation: DC[%s] CONNECTION[%s] TRUST[%s] VERIFY_STATUS_RETURNED" % (
                                   remote_trust_verify.trusted_dc_name,
                                   remote_trust_verify.tc_connection_status[1],
                                   remote_trust_verify.pdc_connection_status[1])
            else:
                remote_validation = "RemoteValidation: DC[%s] CONNECTION[%s] TRUST[%s]" % (
                                   remote_trust_verify.trusted_dc_name,
                                   remote_trust_verify.tc_connection_status[1],
                                   remote_trust_verify.pdc_connection_status[1])

            if remote_trust_status != werror.WERR_SUCCESS or remote_conn_status != werror.WERR_SUCCESS:
                raise CommandError(remote_validation)
            else:
                self.outf.write("OK: %s\n" % remote_validation)

            try:
                server = remote_trust_verify.trusted_dc_name.replace('\\', '')
                domain_and_server = "%s\\%s" % (local_lsa_info.dns_domain.string, server)
                remote_trust_rediscover = \
                    remote_netlogon.netr_LogonControl2Ex(remote_server,
                                                         netlogon.NETLOGON_CONTROL_REDISCOVER,
                                                         2,
                                                         domain_and_server)
            except RuntimeError as error:
                raise self.RemoteRuntimeError(self, error, "NETLOGON_CONTROL_REDISCOVER failed")

            remote_conn_status = self._uint32(remote_trust_rediscover.tc_connection_status[0])

            remote_rediscover = "RemoteRediscover: DC[%s] CONNECTION[%s]" % (
                                   remote_trust_rediscover.trusted_dc_name,
                                   remote_trust_rediscover.tc_connection_status[1])

            if remote_conn_status != werror.WERR_SUCCESS:
                raise CommandError(remote_rediscover)
            else:
                self.outf.write("OK: %s\n" % remote_rediscover)

        return


class cmd_domain_trust_namespaces(DomainTrustCommand):
    """Manage forest trust namespaces."""

    synopsis = "%prog [DOMAIN] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "localdcopts": LocalDCCredentialsOptions,
    }

    takes_options = [
        Option("--refresh", type="choice", metavar="check|store",
               choices=["check", "store", None],
               help="List and maybe store refreshed forest trust information: 'check' or 'store'.",
               dest='refresh',
               default=None),
        Option("--enable-all", action="store_true",
               help="Try to update disabled entries, not allowed with --refresh=check.",
               dest='enable_all',
               default=False),
        Option("--enable-tln", action="append", metavar='DNSDOMAIN',
               help="Enable a top level name entry. Can be specified multiple times.",
               dest='enable_tln',
               default=[]),
        Option("--disable-tln", action="append", metavar='DNSDOMAIN',
               help="Disable a top level name entry. Can be specified multiple times.",
               dest='disable_tln',
               default=[]),
        Option("--add-tln-ex", action="append", metavar='DNSDOMAIN',
               help="Add a top level exclusion entry. Can be specified multiple times.",
               dest='add_tln_ex',
               default=[]),
        Option("--delete-tln-ex", action="append", metavar='DNSDOMAIN',
               help="Delete a top level exclusion entry. Can be specified multiple times.",
               dest='delete_tln_ex',
               default=[]),
        Option("--enable-nb", action="append", metavar='NETBIOSDOMAIN',
               help="Enable a netbios name in a domain entry. Can be specified multiple times.",
               dest='enable_nb',
               default=[]),
        Option("--disable-nb", action="append", metavar='NETBIOSDOMAIN',
               help="Disable a netbios name in a domain entry. Can be specified multiple times.",
               dest='disable_nb',
               default=[]),
        Option("--enable-sid", action="append", metavar='DOMAINSID',
               help="Enable a SID in a domain entry. Can be specified multiple times.",
               dest='enable_sid_str',
               default=[]),
        Option("--disable-sid", action="append", metavar='DOMAINSID',
               help="Disable a SID in a domain entry. Can be specified multiple times.",
               dest='disable_sid_str',
               default=[]),
        Option("--add-upn-suffix", action="append", metavar='DNSDOMAIN',
               help="Add a new uPNSuffixes attribute for the local forest. Can be specified multiple times.",
               dest='add_upn',
               default=[]),
        Option("--delete-upn-suffix", action="append", metavar='DNSDOMAIN',
               help="Delete an existing uPNSuffixes attribute of the local forest. Can be specified multiple times.",
               dest='delete_upn',
               default=[]),
        Option("--add-spn-suffix", action="append", metavar='DNSDOMAIN',
               help="Add a new msDS-SPNSuffixes attribute for the local forest. Can be specified multiple times.",
               dest='add_spn',
               default=[]),
        Option("--delete-spn-suffix", action="append", metavar='DNSDOMAIN',
               help="Delete an existing msDS-SPNSuffixes attribute of the local forest. Can be specified multiple times.",
               dest='delete_spn',
               default=[]),
    ]

    takes_args = ["domain?"]

    def run(self, domain=None, sambaopts=None, localdcopts=None, versionopts=None,
            refresh=None, enable_all=False,
            enable_tln=[], disable_tln=[], add_tln_ex=[], delete_tln_ex=[],
            enable_sid_str=[], disable_sid_str=[], enable_nb=[], disable_nb=[],
            add_upn=[], delete_upn=[], add_spn=[], delete_spn=[]):

        require_update = False

        if domain is None:
            if refresh == "store":
                raise CommandError("--refresh=%s not allowed without DOMAIN" % refresh)

            if enable_all:
                raise CommandError("--enable-all not allowed without DOMAIN")

            if len(enable_tln) > 0:
                raise CommandError("--enable-tln not allowed without DOMAIN")
            if len(disable_tln) > 0:
                raise CommandError("--disable-tln not allowed without DOMAIN")

            if len(add_tln_ex) > 0:
                raise CommandError("--add-tln-ex not allowed without DOMAIN")
            if len(delete_tln_ex) > 0:
                raise CommandError("--delete-tln-ex not allowed without DOMAIN")

            if len(enable_nb) > 0:
                raise CommandError("--enable-nb not allowed without DOMAIN")
            if len(disable_nb) > 0:
                raise CommandError("--disable-nb not allowed without DOMAIN")

            if len(enable_sid_str) > 0:
                raise CommandError("--enable-sid not allowed without DOMAIN")
            if len(disable_sid_str) > 0:
                raise CommandError("--disable-sid not allowed without DOMAIN")

            if len(add_upn) > 0:
                for n in add_upn:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --add-upn-suffix should not include with '*.'" % n)
                require_update = True
            if len(delete_upn) > 0:
                for n in delete_upn:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --delete-upn-suffix should not include with '*.'" % n)
                require_update = True
            for a in add_upn:
                for d in delete_upn:
                    if a.lower() != d.lower():
                        continue
                    raise CommandError("value[%s] specified for --add-upn-suffix and --delete-upn-suffix" % a)

            if len(add_spn) > 0:
                for n in add_spn:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --add-spn-suffix should not include with '*.'" % n)
                require_update = True
            if len(delete_spn) > 0:
                for n in delete_spn:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --delete-spn-suffix should not include with '*.'" % n)
                require_update = True
            for a in add_spn:
                for d in delete_spn:
                    if a.lower() != d.lower():
                        continue
                    raise CommandError("value[%s] specified for --add-spn-suffix and --delete-spn-suffix" % a)
        else:
            if len(add_upn) > 0:
                raise CommandError("--add-upn-suffix not allowed together with DOMAIN")
            if len(delete_upn) > 0:
                raise CommandError("--delete-upn-suffix not allowed together with DOMAIN")
            if len(add_spn) > 0:
                raise CommandError("--add-spn-suffix not allowed together with DOMAIN")
            if len(delete_spn) > 0:
                raise CommandError("--delete-spn-suffix not allowed together with DOMAIN")

        if refresh is not None:
            if refresh == "store":
                require_update = True

            if enable_all and refresh != "store":
                raise CommandError("--enable-all not allowed together with --refresh=%s" % refresh)

            if len(enable_tln) > 0:
                raise CommandError("--enable-tln not allowed together with --refresh")
            if len(disable_tln) > 0:
                raise CommandError("--disable-tln not allowed together with --refresh")

            if len(add_tln_ex) > 0:
                raise CommandError("--add-tln-ex not allowed together with --refresh")
            if len(delete_tln_ex) > 0:
                raise CommandError("--delete-tln-ex not allowed together with --refresh")

            if len(enable_nb) > 0:
                raise CommandError("--enable-nb not allowed together with --refresh")
            if len(disable_nb) > 0:
                raise CommandError("--disable-nb not allowed together with --refresh")

            if len(enable_sid_str) > 0:
                raise CommandError("--enable-sid not allowed together with --refresh")
            if len(disable_sid_str) > 0:
                raise CommandError("--disable-sid not allowed together with --refresh")
        else:
            if enable_all:
                require_update = True

                if len(enable_tln) > 0:
                    raise CommandError("--enable-tln not allowed together with --enable-all")

                if len(enable_nb) > 0:
                    raise CommandError("--enable-nb not allowed together with --enable-all")

                if len(enable_sid_str) > 0:
                    raise CommandError("--enable-sid not allowed together with --enable-all")

            if len(enable_tln) > 0:
                require_update = True
            if len(disable_tln) > 0:
                require_update = True
            for e in enable_tln:
                for d in disable_tln:
                    if e.lower() != d.lower():
                        continue
                    raise CommandError("value[%s] specified for --enable-tln and --disable-tln" % e)

            if len(add_tln_ex) > 0:
                for n in add_tln_ex:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --add-tln-ex should not include with '*.'" % n)
                require_update = True
            if len(delete_tln_ex) > 0:
                for n in delete_tln_ex:
                    if not n.startswith("*."):
                        continue
                    raise CommandError("value[%s] specified for --delete-tln-ex should not include with '*.'" % n)
                require_update = True
            for a in add_tln_ex:
                for d in delete_tln_ex:
                    if a.lower() != d.lower():
                        continue
                    raise CommandError("value[%s] specified for --add-tln-ex and --delete-tln-ex" % a)

            if len(enable_nb) > 0:
                require_update = True
            if len(disable_nb) > 0:
                require_update = True
            for e in enable_nb:
                for d in disable_nb:
                    if e.upper() != d.upper():
                        continue
                    raise CommandError("value[%s] specified for --enable-nb and --disable-nb" % e)

            enable_sid = []
            for s in enable_sid_str:
                try:
                    sid = security.dom_sid(s)
                except TypeError as error:
                    raise CommandError("value[%s] specified for --enable-sid is not a valid SID" % s)
                enable_sid.append(sid)
            disable_sid = []
            for s in disable_sid_str:
                try:
                    sid = security.dom_sid(s)
                except TypeError as error:
                    raise CommandError("value[%s] specified for --disable-sid is not a valid SID" % s)
                disable_sid.append(sid)
            if len(enable_sid) > 0:
                require_update = True
            if len(disable_sid) > 0:
                require_update = True
            for e in enable_sid:
                for d in disable_sid:
                    if e != d:
                        continue
                    raise CommandError("value[%s] specified for --enable-sid and --disable-sid" % e)

        local_policy_access = lsa.LSA_POLICY_VIEW_LOCAL_INFORMATION
        if require_update:
            local_policy_access |= lsa.LSA_POLICY_TRUST_ADMIN

        local_server = self.setup_local_server(sambaopts, localdcopts)
        try:
            local_lsa = self.new_local_lsa_connection()
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to connect lsa server")

        try:
            (local_policy, local_lsa_info) = self.get_lsa_info(local_lsa, local_policy_access)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "failed to query LSA_POLICY_INFO_DNS")

        self.outf.write("LocalDomain Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_lsa_info.name.string,
                        local_lsa_info.dns_domain.string,
                        local_lsa_info.sid))

        if domain is None:
            try:
                local_netlogon = self.new_local_netlogon_connection()
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

            try:
                local_netlogon_info = self.get_netlogon_dc_info(local_netlogon, local_server)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to get netlogon dc info")

            if local_netlogon_info.domain_name != local_netlogon_info.forest_name:
                raise CommandError("The local domain [%s] is not the forest root [%s]" % (
                                   local_netlogon_info.domain_name,
                                   local_netlogon_info.forest_name))

            try:
                # get all information about our own forest
                own_forest_info = local_netlogon.netr_DsRGetForestTrustInformation(local_netlogon_info.dc_unc,
                                                                                   None, 0)
            except RuntimeError as error:
                if self.check_runtime_error(error, werror.WERR_RPC_S_PROCNUM_OUT_OF_RANGE):
                    raise CommandError("LOCAL_DC[%s]: netr_DsRGetForestTrustInformation() not supported." % (
                                       self.local_server))

                if self.check_runtime_error(error, werror.WERR_INVALID_FUNCTION):
                    raise CommandError("LOCAL_DC[%s]: netr_DsRGetForestTrustInformation() not supported." % (
                                       self.local_server))

                if self.check_runtime_error(error, werror.WERR_NERR_ACFNOTLOADED):
                    raise CommandError("LOCAL_DC[%s]: netr_DsRGetForestTrustInformation() not supported." % (
                                       self.local_server))

                raise self.LocalRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

            self.outf.write("Own forest trust information...\n")
            self.write_forest_trust_info(own_forest_info,
                                         tln=local_lsa_info.dns_domain.string)

            try:
                local_samdb = self.new_local_ldap_connection()
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to connect to SamDB")

            local_partitions_dn = "CN=Partitions,%s" % str(local_samdb.get_config_basedn())
            attrs = ['uPNSuffixes', 'msDS-SPNSuffixes']
            try:
                msgs = local_samdb.search(base=local_partitions_dn,
                                          scope=ldb.SCOPE_BASE,
                                          expression="(objectClass=crossRefContainer)",
                                          attrs=attrs)
                stored_msg = msgs[0]
            except ldb.LdbError as error:
                raise self.LocalLdbError(self, error, "failed to search partition dn")

            stored_upn_vals = []
            if 'uPNSuffixes' in stored_msg:
                stored_upn_vals.extend(stored_msg['uPNSuffixes'])

            stored_spn_vals = []
            if 'msDS-SPNSuffixes' in stored_msg:
                stored_spn_vals.extend(stored_msg['msDS-SPNSuffixes'])

            self.outf.write("Stored uPNSuffixes attributes[%d]:\n" % len(stored_upn_vals))
            for v in stored_upn_vals:
                self.outf.write("TLN: %-32s DNS[*.%s]\n" % ("", v))
            self.outf.write("Stored msDS-SPNSuffixes attributes[%d]:\n" % len(stored_spn_vals))
            for v in stored_spn_vals:
                self.outf.write("TLN: %-32s DNS[*.%s]\n" % ("", v))

            if not require_update:
                return

            replace_upn = False
            update_upn_vals = []
            update_upn_vals.extend(stored_upn_vals)

            replace_spn = False
            update_spn_vals = []
            update_spn_vals.extend(stored_spn_vals)

            for upn in add_upn:
                for i, v in enumerate(update_upn_vals):
                    if str(v).lower() == upn.lower():
                        raise CommandError("Entry already present for "
                                           "value[%s] specified for "
                                           "--add-upn-suffix" % upn)
                update_upn_vals.append(upn)
                replace_upn = True

            for upn in delete_upn:
                idx = None
                for i, v in enumerate(update_upn_vals):
                    if str(v).lower() != upn.lower():
                        continue
                    idx = i
                    break
                if idx is None:
                    raise CommandError("Entry not found for value[%s] specified for --delete-upn-suffix" % upn)

                update_upn_vals.pop(idx)
                replace_upn = True

            for spn in add_spn:
                for i, v in enumerate(update_spn_vals):
                    if str(v).lower() == spn.lower():
                        raise CommandError("Entry already present for "
                                           "value[%s] specified for "
                                           "--add-spn-suffix" % spn)
                update_spn_vals.append(spn)
                replace_spn = True

            for spn in delete_spn:
                idx = None
                for i, v in enumerate(update_spn_vals):
                    if str(v).lower() != spn.lower():
                        continue
                    idx = i
                    break
                if idx is None:
                    raise CommandError("Entry not found for value[%s] specified for --delete-spn-suffix" % spn)

                update_spn_vals.pop(idx)
                replace_spn = True

            self.outf.write("Update uPNSuffixes attributes[%d]:\n" % len(update_upn_vals))
            for v in update_upn_vals:
                self.outf.write("TLN: %-32s DNS[*.%s]\n" % ("", v))
            self.outf.write("Update msDS-SPNSuffixes attributes[%d]:\n" % len(update_spn_vals))
            for v in update_spn_vals:
                self.outf.write("TLN: %-32s DNS[*.%s]\n" % ("", v))

            update_msg = ldb.Message()
            update_msg.dn = stored_msg.dn

            if replace_upn:
                update_msg['uPNSuffixes'] = ldb.MessageElement(update_upn_vals,
                                                               ldb.FLAG_MOD_REPLACE,
                                                               'uPNSuffixes')
            if replace_spn:
                update_msg['msDS-SPNSuffixes'] = ldb.MessageElement(update_spn_vals,
                                                                    ldb.FLAG_MOD_REPLACE,
                                                                    'msDS-SPNSuffixes')
            try:
                local_samdb.modify(update_msg)
            except ldb.LdbError as error:
                raise self.LocalLdbError(self, error, "failed to update partition dn")

            try:
                stored_forest_info = local_netlogon.netr_DsRGetForestTrustInformation(local_netlogon_info.dc_unc,
                                                                                      None, 0)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

            self.outf.write("Stored forest trust information...\n")
            self.write_forest_trust_info(stored_forest_info,
                                         tln=local_lsa_info.dns_domain.string)
            return

        try:
            lsaString = lsa.String()
            lsaString.string = domain
            local_tdo_info = \
                local_lsa.QueryTrustedDomainInfoByName(local_policy,
                                                       lsaString,
                                                       lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
        except NTSTATUSError as error:
            if self.check_runtime_error(error, ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND):
                raise CommandError("trusted domain object does not exist for domain [%s]" % domain)

            raise self.LocalRuntimeError(self, error, "QueryTrustedDomainInfoByName(INFO_EX) failed")

        self.outf.write("LocalTDO Netbios[%s] DNS[%s] SID[%s]\n" % (
                        local_tdo_info.netbios_name.string,
                        local_tdo_info.domain_name.string,
                        local_tdo_info.sid))

        if not local_tdo_info.trust_attributes & lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            raise CommandError("trusted domain object for domain [%s] is not marked as FOREST_TRANSITIVE." % domain)

        if refresh is not None:
            try:
                local_netlogon = self.new_local_netlogon_connection()
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to connect netlogon server")

            try:
                local_netlogon_info = self.get_netlogon_dc_info(local_netlogon, local_server)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "failed to get netlogon dc info")

            lsa_update_check = 1
            if refresh == "store":
                netlogon_update_tdo = netlogon.DS_GFTI_UPDATE_TDO
                if enable_all:
                    lsa_update_check = 0
            else:
                netlogon_update_tdo = 0

            try:
                # get all information about the remote trust
                # this triggers netr_GetForestTrustInformation to the remote domain
                # and lsaRSetForestTrustInformation() locally, but new top level
                # names are disabled by default.
                fresh_forest_info = \
                    local_netlogon.netr_DsRGetForestTrustInformation(local_netlogon_info.dc_unc,
                                                                     local_tdo_info.domain_name.string,
                                                                     netlogon_update_tdo)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "netr_DsRGetForestTrustInformation() failed")

            try:
                fresh_forest_collision = \
                    local_lsa.lsaRSetForestTrustInformation(local_policy,
                                                            local_tdo_info.domain_name,
                                                            lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                                                            fresh_forest_info,
                                                            lsa_update_check)
            except RuntimeError as error:
                raise self.LocalRuntimeError(self, error, "lsaRSetForestTrustInformation() failed")

            self.outf.write("Fresh forest trust information...\n")
            self.write_forest_trust_info(fresh_forest_info,
                                         tln=local_tdo_info.domain_name.string,
                                         collisions=fresh_forest_collision)

            if refresh == "store":
                try:
                    lsaString = lsa.String()
                    lsaString.string = local_tdo_info.domain_name.string
                    stored_forest_info = \
                        local_lsa.lsaRQueryForestTrustInformation(local_policy,
                                                                  lsaString,
                                                                  lsa.LSA_FOREST_TRUST_DOMAIN_INFO)
                except RuntimeError as error:
                    raise self.LocalRuntimeError(self, error, "lsaRQueryForestTrustInformation() failed")

                self.outf.write("Stored forest trust information...\n")
                self.write_forest_trust_info(stored_forest_info,
                                             tln=local_tdo_info.domain_name.string)

            return

        #
        # The none --refresh path
        #

        try:
            lsaString = lsa.String()
            lsaString.string = local_tdo_info.domain_name.string
            local_forest_info = \
                local_lsa.lsaRQueryForestTrustInformation(local_policy,
                                                          lsaString,
                                                          lsa.LSA_FOREST_TRUST_DOMAIN_INFO)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "lsaRQueryForestTrustInformation() failed")

        self.outf.write("Local forest trust information...\n")
        self.write_forest_trust_info(local_forest_info,
                                     tln=local_tdo_info.domain_name.string)

        if not require_update:
            return

        entries = []
        entries.extend(local_forest_info.entries)
        update_forest_info = lsa.ForestTrustInformation()
        update_forest_info.count = len(entries)
        update_forest_info.entries = entries

        if enable_all:
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                    continue
                if update_forest_info.entries[i].flags == 0:
                    continue
                update_forest_info.entries[i].time = 0
                update_forest_info.entries[i].flags &= ~lsa.LSA_TLN_DISABLED_MASK
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if update_forest_info.entries[i].flags == 0:
                    continue
                update_forest_info.entries[i].time = 0
                update_forest_info.entries[i].flags &= ~lsa.LSA_NB_DISABLED_MASK
                update_forest_info.entries[i].flags &= ~lsa.LSA_SID_DISABLED_MASK

        for tln in enable_tln:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                    continue
                if r.forest_trust_data.string.lower() != tln.lower():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --enable-tln" % tln)
            if not update_forest_info.entries[idx].flags & lsa.LSA_TLN_DISABLED_MASK:
                raise CommandError("Entry found for value[%s] specified for --enable-tln is already enabled" % tln)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_TLN_DISABLED_MASK

        for tln in disable_tln:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                    continue
                if r.forest_trust_data.string.lower() != tln.lower():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --disable-tln" % tln)
            if update_forest_info.entries[idx].flags & lsa.LSA_TLN_DISABLED_ADMIN:
                raise CommandError("Entry found for value[%s] specified for --disable-tln is already disabled" % tln)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_TLN_DISABLED_MASK
            update_forest_info.entries[idx].flags |= lsa.LSA_TLN_DISABLED_ADMIN

        for tln_ex in add_tln_ex:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
                    continue
                if r.forest_trust_data.string.lower() != tln_ex.lower():
                    continue
                idx = i
                break
            if idx is not None:
                raise CommandError("Entry already present for value[%s] specified for --add-tln-ex" % tln_ex)

            tln_dot = ".%s" % tln_ex.lower()
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
                    continue
                r_dot = ".%s" % r.forest_trust_data.string.lower()
                if tln_dot == r_dot:
                    raise CommandError("TLN entry present for value[%s] specified for --add-tln-ex" % tln_ex)
                if not tln_dot.endswith(r_dot):
                    continue
                idx = i
                break

            if idx is None:
                raise CommandError("No TLN parent present for value[%s] specified for --add-tln-ex" % tln_ex)

            r = lsa.ForestTrustRecord()
            r.type = lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX
            r.flags = 0
            r.time = 0
            r.forest_trust_data.string = tln_ex

            entries = []
            entries.extend(update_forest_info.entries)
            entries.insert(idx + 1, r)
            update_forest_info.count = len(entries)
            update_forest_info.entries = entries

        for tln_ex in delete_tln_ex:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
                    continue
                if r.forest_trust_data.string.lower() != tln_ex.lower():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --delete-tln-ex" % tln_ex)

            entries = []
            entries.extend(update_forest_info.entries)
            entries.pop(idx)
            update_forest_info.count = len(entries)
            update_forest_info.entries = entries

        for nb in enable_nb:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.forest_trust_data.netbios_domain_name.string.upper() != nb.upper():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --enable-nb" % nb)
            if not update_forest_info.entries[idx].flags & lsa.LSA_NB_DISABLED_MASK:
                raise CommandError("Entry found for value[%s] specified for --enable-nb is already enabled" % nb)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_NB_DISABLED_MASK

        for nb in disable_nb:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.forest_trust_data.netbios_domain_name.string.upper() != nb.upper():
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --delete-nb" % nb)
            if update_forest_info.entries[idx].flags & lsa.LSA_NB_DISABLED_ADMIN:
                raise CommandError("Entry found for value[%s] specified for --disable-nb is already disabled" % nb)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_NB_DISABLED_MASK
            update_forest_info.entries[idx].flags |= lsa.LSA_NB_DISABLED_ADMIN

        for sid in enable_sid:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.forest_trust_data.domain_sid != sid:
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --enable-sid" % sid)
            if not update_forest_info.entries[idx].flags & lsa.LSA_SID_DISABLED_MASK:
                raise CommandError("Entry found for value[%s] specified for --enable-sid is already enabled" % nb)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_SID_DISABLED_MASK

        for sid in disable_sid:
            idx = None
            for i, r in enumerate(update_forest_info.entries):
                if r.type != lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
                    continue
                if r.forest_trust_data.domain_sid != sid:
                    continue
                idx = i
                break
            if idx is None:
                raise CommandError("Entry not found for value[%s] specified for --delete-sid" % sid)
            if update_forest_info.entries[idx].flags & lsa.LSA_SID_DISABLED_ADMIN:
                raise CommandError("Entry found for value[%s] specified for --disable-sid is already disabled" % nb)
            update_forest_info.entries[idx].time = 0
            update_forest_info.entries[idx].flags &= ~lsa.LSA_SID_DISABLED_MASK
            update_forest_info.entries[idx].flags |= lsa.LSA_SID_DISABLED_ADMIN

        try:
            update_forest_collision = local_lsa.lsaRSetForestTrustInformation(local_policy,
                                                                              local_tdo_info.domain_name,
                                                                              lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                                                                              update_forest_info, 0)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "lsaRSetForestTrustInformation() failed")

        self.outf.write("Updated forest trust information...\n")
        self.write_forest_trust_info(update_forest_info,
                                     tln=local_tdo_info.domain_name.string,
                                     collisions=update_forest_collision)

        try:
            lsaString = lsa.String()
            lsaString.string = local_tdo_info.domain_name.string
            stored_forest_info = local_lsa.lsaRQueryForestTrustInformation(local_policy,
                                                                           lsaString,
                                                                           lsa.LSA_FOREST_TRUST_DOMAIN_INFO)
        except RuntimeError as error:
            raise self.LocalRuntimeError(self, error, "lsaRQueryForestTrustInformation() failed")

        self.outf.write("Stored forest trust information...\n")
        self.write_forest_trust_info(stored_forest_info,
                                     tln=local_tdo_info.domain_name.string)
        return


class cmd_domain_tombstones_expunge(Command):
    """Expunge tombstones from the database.

This command expunges tombstones from the database."""
    synopsis = "%prog NC [NC [...]] [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--current-time",
               help="The current time to evaluate the tombstone lifetime from, expressed as YYYY-MM-DD",
               type=str),
        Option("--tombstone-lifetime", help="Number of days a tombstone should be preserved for", type=int),
    ]

    takes_args = ["nc*"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, *ncs, **kwargs):
        sambaopts = kwargs.get("sambaopts")
        credopts = kwargs.get("credopts")
        H = kwargs.get("H")
        current_time_string = kwargs.get("current_time")
        tombstone_lifetime = kwargs.get("tombstone_lifetime")
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        if current_time_string is not None:
            current_time_obj = time.strptime(current_time_string, "%Y-%m-%d")
            current_time = int(time.mktime(current_time_obj))

        else:
            current_time = int(time.time())

        if len(ncs) == 0:
            res = samdb.search(expression="", base="", scope=ldb.SCOPE_BASE,
                               attrs=["namingContexts"])

            ncs = []
            for nc in res[0]["namingContexts"]:
                ncs.append(str(nc))
        else:
            ncs = list(ncs)

        started_transaction = False
        try:
            samdb.transaction_start()
            started_transaction = True
            (removed_objects,
             removed_links) = samdb.garbage_collect_tombstones(ncs,
                                                               current_time=current_time,
                                                               tombstone_lifetime=tombstone_lifetime)

        except Exception as err:
            if started_transaction:
                samdb.transaction_cancel()
            raise CommandError("Failed to expunge / garbage collect tombstones", err)

        samdb.transaction_commit()

        self.outf.write("Removed %d objects and %d links successfully\n"
                        % (removed_objects, removed_links))


class cmd_domain_trust(SuperCommand):
    """Domain and forest trust management."""

    subcommands = {}
    subcommands["list"] = cmd_domain_trust_list()
    subcommands["show"] = cmd_domain_trust_show()
    subcommands["create"] = cmd_domain_trust_create()
    subcommands["delete"] = cmd_domain_trust_delete()
    subcommands["validate"] = cmd_domain_trust_validate()
    subcommands["namespaces"] = cmd_domain_trust_namespaces()


class cmd_domain_tombstones(SuperCommand):
    """Domain tombstone and recycled object management."""

    subcommands = {}
    subcommands["expunge"] = cmd_domain_tombstones_expunge()


class ldif_schema_update:
    """Helper class for applying LDIF schema updates"""

    def __init__(self):
        self.is_defunct = False
        self.unknown_oid = None
        self.dn = None
        self.ldif = ""

    def can_ignore_failure(self, error):
        """Checks if we can safely ignore failure to apply an LDIF update"""
        (num, errstr) = error.args

        # Microsoft has marked objects as defunct that Samba doesn't know about
        if num == ldb.ERR_NO_SUCH_OBJECT and self.is_defunct:
            print("Defunct object %s doesn't exist, skipping" % self.dn)
            return True
        elif self.unknown_oid is not None:
            print("Skipping unknown OID %s for object %s" % (self.unknown_oid, self.dn))
            return True

        return False

    def apply(self, samdb):
        """Applies a single LDIF update to the schema"""

        try:
            try:
                samdb.modify_ldif(self.ldif, controls=['relax:0'])
            except ldb.LdbError as e:
                if e.args[0] == ldb.ERR_INVALID_ATTRIBUTE_SYNTAX:

                    # REFRESH after a failed change

                    # Otherwise the OID-to-attribute mapping in
                    # _apply_updates_in_file() won't work, because it
                    # can't lookup the new OID in the schema
                    samdb.set_schema_update_now()

                    samdb.modify_ldif(self.ldif, controls=['relax:0'])
                else:
                    raise
        except ldb.LdbError as e:
            if self.can_ignore_failure(e):
                return 0
            else:
                print("Exception: %s" % e)
                print("Encountered while trying to apply the following LDIF")
                print("----------------------------------------------------")
                print("%s" % self.ldif)

                raise

        return 1


class cmd_domain_schema_upgrade(Command):
    """Domain schema upgrading"""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),  # unused
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--schema", type="choice", metavar="SCHEMA",
               choices=["2012", "2012_R2"],
               help="The schema file to upgrade to. Default is (Windows) 2012_R2.",
               default="2012_R2"),
        Option("--ldf-file", type=str, default=None,
               help="Just apply the schema updates in the adprep/.LDF file(s) specified"),
        Option("--base-dir", type=str, default=None,
               help="Location of ldf files Default is ${SETUPDIR}/adprep.")
    ]

    def _apply_updates_in_file(self, samdb, ldif_file):
        """
        Applies a series of updates specified in an .LDIF file. The .LDIF file
        is based on the adprep Schema updates provided by Microsoft.
        """
        count = 0
        ldif_op = ldif_schema_update()

        # parse the file line by line and work out each update operation to apply
        for line in ldif_file:

            line = line.rstrip()

            # the operations in the .LDIF file are separated by blank lines. If
            # we hit a blank line, try to apply the update we've parsed so far
            if line == '':

                # keep going if we haven't parsed anything yet
                if ldif_op.ldif == '':
                    continue

                # Apply the individual change
                count += ldif_op.apply(samdb)

                # start storing the next operation from scratch again
                ldif_op = ldif_schema_update()
                continue

            # replace the placeholder domain name in the .ldif file with the real domain
            if line.upper().endswith('DC=X'):
                line = line[:-len('DC=X')] + str(samdb.get_default_basedn())
            elif line.upper().endswith('CN=X'):
                line = line[:-len('CN=X')] + str(samdb.get_default_basedn())

            values = line.split(':')

            if values[0].lower() == 'dn':
                ldif_op.dn = values[1].strip()

            # replace the Windows-specific operation with the Samba one
            if values[0].lower() == 'changetype':
                line = line.lower().replace(': ntdsschemaadd',
                                            ': add')
                line = line.lower().replace(': ntdsschemamodify',
                                            ': modify')

            if values[0].lower() in ['rdnattid', 'subclassof',
                                     'systemposssuperiors',
                                     'systemmaycontain',
                                     'systemauxiliaryclass']:
                _, value = values

                # The Microsoft updates contain some OIDs we don't recognize.
                # Query the DB to see if we can work out the OID this update is
                # referring to. If we find a match, then replace the OID with
                # the ldapDisplayname
                if '.' in value:
                    res = samdb.search(base=samdb.get_schema_basedn(),
                                       expression="(|(attributeId=%s)(governsId=%s))" %
                                       (value, value),
                                       attrs=['ldapDisplayName'])

                    if len(res) != 1:
                        ldif_op.unknown_oid = value
                    else:
                        display_name = str(res[0]['ldapDisplayName'][0])
                        line = line.replace(value, ' ' + display_name)

            # Microsoft has marked objects as defunct that Samba doesn't know about
            if values[0].lower() == 'isdefunct' and values[1].strip().lower() == 'true':
                ldif_op.is_defunct = True

            # Samba has added the showInAdvancedViewOnly attribute to all objects,
            # so rather than doing an add, we need to do a replace
            if values[0].lower() == 'add' and values[1].strip().lower() == 'showinadvancedviewonly':
                line = 'replace: showInAdvancedViewOnly'

            # Add the line to the current LDIF operation (including the newline
            # we stripped off at the start of the loop)
            ldif_op.ldif += line + '\n'

        return count

    def _apply_update(self, samdb, update_file, base_dir):
        """Wrapper function for parsing an LDIF file and applying the updates"""

        print("Applying %s updates..." % update_file)

        ldif_file = None
        try:
            ldif_file = open(os.path.join(base_dir, update_file))

            count = self._apply_updates_in_file(samdb, ldif_file)

        finally:
            if ldif_file:
                ldif_file.close()

        print("%u changes applied" % count)

        return count

    def run(self, **kwargs):
        try:
            from samba.ms_schema_markdown import read_ms_markdown
        except ImportError as e:
            self.outf.write("Exception in importing markdown: %s" % e)
            raise CommandError('Failed to import module markdown')
        from samba.schema import Schema

        updates_allowed_overridden = False
        sambaopts = kwargs.get("sambaopts")
        credopts = kwargs.get("credopts")
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        H = kwargs.get("H")
        target_schema = kwargs.get("schema")
        ldf_files = kwargs.get("ldf_file")
        base_dir = kwargs.get("base_dir")

        temp_folder = None

        samdb = SamDB(url=H, session_info=system_session(), credentials=creds, lp=lp)

        # we're not going to get far if the config doesn't allow schema updates
        if lp.get("dsdb:schema update allowed") is None:
            lp.set("dsdb:schema update allowed", "yes")
            print("Temporarily overriding 'dsdb:schema update allowed' setting")
            updates_allowed_overridden = True

        own_dn = ldb.Dn(samdb, samdb.get_dsServiceName())
        master = get_fsmo_roleowner(samdb, str(samdb.get_schema_basedn()),
                                    'schema')
        if own_dn != master:
            raise CommandError("This server is not the schema master.")

        # if specific LDIF files were specified, just apply them
        if ldf_files:
            schema_updates = ldf_files.split(",")
        else:
            schema_updates = []

            # work out the version of the target schema we're upgrading to
            end = Schema.get_version(target_schema)

            # work out the version of the schema we're currently using
            res = samdb.search(base=samdb.get_schema_basedn(),
                               scope=ldb.SCOPE_BASE, attrs=['objectVersion'])

            if len(res) != 1:
                raise CommandError('Could not determine current schema version')
            start = int(res[0]['objectVersion'][0]) + 1

            diff_dir = setup_path("adprep/WindowsServerDocs")
            if base_dir is None:
                # Read from the Schema-Updates.md file
                temp_folder = tempfile.mkdtemp()

                update_file = setup_path("adprep/WindowsServerDocs/Schema-Updates.md")

                try:
                    read_ms_markdown(update_file, temp_folder)
                except Exception as e:
                    print("Exception in markdown parsing: %s" % e)
                    shutil.rmtree(temp_folder)
                    raise CommandError('Failed to upgrade schema')

                base_dir = temp_folder

            for version in range(start, end + 1):
                update = 'Sch%d.ldf' % version
                schema_updates.append(update)

                # Apply patches if we parsed the Schema-Updates.md file
                diff = os.path.abspath(os.path.join(diff_dir, update + '.diff'))
                if temp_folder and os.path.exists(diff):
                    try:
                        p = subprocess.Popen(['patch', update, '-i', diff],
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, cwd=temp_folder)
                    except (OSError, IOError):
                        shutil.rmtree(temp_folder)
                        raise CommandError("Failed to upgrade schema. Check if 'patch' is installed.")

                    stdout, stderr = p.communicate()

                    if p.returncode:
                        print("Exception in patch: %s\n%s" % (stdout, stderr))
                        shutil.rmtree(temp_folder)
                        raise CommandError('Failed to upgrade schema')

                    print("Patched %s using %s" % (update, diff))

        if base_dir is None:
            base_dir = setup_path("adprep")

        samdb.transaction_start()
        count = 0
        error_encountered = False

        try:
            # Apply the schema updates needed to move to the new schema version
            for ldif_file in schema_updates:
                count += self._apply_update(samdb, ldif_file, base_dir)

            if count > 0:
                samdb.transaction_commit()
                print("Schema successfully updated")
            else:
                print("No changes applied to schema")
                samdb.transaction_cancel()
        except Exception as e:
            print("Exception: %s" % e)
            print("Error encountered, aborting schema upgrade")
            samdb.transaction_cancel()
            error_encountered = True

        if updates_allowed_overridden:
            lp.set("dsdb:schema update allowed", "no")

        if temp_folder:
            shutil.rmtree(temp_folder)

        if error_encountered:
            raise CommandError('Failed to upgrade schema')


class cmd_domain_functional_prep(Command):
    """Domain functional level preparation"""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--function-level", type="choice", metavar="FUNCTION_LEVEL",
               choices=["2008_R2", "2012", "2012_R2"],
               help="The schema file to upgrade to. Default is (Windows) 2012_R2.",
               default="2012_R2"),
        Option("--forest-prep", action="store_true",
               help="Run the forest prep (by default, both the domain and forest prep are run)."),
        Option("--domain-prep", action="store_true",
               help="Run the domain prep (by default, both the domain and forest prep are run).")
    ]

    def run(self, **kwargs):
        updates_allowed_overridden = False
        sambaopts = kwargs.get("sambaopts")
        credopts = kwargs.get("credopts")
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        H = kwargs.get("H")
        target_level = string_version_to_constant[kwargs.get("function_level")]
        forest_prep = kwargs.get("forest_prep")
        domain_prep = kwargs.get("domain_prep")

        samdb = SamDB(url=H, session_info=system_session(), credentials=creds, lp=lp)

        # we're not going to get far if the config doesn't allow schema updates
        if lp.get("dsdb:schema update allowed") is None:
            lp.set("dsdb:schema update allowed", "yes")
            print("Temporarily overriding 'dsdb:schema update allowed' setting")
            updates_allowed_overridden = True

        if forest_prep is None and domain_prep is None:
            forest_prep = True
            domain_prep = True

        own_dn = ldb.Dn(samdb, samdb.get_dsServiceName())
        if forest_prep:
            master = get_fsmo_roleowner(samdb, str(samdb.get_schema_basedn()),
                                        'schema')
            if own_dn != master:
                raise CommandError("This server is not the schema master.")

        if domain_prep:
            domain_dn = samdb.domain_dn()
            infrastructure_dn = "CN=Infrastructure," + domain_dn
            master = get_fsmo_roleowner(samdb, infrastructure_dn,
                                        'infrastructure')
            if own_dn != master:
                raise CommandError("This server is not the infrastructure master.")

        if forest_prep:
            samdb.transaction_start()
            error_encountered = False
            try:
                from samba.forest_update import ForestUpdate
                forest = ForestUpdate(samdb, fix=True)

                forest.check_updates_iterator([53, 79, 80, 81, 82, 83])
                forest.check_updates_functional_level(target_level,
                                                      DS_DOMAIN_FUNCTION_2008_R2,
                                                      update_revision=True)

                samdb.transaction_commit()
            except Exception as e:
                print("Exception: %s" % e)
                samdb.transaction_cancel()
                error_encountered = True

        if domain_prep:
            samdb.transaction_start()
            error_encountered = False
            try:
                from samba.domain_update import DomainUpdate

                domain = DomainUpdate(samdb, fix=True)
                domain.check_updates_functional_level(target_level,
                                                      DS_DOMAIN_FUNCTION_2008,
                                                      update_revision=True)

                samdb.transaction_commit()
            except Exception as e:
                print("Exception: %s" % e)
                samdb.transaction_cancel()
                error_encountered = True

        if updates_allowed_overridden:
            lp.set("dsdb:schema update allowed", "no")

        if error_encountered:
            raise CommandError('Failed to perform functional prep')


class cmd_domain(SuperCommand):
    """Domain management."""

    subcommands = {}
    subcommands["demote"] = cmd_domain_demote()
    if cmd_domain_export_keytab is not None:
        subcommands["exportkeytab"] = cmd_domain_export_keytab()
    subcommands["info"] = cmd_domain_info()
    subcommands["provision"] = cmd_domain_provision()
    subcommands["join"] = cmd_domain_join()
    subcommands["dcpromo"] = cmd_domain_dcpromo()
    subcommands["level"] = cmd_domain_level()
    subcommands["passwordsettings"] = cmd_domain_passwordsettings()
    subcommands["classicupgrade"] = cmd_domain_classicupgrade()
    subcommands["samba3upgrade"] = cmd_domain_samba3upgrade()
    subcommands["trust"] = cmd_domain_trust()
    subcommands["tombstones"] = cmd_domain_tombstones()
    subcommands["schemaupgrade"] = cmd_domain_schema_upgrade()
    subcommands["functionalprep"] = cmd_domain_functional_prep()
    subcommands["backup"] = cmd_domain_backup()

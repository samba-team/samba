# machine account (computer) management
#
# Copyright Bjoern Baumbch <bb@sernet.de> 2018
#
# based on user management
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
# Copyright Theresa Halloran 2011 <theresahalloran@gmail.com>
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

import samba.getopt as options
import ldb
import socket
import samba
import re
import os
import tempfile
from samba import sd_utils
from samba.dcerpc import dnsserver, dnsp, security
from samba.dnsserver import ARecord, AAAARecord
from samba.ndr import ndr_unpack, ndr_pack, ndr_print
from samba.remove_dc import remove_dns_references
from samba.auth import system_session
from samba.samdb import SamDB
from samba.compat import get_bytes
from subprocess import check_call, CalledProcessError
from . import common

from samba import (
    credentials,
    dsdb,
    Ldb,
    werror,
    WERRORError
)

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
)

def _is_valid_ip(ip_string, address_families=None):
    """Check ip string is valid address"""
    # by default, check both ipv4 and ipv6
    if not address_families:
        address_families = [socket.AF_INET, socket.AF_INET6]

    for address_family in address_families:
        try:
            socket.inet_pton(address_family, ip_string)
            return True  # if no error, return directly
        except socket.error:
            continue  # Otherwise, check next family
    return False


def _is_valid_ipv4(ip_string):
    """Check ip string is valid ipv4 address"""
    return _is_valid_ip(ip_string, address_families=[socket.AF_INET])


def _is_valid_ipv6(ip_string):
    """Check ip string is valid ipv6 address"""
    return _is_valid_ip(ip_string, address_families=[socket.AF_INET6])


def add_dns_records(
        samdb, name, dns_conn, change_owner_sd,
        server, ip_address_list, logger):
    """Add DNS A or AAAA records while creating computer. """
    name = name.rstrip('$')
    client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
    select_flags = dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA | dnsserver.DNS_RPC_VIEW_NO_CHILDREN
    zone = samdb.domain_dns_name()
    name_found = True
    sd_helper = sd_utils.SDUtils(samdb)

    try:
        buflen, res = dns_conn.DnssrvEnumRecords2(
            client_version,
            0,
            server,
            zone,
            name,
            None,
            dnsp.DNS_TYPE_ALL,
            select_flags,
            None,
            None,
        )
    except WERRORError as e:
        if e.args[0] == werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST:
            name_found = False
            pass

    if name_found:
        for rec in res.rec:
            for record in rec.records:
                if record.wType == dnsp.DNS_TYPE_A or record.wType == dnsp.DNS_TYPE_AAAA:
                    # delete record
                    del_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
                    del_rec_buf.rec = record
                    try:
                        dns_conn.DnssrvUpdateRecord2(
                            client_version,
                            0,
                            server,
                            zone,
                            name,
                            None,
                            del_rec_buf,
                        )
                    except WERRORError as e:
                        if e.args[0] != werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST:
                            raise

    for ip_address in ip_address_list:
        if _is_valid_ipv6(ip_address):
            logger.info("Adding DNS AAAA record %s.%s for IPv6 IP: %s" % (
                name, zone, ip_address))
            rec = AAAARecord(ip_address)
        elif _is_valid_ipv4(ip_address):
            logger.info("Adding DNS A record %s.%s for IPv4 IP: %s" % (
                name, zone, ip_address))
            rec = ARecord(ip_address)
        else:
            raise ValueError('Invalid IP: {}'.format(ip_address))

        # Add record
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec

        dns_conn.DnssrvUpdateRecord2(
            client_version,
            0,
            server,
            zone,
            name,
            add_rec_buf,
            None,
        )

    if (len(ip_address_list) > 0):
        domaindns_zone_dn = ldb.Dn(
            samdb,
            'DC=DomainDnsZones,%s' % samdb.get_default_basedn(),
        )

        dns_a_dn, ldap_record = samdb.dns_lookup(
            "%s.%s" % (name, zone),
            dns_partition=domaindns_zone_dn,
        )

        # Make the DC own the DNS record, not the administrator
        sd_helper.modify_sd_on_dn(
            dns_a_dn,
            change_owner_sd,
            controls=["sd_flags:1:%d" % (security.SECINFO_OWNER | security.SECINFO_GROUP)],
        )


class cmd_computer_create(Command):
    """Create a new computer.

This command creates a new computer account in the Active Directory domain.
The computername specified on the command is the sAMaccountName without the
trailing $ (dollar sign).

User accounts may represent physical entities, such as workstations. Computer
accounts are also referred to as security principals and are assigned a
security identifier (SID).

Example1:
samba-tool computer create Computer1 -H ldap://samba.samdom.example.com \\
    -Uadministrator%passw1rd

Example1 shows how to create a new computer in the domain against a remote LDAP
server. The -H parameter is used to specify the remote target server. The -U
option is used to pass the userid and password authorized to issue the command
remotely.

Example2:
sudo samba-tool computer create Computer2

Example2 shows how to create a new computer in the domain against the local
server. sudo is used so a user may run the command as root.

Example3:
samba-tool computer create Computer3 --computerou='OU=OrgUnit'

Example3 shows how to create a new computer in the OrgUnit organizational unit.

"""
    synopsis = "%prog <computername> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--computerou",
               help=("DN of alternative location (with or without domainDN "
                     "counterpart) to default CN=Computers in which new "
                     "computer object will be created. E.g. 'OU=<OU name>'"),
               type=str),
        Option("--description", help="Computers's description", type=str),
        Option("--prepare-oldjoin",
               help="Prepare enabled machine account for oldjoin mechanism",
               action="store_true"),
        Option("--ip-address",
               dest='ip_address_list',
               help=("IPv4 address for the computer's A record, or IPv6 "
                     "address for AAAA record, can be provided multiple "
                     "times"),
               action='append'),
        Option("--service-principal-name",
               dest='service_principal_name_list',
               help=("Computer's Service Principal Name, can be provided "
                     "multiple times"),
               action='append')
    ]

    takes_args = ["computername"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, computername, credopts=None, sambaopts=None, versionopts=None,
            H=None, computerou=None, description=None, prepare_oldjoin=False,
            ip_address_list=None, service_principal_name_list=None):

        if ip_address_list is None:
            ip_address_list = []

        if service_principal_name_list is None:
            service_principal_name_list = []

        # check each IP address if provided
        for ip_address in ip_address_list:
            if not _is_valid_ip(ip_address):
                raise CommandError('Invalid IP address {}'.format(ip_address))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.newcomputer(computername, computerou=computerou,
                              description=description,
                              prepare_oldjoin=prepare_oldjoin,
                              ip_address_list=ip_address_list,
                              service_principal_name_list=service_principal_name_list,
                              )

            if ip_address_list:
                # if ip_address_list provided, then we need to create DNS
                # records for this computer.

                hostname = re.sub(r"\$$", "", computername)
                if hostname.count('$'):
                    raise CommandError('Illegal computername "%s"' % computername)

                filters = '(&(sAMAccountName={}$)(objectclass=computer))'.format(
                    ldb.binary_encode(hostname))

                recs = samdb.search(
                    base=samdb.domain_dn(),
                    scope=ldb.SCOPE_SUBTREE,
                    expression=filters,
                    attrs=['primaryGroupID', 'objectSid'])

                group = recs[0]['primaryGroupID'][0]
                owner = ndr_unpack(security.dom_sid, recs[0]["objectSid"][0])

                dns_conn = dnsserver.dnsserver(
                    "ncacn_ip_tcp:{}[sign]".format(samdb.host_dns_name()),
                    lp, creds)

                change_owner_sd = security.descriptor()
                change_owner_sd.owner_sid = owner
                change_owner_sd.group_sid = security.dom_sid(
                    "{}-{}".format(samdb.get_domain_sid(), group),
                )

                add_dns_records(
                    samdb, hostname, dns_conn,
                    change_owner_sd, samdb.host_dns_name(),
                    ip_address_list, self.get_logger())
        except Exception as e:
            raise CommandError("Failed to create computer '%s': " %
                               computername, e)

        self.outf.write("Computer '%s' created successfully\n" % computername)


class cmd_computer_delete(Command):
    """Delete a computer.

This command deletes a computer account from the Active Directory domain. The
computername specified on the command is the sAMAccountName without the
trailing $ (dollar sign).

Once the account is deleted, all permissions and memberships associated with
that account are deleted. If a new computer account is added with the same name
as a previously deleted account name, the new computer does not have the
previous permissions. The new account computer will be assigned a new security
identifier (SID) and permissions and memberships will have to be added.

The command may be run from the root userid or another authorized
userid. The -H or --URL= option can be used to execute the command against
a remote server.

Example1:
samba-tool computer delete Computer1 -H ldap://samba.samdom.example.com \\
    -Uadministrator%passw1rd

Example1 shows how to delete a computer in the domain against a remote LDAP
server. The -H parameter is used to specify the remote target server. The
--computername= and --password= options are used to pass the computername and
password of a computer that exists on the remote server and is authorized to
issue the command on that server.

Example2:
sudo samba-tool computer delete Computer2

Example2 shows how to delete a computer in the domain against the local server.
sudo is used so a computer may run the command as root.

"""
    synopsis = "%prog <computername> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["computername"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, computername, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        samaccountname = computername
        if not computername.endswith('$'):
            samaccountname = "%s$" % computername

        filter = ("(&(sAMAccountName=%s)(sAMAccountType=%u))" %
                  (ldb.binary_encode(samaccountname),
                   dsdb.ATYPE_WORKSTATION_TRUST))
        try:
            res = samdb.search(base=samdb.domain_dn(),
                               scope=ldb.SCOPE_SUBTREE,
                               expression=filter,
                               attrs=["userAccountControl", "dNSHostName"])
            computer_dn = res[0].dn
            computer_ac = int(res[0]["userAccountControl"][0])
            if "dNSHostName" in res[0]:
                computer_dns_host_name = str(res[0]["dNSHostName"][0])
            else:
                computer_dns_host_name = None
        except IndexError:
            raise CommandError('Unable to find computer "%s"' % computername)

        computer_is_workstation = (
            computer_ac & dsdb.UF_WORKSTATION_TRUST_ACCOUNT)
        if not computer_is_workstation:
            raise CommandError('Failed to remove computer "%s": '
                               'Computer is not a workstation - removal denied'
                               % computername)
        try:
            samdb.delete(computer_dn)
            if computer_dns_host_name:
                remove_dns_references(
                    samdb, self.get_logger(), computer_dns_host_name,
                    ignore_no_name=True)
        except Exception as e:
            raise CommandError('Failed to remove computer "%s"' %
                               samaccountname, e)
        self.outf.write("Deleted computer %s\n" % computername)


class cmd_computer_edit(Command):
    """Modify Computer AD object.

    This command will allow editing of a computer account in the Active
    Directory domain. You will then be able to add or change attributes and
    their values.

    The computername specified on the command is the sAMaccountName with or
    without the trailing $ (dollar sign).

    The command may be run from the root userid or another authorized userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool computer edit Computer1 -H ldap://samba.samdom.example.com \\
        -U administrator --password=passw1rd

    Example1 shows how to edit a computers attributes in the domain against a
    remote LDAP server.

    The -H parameter is used to specify the remote target server.

    Example2:
    samba-tool computer edit Computer2

    Example2 shows how to edit a computers attributes in the domain against a
    local LDAP server.

    Example3:
    samba-tool computer edit Computer3 --editor=nano

    Example3 shows how to edit a computers attributes in the domain against a
    local LDAP server using the 'nano' editor.
    """
    synopsis = "%prog <computername> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--editor", help="Editor to use instead of the system default,"
               " or 'vi' if no system default is set.", type=str),
    ]

    takes_args = ["computername"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, computername, credopts=None, sambaopts=None, versionopts=None,
            H=None, editor=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        samaccountname = computername
        if not computername.endswith('$'):
            samaccountname = "%s$" % computername

        filter = ("(&(sAMAccountType=%d)(sAMAccountName=%s))" %
                  (dsdb.ATYPE_WORKSTATION_TRUST,
                   ldb.binary_encode(samaccountname)))

        domaindn = samdb.domain_dn()

        try:
            res = samdb.search(base=domaindn,
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE)
            computer_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find computer "%s"' % (computername))

        if len(res) != 1:
            raise CommandError('Invalid number of results: for "%s": %d' %
                               ((computername), len(res)))

        msg = res[0]
        result_ldif = common.get_ldif_for_editor(samdb, msg)

        if editor is None:
            editor = os.environ.get('EDITOR')
            if editor is None:
                editor = 'vi'

        with tempfile.NamedTemporaryFile(suffix=".tmp") as t_file:
            t_file.write(get_bytes(result_ldif))
            t_file.flush()
            try:
                check_call([editor, t_file.name])
            except CalledProcessError as e:
                raise CalledProcessError("ERROR: ", e)
            with open(t_file.name) as edited_file:
                edited_message = edited_file.read()

        msgs_edited = samdb.parse_ldif(edited_message)
        msg_edited = next(msgs_edited)[1]

        res_msg_diff = samdb.msg_diff(msg, msg_edited)
        if len(res_msg_diff) == 0:
            self.outf.write("Nothing to do\n")
            return

        try:
            samdb.modify(res_msg_diff)
        except Exception as e:
            raise CommandError("Failed to modify computer '%s': " %
                               (computername, e))

        self.outf.write("Modified computer '%s' successfully\n" % computername)

class cmd_computer_list(Command):
    """List all computers."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("-b", "--base-dn",
               help="Specify base DN to use",
               type=str),
        Option("--full-dn", dest="full_dn",
               default=False,
               action="store_true",
               help="Display DN instead of the sAMAccountName.")
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self,
            sambaopts=None,
            credopts=None,
            versionopts=None,
            H=None,
            base_dn=None,
            full_dn=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        filter = "(sAMAccountType=%u)" % (dsdb.ATYPE_WORKSTATION_TRUST)

        search_dn = samdb.domain_dn()
        if base_dn:
            search_dn = samdb.normalize_dn_in_domain(base_dn)

        res = samdb.search(search_dn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression=filter,
                           attrs=["samaccountname"])
        if (len(res) == 0):
            return

        for msg in res:
            if full_dn:
                self.outf.write("%s\n" % msg.get("dn"))
                continue

            self.outf.write("%s\n" % msg.get("samaccountname", idx=0))


class cmd_computer_show(Command):
    """Display a computer AD object.

This command displays a computer account and it's attributes in the Active
Directory domain.
The computername specified on the command is the sAMAccountName.

The command may be run from the root userid or another authorized
userid.

The -H or --URL= option can be used to execute the command against a remote
server.

Example1:
samba-tool computer show Computer1 -H ldap://samba.samdom.example.com \\
    -U administrator

Example1 shows how display a computers attributes in the domain against a
remote LDAP server.

The -H parameter is used to specify the remote target server.

Example2:
samba-tool computer show Computer2

Example2 shows how to display a computers attributes in the domain against a
local LDAP server.

Example3:
samba-tool computer show Computer2 --attributes=objectSid,operatingSystem

Example3 shows how to display a computers objectSid and operatingSystem
attribute.
"""
    synopsis = "%prog <computername> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--attributes",
               help=("Comma separated list of attributes, "
                     "which will be printed."),
               type=str, dest="computer_attrs"),
    ]

    takes_args = ["computername"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, computername, credopts=None, sambaopts=None, versionopts=None,
            H=None, computer_attrs=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        attrs = None
        if computer_attrs:
            attrs = computer_attrs.split(",")

        samaccountname = computername
        if not computername.endswith('$'):
            samaccountname = "%s$" % computername

        filter = ("(&(sAMAccountType=%d)(sAMAccountName=%s))" %
                  (dsdb.ATYPE_WORKSTATION_TRUST,
                   ldb.binary_encode(samaccountname)))

        domaindn = samdb.domain_dn()

        try:
            res = samdb.search(base=domaindn, expression=filter,
                               scope=ldb.SCOPE_SUBTREE, attrs=attrs)
            computer_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find computer "%s"' %
                               samaccountname)

        for msg in res:
            computer_ldif = common.get_ldif_for_editor(samdb, msg)
            self.outf.write(computer_ldif)


class cmd_computer_move(Command):
    """Move a computer to an organizational unit/container."""

    synopsis = "%prog computername <new_ou_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["computername", "new_ou_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, computername, new_ou_dn, credopts=None, sambaopts=None,
            versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        samaccountname = computername
        if not computername.endswith('$'):
            samaccountname = "%s$" % computername

        filter = ("(&(sAMAccountName=%s)(sAMAccountType=%u))" %
                  (ldb.binary_encode(samaccountname),
                   dsdb.ATYPE_WORKSTATION_TRUST))
        try:
            res = samdb.search(base=domain_dn,
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE)
            computer_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find computer "%s"' % (computername))

        full_new_ou_dn = ldb.Dn(samdb, new_ou_dn)
        if not full_new_ou_dn.is_child_of(domain_dn):
            full_new_ou_dn.add_base(domain_dn)
        new_computer_dn = ldb.Dn(samdb, str(computer_dn))
        new_computer_dn.remove_base_components(len(computer_dn) -1)
        new_computer_dn.add_base(full_new_ou_dn)
        try:
            samdb.rename(computer_dn, new_computer_dn)
        except Exception as e:
            raise CommandError('Failed to move computer "%s"' % computername, e)
        self.outf.write('Moved computer "%s" to "%s"\n' %
                        (computername, new_ou_dn))


class cmd_computer(SuperCommand):
    """Computer management."""

    subcommands = {}
    subcommands["create"] = cmd_computer_create()
    subcommands["delete"] = cmd_computer_delete()
    subcommands["edit"] = cmd_computer_edit()
    subcommands["list"] = cmd_computer_list()
    subcommands["show"] = cmd_computer_show()
    subcommands["move"] = cmd_computer_move()

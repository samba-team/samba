# implement samba_tool gpo commands
#
# Copyright Andrew Tridgell 2010
# Copyright Amitay Isaacs 2011-2012 <amitay@gmail.com>
#
# based on C implementation by Guenther Deschner and Wilco Baan Hofman
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
import samba.getopt as options
import ldb
import re
import xml.etree.ElementTree as ET
import shutil
import tempfile

from samba.auth import system_session
from samba.netcmd import (
    Command,
    CommandError,
    Option,
    SuperCommand,
)
from samba.samdb import SamDB
from samba import dsdb
from samba.dcerpc import security
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import preg
import samba.security
import samba.auth
from samba.auth import AUTH_SESSION_INFO_DEFAULT_GROUPS, AUTH_SESSION_INFO_AUTHENTICATED, AUTH_SESSION_INFO_SIMPLE_PRIVILEGES
from samba.netcmd.common import netcmd_finddc
from samba import policy
from samba.samba3 import libsmb_samba_internal as libsmb
from samba import NTSTATUSError
import uuid
from samba.ntacls import dsacl2fsacl
from samba.dcerpc import nbt
from samba.net import Net
from samba.gp_parse import GPParser, GPNoParserException, GPGeneralizeException
from samba.gp_parse.gp_pol import GPPolParser
from samba.gp_parse.gp_ini import (
    GPIniParser,
    GPTIniParser,
    GPFDeploy1IniParser,
    GPScriptsIniParser
)
from samba.gp_parse.gp_csv import GPAuditCsvParser
from samba.gp_parse.gp_inf import GptTmplInfParser
from samba.gp_parse.gp_aas import GPAasParser
from samba import param
from samba.netcmd.common import attr_default
from samba.common import get_bytes, get_string
from configparser import ConfigParser
from io import StringIO, BytesIO
from samba.gp.vgp_files_ext import calc_mode, stat_from_mode
import hashlib
import json
from samba.registry import str_regtype
from samba.ntstatus import (
    NT_STATUS_OBJECT_NAME_INVALID,
    NT_STATUS_OBJECT_NAME_NOT_FOUND,
    NT_STATUS_OBJECT_PATH_NOT_FOUND,
    NT_STATUS_OBJECT_NAME_COLLISION,
    NT_STATUS_ACCESS_DENIED
)
from samba.netcmd.gpcommon import (
    create_directory_hier,
    smb_connection,
    get_gpo_dn
)
from samba.policies import RegistryGroupPolicies
from samba.dcerpc.misc import REG_MULTI_SZ
from samba.gp.gpclass import register_gp_extension, list_gp_extensions, \
    unregister_gp_extension


def gpo_flags_string(value):
    """return gpo flags string"""
    flags = policy.get_gpo_flags(value)
    if not flags:
        ret = 'NONE'
    else:
        ret = ' '.join(flags)
    return ret


def gplink_options_string(value):
    """return gplink options string"""
    options = policy.get_gplink_options(value)
    if not options:
        ret = 'NONE'
    else:
        ret = ' '.join(options)
    return ret


def parse_gplink(gplink):
    """parse a gPLink into an array of dn and options"""
    ret = []

    if gplink.strip() == '':
        return ret

    a = gplink.split(']')
    for g in a:
        if not g:
            continue
        d = g.split(';')
        if len(d) != 2 or not d[0].startswith("[LDAP://"):
            raise RuntimeError("Badly formed gPLink '%s'" % g)
        ret.append({'dn': d[0][8:], 'options': int(d[1])})
    return ret


def encode_gplink(gplist):
    """Encode an array of dn and options into gPLink string"""
    ret = "".join("[LDAP://%s;%d]" % (g['dn'], g['options']) for g in gplist)
    return ret


def dc_url(lp, creds, url=None, dc=None):
    """If URL is not specified, return URL for writable DC.
    If dc is provided, use that to construct ldap URL"""

    if url is None:
        if dc is None:
            try:
                dc = netcmd_finddc(lp, creds)
            except Exception as e:
                raise RuntimeError("Could not find a DC for domain", e)
        url = 'ldap://' + dc
    return url


def get_gpo_info(samdb, gpo=None, displayname=None, dn=None,
                 sd_flags=(security.SECINFO_OWNER |
                           security.SECINFO_GROUP |
                           security.SECINFO_DACL |
                           security.SECINFO_SACL)):
    """Get GPO information using gpo, displayname or dn"""

    policies_dn = samdb.get_default_basedn()
    policies_dn.add_child(ldb.Dn(samdb, "CN=Policies,CN=System"))

    base_dn = policies_dn
    search_expr = "(objectClass=groupPolicyContainer)"
    search_scope = ldb.SCOPE_ONELEVEL

    if gpo is not None:
        search_expr = "(&(objectClass=groupPolicyContainer)(name=%s))" % ldb.binary_encode(gpo)

    if displayname is not None:
        search_expr = "(&(objectClass=groupPolicyContainer)(displayname=%s))" % ldb.binary_encode(displayname)

    if dn is not None:
        base_dn = dn
        search_scope = ldb.SCOPE_BASE

    try:
        msg = samdb.search(base=base_dn, scope=search_scope,
                           expression=search_expr,
                           attrs=['nTSecurityDescriptor',
                                  'versionNumber',
                                  'flags',
                                  'name',
                                  'displayName',
                                  'gPCFileSysPath',
                                  'gPCMachineExtensionNames',
                                  'gPCUserExtensionNames'],
                           controls=['sd_flags:1:%d' % sd_flags])
    except Exception as e:
        if gpo is not None:
            mesg = "Cannot get information for GPO %s" % gpo
        else:
            mesg = "Cannot get information for GPOs"
        raise CommandError(mesg, e)

    return msg


def get_gpo_containers(samdb, gpo):
    """lists dn of containers for a GPO"""

    search_expr = "(&(objectClass=*)(gPLink=*%s*))" % gpo
    try:
        msg = samdb.search(expression=search_expr, attrs=['gPLink'])
    except Exception as e:
        raise CommandError("Could not find container(s) with GPO %s" % gpo, e)

    return msg


def del_gpo_link(samdb, container_dn, gpo):
    """delete GPO link for the container"""
    # Check if valid Container DN and get existing GPlinks
    try:
        msg = samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                           expression="(objectClass=*)",
                           attrs=['gPLink'])[0]
    except Exception as e:
        raise CommandError("Container '%s' does not exist" % container_dn, e)

    found = False
    gpo_dn = str(get_gpo_dn(samdb, gpo))
    if 'gPLink' in msg:
        gplist = parse_gplink(str(msg['gPLink'][0]))
        for g in gplist:
            if g['dn'].lower() == gpo_dn.lower():
                gplist.remove(g)
                found = True
                break
    else:
        raise CommandError("No GPO(s) linked to this container")

    if not found:
        raise CommandError("GPO '%s' not linked to this container" % gpo)

    m = ldb.Message()
    m.dn = container_dn
    if gplist:
        gplink_str = encode_gplink(gplist)
        m['r0'] = ldb.MessageElement(gplink_str, ldb.FLAG_MOD_REPLACE, 'gPLink')
    else:
        m['d0'] = ldb.MessageElement(msg['gPLink'][0], ldb.FLAG_MOD_DELETE, 'gPLink')
    try:
        samdb.modify(m)
    except Exception as e:
        raise CommandError("Error removing GPO from container", e)


def parse_unc(unc):
    """Parse UNC string into a hostname, a service, and a filepath"""
    tmp = []
    if unc.startswith('\\\\'):
        tmp = unc[2:].split('\\', 2)
    elif unc.startswith('//'):
        tmp = unc[2:].split('/', 2)

    if len(tmp) != 3:
        raise ValueError("Invalid UNC string: %s" % unc)

    return tmp


def find_parser(name, flags=re.IGNORECASE):
    if re.match(r'fdeploy1\.ini$', name, flags=flags):
        return GPFDeploy1IniParser()
    if re.match(r'audit\.csv$', name, flags=flags):
        return GPAuditCsvParser()
    if re.match(r'GptTmpl\.inf$', name, flags=flags):
        return GptTmplInfParser()
    if re.match(r'GPT\.INI$', name, flags=flags):
        return GPTIniParser()
    if re.match(r'scripts\.ini$', name, flags=flags):
        return GPScriptsIniParser()
    if re.match(r'psscripts\.ini$', name, flags=flags):
        return GPScriptsIniParser()
    if re.match(r'GPE\.INI$', name, flags=flags):
        # This file does not appear in the protocol specifications!
        #
        # It appears to be a legacy file used to maintain gPCUserExtensionNames
        # and gPCMachineExtensionNames. We should just copy the file as binary.
        return GPParser()
    if re.match(r'.*\.ini$', name, flags=flags):
        return GPIniParser()
    if re.match(r'.*\.pol$', name, flags=flags):
        return GPPolParser()
    if re.match(r'.*\.aas$', name, flags=flags):
        return GPAasParser()

    return GPParser()


def backup_directory_remote_to_local(conn, remotedir, localdir):
    SUFFIX = '.SAMBABACKUP'
    if not os.path.isdir(localdir):
        os.mkdir(localdir)
    r_dirs = [ remotedir ]
    l_dirs = [ localdir ]
    while r_dirs:
        r_dir = r_dirs.pop()
        l_dir = l_dirs.pop()

        dirlist = conn.list(r_dir, attribs=attr_flags)
        dirlist.sort(key=lambda x : x['name'])
        for e in dirlist:
            r_name = r_dir + '\\' + e['name']
            l_name = os.path.join(l_dir, e['name'])

            if e['attrib'] & libsmb.FILE_ATTRIBUTE_DIRECTORY:
                r_dirs.append(r_name)
                l_dirs.append(l_name)
                os.mkdir(l_name)
            else:
                data = conn.loadfile(r_name)
                with open(l_name + SUFFIX, 'wb') as f:
                    f.write(data)

                parser = find_parser(e['name'])
                parser.parse(data)
                parser.write_xml(l_name + '.xml')


attr_flags = libsmb.FILE_ATTRIBUTE_SYSTEM | \
             libsmb.FILE_ATTRIBUTE_DIRECTORY | \
             libsmb.FILE_ATTRIBUTE_ARCHIVE | \
             libsmb.FILE_ATTRIBUTE_HIDDEN


def copy_directory_remote_to_local(conn, remotedir, localdir):
    if not os.path.isdir(localdir):
        os.mkdir(localdir)
    r_dirs = [remotedir]
    l_dirs = [localdir]
    while r_dirs:
        r_dir = r_dirs.pop()
        l_dir = l_dirs.pop()

        dirlist = conn.list(r_dir, attribs=attr_flags)
        dirlist.sort(key=lambda x : x['name'])
        for e in dirlist:
            r_name = r_dir + '\\' + e['name']
            l_name = os.path.join(l_dir, e['name'])

            if e['attrib'] & libsmb.FILE_ATTRIBUTE_DIRECTORY:
                r_dirs.append(r_name)
                l_dirs.append(l_name)
                os.mkdir(l_name)
            else:
                data = conn.loadfile(r_name)
                with open(l_name, 'wb') as f:
                    f.write(data)


def copy_directory_local_to_remote(conn, localdir, remotedir,
                                   ignore_existing_dir=False,
                                   keep_existing_files=False):
    if not conn.chkpath(remotedir):
        conn.mkdir(remotedir)
    l_dirs = [localdir]
    r_dirs = [remotedir]
    while l_dirs:
        l_dir = l_dirs.pop()
        r_dir = r_dirs.pop()

        dirlist = os.listdir(l_dir)
        dirlist.sort()
        for e in dirlist:
            l_name = os.path.join(l_dir, e)
            r_name = r_dir + '\\' + e

            if os.path.isdir(l_name):
                l_dirs.append(l_name)
                r_dirs.append(r_name)
                try:
                    conn.mkdir(r_name)
                except NTSTATUSError:
                    if not ignore_existing_dir:
                        raise
            else:
                if keep_existing_files:
                    try:
                        conn.loadfile(r_name)
                        continue
                    except NTSTATUSError:
                        pass

                with open(l_name, 'rb') as f:
                    conn.savefile(r_name, f.read())


class GPOCommand(Command):
    def construct_tmpdir(self, tmpdir, gpo):
        """Ensure that the temporary directory structure used in fetch,
        backup, create, and restore is consistent.

        If --tmpdir is used the named directory must be present, which may
        contain a 'policy' subdirectory, but 'policy' must not itself have
        a subdirectory with the gpo name. The policy and gpo directories
        will be created.

        If --tmpdir is not used, a temporary directory is securely created.
        """
        if tmpdir is None:
            tmpdir = tempfile.mkdtemp()
            print("Using temporary directory %s (use --tmpdir to change)" % tmpdir,
                  file=self.outf)

        if not os.path.isdir(tmpdir):
            raise CommandError("Temporary directory '%s' does not exist" % tmpdir)

        localdir = os.path.join(tmpdir, "policy")
        if not os.path.isdir(localdir):
            os.mkdir(localdir)

        gpodir = os.path.join(localdir, gpo)
        if os.path.isdir(gpodir):
            raise CommandError(
                "GPO directory '%s' already exists, refusing to overwrite" % gpodir)

        try:
            os.mkdir(gpodir)
        except (IOError, OSError) as e:
            raise CommandError("Error creating teporary GPO directory", e)

        return tmpdir, gpodir

    def samdb_connect(self):
        """make a ldap connection to the server"""
        try:
            self.samdb = SamDB(url=self.url,
                               session_info=system_session(),
                               credentials=self.creds, lp=self.lp)
        except Exception as e:
            raise CommandError("LDAP connection to %s failed " % self.url, e)


class cmd_listall(GPOCommand):
    """List all GPOs."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H")
    ]

    def run(self, H=None, sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        self.samdb_connect()

        msg = get_gpo_info(self.samdb, None)

        for m in msg:
            self.outf.write("GPO          : %s\n" % m['name'][0])
            self.outf.write("display name : %s\n" % m['displayName'][0])
            self.outf.write("path         : %s\n" % m['gPCFileSysPath'][0])
            self.outf.write("dn           : %s\n" % m.dn)
            self.outf.write("version      : %s\n" % attr_default(m, 'versionNumber', '0'))
            self.outf.write("flags        : %s\n" % gpo_flags_string(int(attr_default(m, 'flags', 0))))
            self.outf.write("\n")


class cmd_list(GPOCommand):
    """List GPOs for an account."""

    synopsis = "%prog <username|machinename> [options]"

    takes_args = ['accountname']
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H")
    ]

    def run(self, accountname, H=None, sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        self.samdb_connect()

        try:
            msg = self.samdb.search(expression='(&(|(samAccountName=%s)(samAccountName=%s$))(objectClass=User))' %
                                    (ldb.binary_encode(accountname), ldb.binary_encode(accountname)))
            user_dn = msg[0].dn
        except Exception:
            raise CommandError("Failed to find account %s" % accountname)

        # check if its a computer account
        try:
            msg = self.samdb.search(base=user_dn, scope=ldb.SCOPE_BASE, attrs=['objectClass'])[0]
            is_computer = 'computer' in msg['objectClass']
        except Exception:
            raise CommandError("Failed to find objectClass for %s" % accountname)

        session_info_flags = (AUTH_SESSION_INFO_DEFAULT_GROUPS |
                              AUTH_SESSION_INFO_AUTHENTICATED)

        # When connecting to a remote server, don't look up the local privilege DB
        if self.url is not None and self.url.startswith('ldap'):
            session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES

        session = samba.auth.user_session(self.samdb, lp_ctx=self.lp, dn=user_dn,
                                          session_info_flags=session_info_flags)

        token = session.security_token

        gpos = []

        inherit = True
        dn = ldb.Dn(self.samdb, str(user_dn)).parent()
        while True:
            msg = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=['gPLink', 'gPOptions'])[0]
            if 'gPLink' in msg:
                glist = parse_gplink(str(msg['gPLink'][0]))
                for g in glist:
                    if not inherit and not (g['options'] & dsdb.GPLINK_OPT_ENFORCE):
                        continue
                    if g['options'] & dsdb.GPLINK_OPT_DISABLE:
                        continue

                    try:
                        sd_flags = (security.SECINFO_OWNER |
                                    security.SECINFO_GROUP |
                                    security.SECINFO_DACL)
                        gmsg = self.samdb.search(base=g['dn'], scope=ldb.SCOPE_BASE,
                                                 attrs=['name', 'displayName', 'flags',
                                                        'nTSecurityDescriptor'],
                                                 controls=['sd_flags:1:%d' % sd_flags])
                        secdesc_ndr = gmsg[0]['nTSecurityDescriptor'][0]
                        secdesc = ndr_unpack(security.descriptor, secdesc_ndr)
                    except Exception:
                        self.outf.write("Failed to fetch gpo object with nTSecurityDescriptor %s\n" %
                                        g['dn'])
                        continue

                    try:
                        samba.security.access_check(secdesc, token,
                                                    security.SEC_STD_READ_CONTROL |
                                                    security.SEC_ADS_LIST |
                                                    security.SEC_ADS_READ_PROP)
                    except RuntimeError:
                        self.outf.write("Failed access check on %s\n" % msg.dn)
                        continue

                    # check the flags on the GPO
                    flags = int(attr_default(gmsg[0], 'flags', 0))
                    if is_computer and (flags & dsdb.GPO_FLAG_MACHINE_DISABLE):
                        continue
                    if not is_computer and (flags & dsdb.GPO_FLAG_USER_DISABLE):
                        continue
                    gpos.append((gmsg[0]['displayName'][0], gmsg[0]['name'][0]))

            # check if this blocks inheritance
            gpoptions = int(attr_default(msg, 'gPOptions', 0))
            if gpoptions & dsdb.GPO_BLOCK_INHERITANCE:
                inherit = False

            if dn == self.samdb.get_default_basedn():
                break
            dn = dn.parent()

        if is_computer:
            msg_str = 'computer'
        else:
            msg_str = 'user'

        self.outf.write("GPOs for %s %s\n" % (msg_str, accountname))
        for g in gpos:
            self.outf.write("    %s %s\n" % (g[0], g[1]))


class cmd_show(GPOCommand):
    """Show information for a GPO."""

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str)
    ]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        self.samdb_connect()

        try:
            msg = get_gpo_info(self.samdb, gpo)[0]
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)

        try:
            secdesc_ndr = msg['nTSecurityDescriptor'][0]
            secdesc = ndr_unpack(security.descriptor, secdesc_ndr)
            secdesc_sddl = secdesc.as_sddl()
        except Exception:
            secdesc_sddl = "<hidden>"

        self.outf.write("GPO          : %s\n" % msg['name'][0])
        self.outf.write("display name : %s\n" % msg['displayName'][0])
        self.outf.write("path         : %s\n" % msg['gPCFileSysPath'][0])
        if 'gPCMachineExtensionNames' in msg:
            self.outf.write("Machine Exts : %s\n" % msg['gPCMachineExtensionNames'][0])
        if 'gPCUserExtensionNames' in msg:
            self.outf.write("User Exts    : %s\n" % msg['gPCUserExtensionNames'][0])
        self.outf.write("dn           : %s\n" % msg.dn)
        self.outf.write("version      : %s\n" % attr_default(msg, 'versionNumber', '0'))
        self.outf.write("flags        : %s\n" % gpo_flags_string(int(attr_default(msg, 'flags', 0))))
        self.outf.write("ACL          : %s\n" % secdesc_sddl)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        pol_file = '\\'.join([realm.lower(), 'Policies', gpo,
                                '%s\\Registry.pol'])
        policy_defs = []
        for policy_class in ['MACHINE', 'USER']:
            try:
                pol_data = ndr_unpack(preg.file,
                                      conn.loadfile(pol_file % policy_class))
            except NTSTATUSError as e:
                if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                                 NT_STATUS_OBJECT_NAME_NOT_FOUND,
                                 NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                    continue # The file doesn't exist, so there is nothing to list
                if e.args[0] == NT_STATUS_ACCESS_DENIED:
                    raise CommandError("The authenticated user does "
                                       "not have sufficient privileges")
                raise

            for entry in pol_data.entries:
                if entry.valuename == "**delvals.":
                    continue
                defs = {}
                defs['keyname'] = entry.keyname
                defs['valuename'] = entry.valuename
                defs['class'] = policy_class
                defs['type'] = str_regtype(entry.type)
                defs['data'] = entry.data
                # Bytes aren't JSON serializable
                if type(defs['data']) == bytes:
                    if entry.type == REG_MULTI_SZ:
                        data = defs['data'].decode('utf-16-le')
                        defs['data'] = data.rstrip('\x00').split('\x00')
                    else:
                        defs['data'] = list(defs['data'])
                policy_defs.append(defs)
        self.outf.write("Policies     :\n")
        json.dump(policy_defs, self.outf, indent=4)
        self.outf.write("\n")


class cmd_load(GPOCommand):
    """Load policies onto a GPO.

    Reads json from standard input until EOF, unless a json formatted
    file is provided via --content.

    Example json_input:
    [
        {
            "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
            "valuename": "StartPage",
            "class": "USER",
            "type": "REG_SZ",
            "data": "homepage"
        },
        {
            "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
            "valuename": "URL",
            "class": "USER",
            "type": "REG_SZ",
            "data": "google.com"
        },
        {
            "keyname": "Software\\Microsoft\\Internet Explorer\\Toolbar",
            "valuename": "IEToolbar",
            "class": "USER",
            "type": "REG_BINARY",
            "data": [0]
        },
        {
            "keyname": "Software\\Policies\\Microsoft\\InputPersonalization",
            "valuename": "RestrictImplicitTextCollection",
            "class": "USER",
            "type": "REG_DWORD",
            "data": 1
        }
    ]

    Valid class attributes: MACHINE|USER|BOTH
    Data arrays are interpreted as bytes.

    The --machine-ext-name and --user-ext-name options are multi-value inputs
    which respectively set the gPCMachineExtensionNames and gPCUserExtensionNames
    ldap attributes on the GPO. These attributes must be set to the correct GUID
    names for Windows Group Policy to work correctly. These GUIDs represent
    the client side extensions to apply on the machine. Linux Group Policy does
    not enforce this constraint.
    {35378EAC-683F-11D2-A89A-00C04FBBCFA2} is provided by default, which
    enables most Registry policies.
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--content", help="JSON file of policy inputs", type=str),
        Option("--machine-ext-name",
            action="append", dest="machine_exts",
            default=['{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'],
            help="A machine extension name to add to gPCMachineExtensionNames"),
        Option("--user-ext-name",
            action="append", dest="user_exts",
            default=['{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'],
            help="A user extension name to add to gPCUserExtensionNames"),
        Option("--replace", action='store_true', default=False,
               help="Replace the existing Group Policies, rather than merging")
    ]

    def run(self, gpo, H=None, content=None,
            machine_exts=None,
            user_exts=None,
            replace=False, sambaopts=None, credopts=None, versionopts=None):
        if machine_exts is None:
            machine_exts = ['{35378EAC-683F-11D2-A89A-00C04FBBCFA2}']
        if user_exts is None:
            user_exts = ['{35378EAC-683F-11D2-A89A-00C04FBBCFA2}']
        if content is None:
            policy_defs = json.loads(sys.stdin.read())
        elif os.path.exists(content):
            with open(content, 'rb') as r:
                policy_defs = json.load(r)
        else:
            raise CommandError("The JSON content file does not exist")

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)
        self.url = dc_url(self.lp, self.creds, H)
        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)
        for ext_name in machine_exts:
            reg.register_extension_name(ext_name, 'gPCMachineExtensionNames')
        for ext_name in user_exts:
            reg.register_extension_name(ext_name, 'gPCUserExtensionNames')
        try:
            if replace:
                reg.replace_s(policy_defs)
            else:
                reg.merge_s(policy_defs)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise


class cmd_remove(GPOCommand):
    """Remove policies from a GPO.

    Reads json from standard input until EOF, unless a json formatted
    file is provided via --content.

    Example json_input:
    [
        {
            "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
            "valuename": "StartPage",
            "class": "USER",
        },
        {
            "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
            "valuename": "URL",
            "class": "USER",
        },
        {
            "keyname": "Software\\Microsoft\\Internet Explorer\\Toolbar",
            "valuename": "IEToolbar",
            "class": "USER"
        },
        {
            "keyname": "Software\\Policies\\Microsoft\\InputPersonalization",
            "valuename": "RestrictImplicitTextCollection",
            "class": "USER"
        }
    ]

    Valid class attributes: MACHINE|USER|BOTH
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--content", help="JSON file of policy inputs", type=str),
        Option("--machine-ext-name",
            action="append", default=[], dest="machine_exts",
            help="A machine extension name to remove from gPCMachineExtensionNames"),
        Option("--user-ext-name",
            action="append", default=[], dest="user_exts",
            help="A user extension name to remove from gPCUserExtensionNames")
    ]

    def run(self, gpo, H=None, content=None, machine_exts=None, user_exts=None,
            sambaopts=None, credopts=None, versionopts=None):
        if machine_exts is None:
            machine_exts = []
        if user_exts is None:
            user_exts = []
        if content is None:
            policy_defs = json.loads(sys.stdin.read())
        elif os.path.exists(content):
            with open(content, 'rb') as r:
                policy_defs = json.load(r)
        else:
            raise CommandError("The JSON content file does not exist")

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)
        self.url = dc_url(self.lp, self.creds, H)
        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)
        for ext_name in machine_exts:
            reg.unregister_extension_name(ext_name, 'gPCMachineExtensionNames')
        for ext_name in user_exts:
            reg.unregister_extension_name(ext_name, 'gPCUserExtensionNames')
        try:
            reg.remove_s(policy_defs)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise


class cmd_getlink(GPOCommand):
    """List GPO Links for a container."""

    synopsis = "%prog <container_dn> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['container_dn']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str)
    ]

    def run(self, container_dn, H=None, sambaopts=None, credopts=None,
            versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        self.samdb_connect()

        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPLink'])[0]
        except Exception:
            raise CommandError("Container '%s' does not exist" % container_dn)

        if 'gPLink' in msg and msg['gPLink']:
            self.outf.write("GPO(s) linked to DN %s\n" % container_dn)
            gplist = parse_gplink(str(msg['gPLink'][0]))
            for g in gplist:
                msg = get_gpo_info(self.samdb, dn=g['dn'])
                self.outf.write("    GPO     : %s\n" % msg[0]['name'][0])
                self.outf.write("    Name    : %s\n" % msg[0]['displayName'][0])
                self.outf.write("    Options : %s\n" % gplink_options_string(g['options']))
                self.outf.write("\n")
        else:
            self.outf.write("No GPO(s) linked to DN=%s\n" % container_dn)


class cmd_setlink(GPOCommand):
    """Add or update a GPO link to a container."""

    synopsis = "%prog <container_dn> <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['container_dn', 'gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--disable", dest="disabled", default=False, action='store_true',
               help="Disable policy"),
        Option("--enforce", dest="enforced", default=False, action='store_true',
               help="Enforce policy")
    ]

    def run(self, container_dn, gpo, H=None, disabled=False, enforced=False,
            sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        self.samdb_connect()

        gplink_options = 0
        if disabled:
            gplink_options |= dsdb.GPLINK_OPT_DISABLE
        if enforced:
            gplink_options |= dsdb.GPLINK_OPT_ENFORCE

        # Check if valid GPO DN
        try:
            get_gpo_info(self.samdb, gpo=gpo)[0]
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)
        gpo_dn = str(get_gpo_dn(self.samdb, gpo))

        # Check if valid Container DN
        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPLink'])[0]
        except Exception:
            raise CommandError("Container '%s' does not exist" % container_dn)

        # Update existing GPlinks or Add new one
        existing_gplink = False
        if 'gPLink' in msg:
            gplist = parse_gplink(str(msg['gPLink'][0]))
            existing_gplink = True
            found = False
            for g in gplist:
                if g['dn'].lower() == gpo_dn.lower():
                    g['options'] = gplink_options
                    found = True
                    break
            if found:
                raise CommandError("GPO '%s' already linked to this container" % gpo)
            else:
                gplist.insert(0, {'dn': gpo_dn, 'options': gplink_options})
        else:
            gplist = []
            gplist.append({'dn': gpo_dn, 'options': gplink_options})

        gplink_str = encode_gplink(gplist)

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, container_dn)

        if existing_gplink:
            m['new_value'] = ldb.MessageElement(gplink_str, ldb.FLAG_MOD_REPLACE, 'gPLink')
        else:
            m['new_value'] = ldb.MessageElement(gplink_str, ldb.FLAG_MOD_ADD, 'gPLink')

        try:
            self.samdb.modify(m)
        except Exception as e:
            raise CommandError("Error adding GPO Link", e)

        self.outf.write("Added/Updated GPO link\n")
        cmd_getlink().run(container_dn, H, sambaopts, credopts, versionopts)


class cmd_dellink(GPOCommand):
    """Delete GPO link from a container."""

    synopsis = "%prog <container_dn> <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['container', 'gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
    ]

    def run(self, container, gpo, H=None, sambaopts=None, credopts=None,
            versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        self.samdb_connect()

        # Check if valid GPO
        try:
            get_gpo_info(self.samdb, gpo=gpo)[0]
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)

        container_dn = ldb.Dn(self.samdb, container)
        del_gpo_link(self.samdb, container_dn, gpo)
        self.outf.write("Deleted GPO link.\n")
        cmd_getlink().run(container_dn, H, sambaopts, credopts, versionopts)


class cmd_listcontainers(GPOCommand):
    """List all linked containers for a GPO."""

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str)
    ]

    def run(self, gpo, H=None, sambaopts=None, credopts=None,
            versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        self.samdb_connect()

        msg = get_gpo_containers(self.samdb, gpo)
        if len(msg):
            self.outf.write("Container(s) using GPO %s\n" % gpo)
            for m in msg:
                self.outf.write("    DN: %s\n" % m['dn'])
        else:
            self.outf.write("No Containers using GPO %s\n" % gpo)


class cmd_getinheritance(GPOCommand):
    """Get inheritance flag for a container."""

    synopsis = "%prog <container_dn> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['container_dn']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str)
    ]

    def run(self, container_dn, H=None, sambaopts=None, credopts=None,
            versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        self.samdb_connect()

        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPOptions'])[0]
        except Exception:
            raise CommandError("Container '%s' does not exist" % container_dn)

        inheritance = 0
        if 'gPOptions' in msg:
            inheritance = int(msg['gPOptions'][0])

        if inheritance == dsdb.GPO_BLOCK_INHERITANCE:
            self.outf.write("Container has GPO_BLOCK_INHERITANCE\n")
        else:
            self.outf.write("Container has GPO_INHERIT\n")


class cmd_setinheritance(GPOCommand):
    """Set inheritance flag on a container."""

    synopsis = "%prog <container_dn> <block|inherit> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['container_dn', 'inherit_state']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str)
    ]

    def run(self, container_dn, inherit_state, H=None, sambaopts=None, credopts=None,
            versionopts=None):

        if inherit_state.lower() == 'block':
            inheritance = dsdb.GPO_BLOCK_INHERITANCE
        elif inherit_state.lower() == 'inherit':
            inheritance = dsdb.GPO_INHERIT
        else:
            raise CommandError("Unknown inheritance state (%s)" % inherit_state)

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        self.samdb_connect()
        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPOptions'])[0]
        except Exception:
            raise CommandError("Container '%s' does not exist" % container_dn)

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, container_dn)

        if 'gPOptions' in msg:
            m['new_value'] = ldb.MessageElement(str(inheritance), ldb.FLAG_MOD_REPLACE, 'gPOptions')
        else:
            m['new_value'] = ldb.MessageElement(str(inheritance), ldb.FLAG_MOD_ADD, 'gPOptions')

        try:
            self.samdb.modify(m)
        except Exception as e:
            raise CommandError("Error setting inheritance state %s" % inherit_state, e)


class cmd_fetch(GPOCommand):
    """Download a GPO."""

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--tmpdir", help="Temporary directory for copying policy files", type=str)
    ]

    def run(self, gpo, H=None, tmpdir=None, sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        self.samdb_connect()
        try:
            msg = get_gpo_info(self.samdb, gpo)[0]
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)

        # verify UNC path
        unc = str(msg['gPCFileSysPath'][0])
        try:
            [dom_name, service, sharepath] = parse_unc(unc)
        except ValueError:
            raise CommandError("Invalid GPO path (%s)" % unc)

        # SMB connect to DC
        conn = smb_connection(dc_hostname, service, lp=self.lp,
                              creds=self.creds)

        # Copy GPT
        tmpdir, gpodir = self.construct_tmpdir(tmpdir, gpo)

        try:
            copy_directory_remote_to_local(conn, sharepath, gpodir)
        except Exception as e:
            # FIXME: Catch more specific exception
            raise CommandError("Error copying GPO from DC", e)
        self.outf.write('GPO copied to %s\n' % gpodir)


class cmd_backup(GPOCommand):
    """Backup a GPO."""

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--tmpdir", help="Temporary directory for copying policy files", type=str),
        Option("--generalize", help="Generalize XML entities to restore",
               default=False, action='store_true'),
        Option("--entities", help="File to export defining XML entities for the restore",
               dest='ent_file', type=str)
    ]

    def run(self, gpo, H=None, tmpdir=None, generalize=False, sambaopts=None,
            credopts=None, versionopts=None, ent_file=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        self.samdb_connect()
        try:
            msg = get_gpo_info(self.samdb, gpo)[0]
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)

        # verify UNC path
        unc = str(msg['gPCFileSysPath'][0])
        try:
            [dom_name, service, sharepath] = parse_unc(unc)
        except ValueError:
            raise CommandError("Invalid GPO path (%s)" % unc)

        # SMB connect to DC
        conn = smb_connection(dc_hostname, service, lp=self.lp,
                              creds=self.creds)

        # Copy GPT
        tmpdir, gpodir = self.construct_tmpdir(tmpdir, gpo)

        try:
            backup_directory_remote_to_local(conn, sharepath, gpodir)
        except Exception as e:
            # FIXME: Catch more specific exception
            raise CommandError("Error copying GPO from DC", e)

        self.outf.write('GPO copied to %s\n' % gpodir)

        if generalize:
            self.outf.write('\nAttempting to generalize XML entities:\n')
            entities = cmd_backup.generalize_xml_entities(self.outf, gpodir,
                                                          gpodir)
            import operator
            ents = "".join('<!ENTITY {} "{}\n">'.format(ent[1].strip('&;'), ent[0]) \
                             for ent in sorted(entities.items(), key=operator.itemgetter(1)))

            if ent_file:
                with open(ent_file, 'w') as f:
                    f.write(ents)
                self.outf.write('Entities successfully written to %s\n' %
                                ent_file)
            else:
                self.outf.write('\nEntities:\n')
                self.outf.write(ents)

        # Backup the enabled GPO extension names
        for ext in ('gPCMachineExtensionNames', 'gPCUserExtensionNames'):
            if ext in msg:
                with open(os.path.join(gpodir, ext + '.SAMBAEXT'), 'wb') as f:
                    f.write(msg[ext][0])

    @staticmethod
    def generalize_xml_entities(outf, sourcedir, targetdir):
        entities = {}

        if not os.path.exists(targetdir):
            os.mkdir(targetdir)

        l_dirs = [ sourcedir ]
        r_dirs = [ targetdir ]
        while l_dirs:
            l_dir = l_dirs.pop()
            r_dir = r_dirs.pop()

            dirlist = os.listdir(l_dir)
            dirlist.sort()
            for e in dirlist:
                l_name = os.path.join(l_dir, e)
                r_name = os.path.join(r_dir, e)

                if os.path.isdir(l_name):
                    l_dirs.append(l_name)
                    r_dirs.append(r_name)
                    if not os.path.exists(r_name):
                        os.mkdir(r_name)
                else:
                    if l_name.endswith('.xml'):
                        # Restore the xml file if possible

                        # Get the filename to find the parser
                        to_parse = os.path.basename(l_name)[:-4]

                        parser = find_parser(to_parse)
                        try:
                            with open(l_name, 'r') as ltemp:
                                data = ltemp.read()

                            concrete_xml = ET.fromstring(data)
                            found_entities = parser.generalize_xml(concrete_xml, r_name, entities)
                        except GPGeneralizeException:
                            outf.write('SKIPPING: Generalizing failed for %s\n' % to_parse)

                    else:
                        # No need to generalize non-xml files.
                        #
                        # TODO This could be improved with xml files stored in
                        # the renamed backup file (with custom extension) by
                        # inlining them into the exported backups.
                        if not os.path.samefile(l_name, r_name):
                            shutil.copy2(l_name, r_name)

        return entities


class cmd_create(GPOCommand):
    """Create an empty GPO."""

    synopsis = "%prog <displayname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['displayname']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--tmpdir", help="Temporary directory for copying policy files", type=str)
    ]

    def run(self, displayname, H=None, tmpdir=None, sambaopts=None, credopts=None,
            versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        net = Net(creds=self.creds, lp=self.lp)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
            flags = (nbt.NBT_SERVER_LDAP |
                     nbt.NBT_SERVER_DS |
                     nbt.NBT_SERVER_WRITABLE)
            cldap_ret = net.finddc(address=dc_hostname, flags=flags)
        else:
            flags = (nbt.NBT_SERVER_LDAP |
                     nbt.NBT_SERVER_DS |
                     nbt.NBT_SERVER_WRITABLE)
            cldap_ret = net.finddc(domain=self.lp.get('realm'), flags=flags)
            dc_hostname = cldap_ret.pdc_dns_name
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        self.samdb_connect()

        msg = get_gpo_info(self.samdb, displayname=displayname)
        if msg.count > 0:
            raise CommandError("A GPO already existing with name '%s'" % displayname)

        # Create new GUID
        guid  = str(uuid.uuid4())
        gpo = "{%s}" % guid.upper()

        self.gpo_name = gpo

        realm = cldap_ret.dns_domain
        unc_path = "\\\\%s\\sysvol\\%s\\Policies\\%s" % (realm, realm, gpo)

        # Create GPT
        self.tmpdir, gpodir = self.construct_tmpdir(tmpdir, gpo)
        self.gpodir = gpodir

        try:
            os.mkdir(os.path.join(gpodir, "Machine"))
            os.mkdir(os.path.join(gpodir, "User"))
            gpt_contents = "[General]\r\nVersion=0\r\n"
            with open(os.path.join(gpodir, "GPT.INI"), "w") as f:
                f.write(gpt_contents)
        except Exception as e:
            raise CommandError("Error Creating GPO files", e)

        # Connect to DC over SMB
        [dom_name, service, sharepath] = parse_unc(unc_path)
        self.sharepath = sharepath
        conn = smb_connection(dc_hostname, service, lp=self.lp,
                              creds=self.creds)

        self.conn = conn

        self.samdb.transaction_start()
        try:
            # Add cn=<guid>
            gpo_dn = get_gpo_dn(self.samdb, gpo)

            m = ldb.Message()
            m.dn = gpo_dn
            m['a01'] = ldb.MessageElement("groupPolicyContainer", ldb.FLAG_MOD_ADD, "objectClass")
            self.samdb.add(m)

            # Add cn=User,cn=<guid>
            m = ldb.Message()
            m.dn = ldb.Dn(self.samdb, "CN=User,%s" % str(gpo_dn))
            m['a01'] = ldb.MessageElement("container", ldb.FLAG_MOD_ADD, "objectClass")
            self.samdb.add(m)

            # Add cn=Machine,cn=<guid>
            m = ldb.Message()
            m.dn = ldb.Dn(self.samdb, "CN=Machine,%s" % str(gpo_dn))
            m['a01'] = ldb.MessageElement("container", ldb.FLAG_MOD_ADD, "objectClass")
            self.samdb.add(m)

            # Get new security descriptor
            ds_sd_flags = (security.SECINFO_OWNER |
                           security.SECINFO_GROUP |
                           security.SECINFO_DACL)
            msg = get_gpo_info(self.samdb, gpo=gpo, sd_flags=ds_sd_flags)[0]
            ds_sd_ndr = msg['nTSecurityDescriptor'][0]
            ds_sd = ndr_unpack(security.descriptor, ds_sd_ndr).as_sddl()

            # Create a file system security descriptor
            domain_sid = security.dom_sid(self.samdb.get_domain_sid())
            fs_sd = dsacl2fsacl(ds_sd, domain_sid, as_sddl=False)

            # Copy GPO directory
            create_directory_hier(conn, sharepath)

            # Set ACL
            sio = (security.SECINFO_OWNER |
                   security.SECINFO_GROUP |
                   security.SECINFO_DACL |
                   security.SECINFO_PROTECTED_DACL)
            conn.set_acl(sharepath, fs_sd, sio)

            # Copy GPO files over SMB
            copy_directory_local_to_remote(conn, gpodir, sharepath)

            m = ldb.Message()
            m.dn = gpo_dn
            m['a02'] = ldb.MessageElement(displayname, ldb.FLAG_MOD_REPLACE, "displayName")
            m['a03'] = ldb.MessageElement(unc_path, ldb.FLAG_MOD_REPLACE, "gPCFileSysPath")
            m['a05'] = ldb.MessageElement("0", ldb.FLAG_MOD_REPLACE, "versionNumber")
            m['a07'] = ldb.MessageElement("2", ldb.FLAG_MOD_REPLACE, "gpcFunctionalityVersion")
            m['a04'] = ldb.MessageElement("0", ldb.FLAG_MOD_REPLACE, "flags")
            controls = ["permissive_modify:0"]
            self.samdb.modify(m, controls=controls)
        except Exception:
            self.samdb.transaction_cancel()
            raise
        else:
            self.samdb.transaction_commit()

        if tmpdir is None:
            # Without --tmpdir, we created one in /tmp/. It must go.
            shutil.rmtree(self.tmpdir)

        self.outf.write("GPO '%s' created as %s\n" % (displayname, gpo))


class cmd_restore(cmd_create):
    """Restore a GPO to a new container."""

    synopsis = "%prog <displayname> <backup location> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['displayname', 'backup']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--tmpdir", help="Temporary directory for copying policy files", type=str),
        Option("--entities", help="File defining XML entities to insert into DOCTYPE header", type=str),
        Option("--restore-metadata", help="Keep the old GPT.INI file and associated version number",
               default=False, action="store_true")
    ]

    def restore_from_backup_to_local_dir(self, sourcedir, targetdir, dtd_header=''):
        SUFFIX = '.SAMBABACKUP'

        if not os.path.exists(targetdir):
            os.mkdir(targetdir)

        l_dirs = [ sourcedir ]
        r_dirs = [ targetdir ]
        while l_dirs:
            l_dir = l_dirs.pop()
            r_dir = r_dirs.pop()

            dirlist = os.listdir(l_dir)
            dirlist.sort()
            for e in dirlist:
                l_name = os.path.join(l_dir, e)
                r_name = os.path.join(r_dir, e)

                if os.path.isdir(l_name):
                    l_dirs.append(l_name)
                    r_dirs.append(r_name)
                    if not os.path.exists(r_name):
                        os.mkdir(r_name)
                else:
                    if l_name.endswith('.xml'):
                        # Restore the xml file if possible

                        # Get the filename to find the parser
                        to_parse = os.path.basename(l_name)[:-4]

                        parser = find_parser(to_parse)
                        try:
                            with open(l_name, 'r') as ltemp:
                                data = ltemp.read()
                                xml_head = '<?xml version="1.0" encoding="utf-8"?>'

                                if data.startswith(xml_head):
                                    # It appears that sometimes the DTD rejects
                                    # the xml header being after it.
                                    data = data[len(xml_head):]

                                    # Load the XML file with the DTD (entity) header
                                    parser.load_xml(ET.fromstring(xml_head + dtd_header + data))
                                else:
                                    parser.load_xml(ET.fromstring(dtd_header + data))

                                # Write out the substituted files in the output
                                # location, ready to copy over.
                                parser.write_binary(r_name[:-4])

                        except GPNoParserException:
                            # In the failure case, we fallback
                            original_file = l_name[:-4] + SUFFIX
                            shutil.copy2(original_file, r_name[:-4])

                            self.outf.write('WARNING: No such parser for %s\n' % to_parse)
                            self.outf.write('WARNING: Falling back to simple copy-restore.\n')
                        except:
                            import traceback
                            traceback.print_exc()

                            # In the failure case, we fallback
                            original_file = l_name[:-4] + SUFFIX
                            shutil.copy2(original_file, r_name[:-4])

                            self.outf.write('WARNING: Error during parsing for %s\n' % l_name)
                            self.outf.write('WARNING: Falling back to simple copy-restore.\n')

    def run(self, displayname, backup, H=None, tmpdir=None, entities=None, sambaopts=None, credopts=None,
            versionopts=None, restore_metadata=None):

        dtd_header = ''

        if not os.path.exists(backup):
            raise CommandError("Backup directory does not exist %s" % backup)

        if entities is not None:
            # DOCTYPE name is meant to match root element, but ElementTree does
            # not seem to care, so this seems to be enough.

            dtd_header = '<!DOCTYPE foobar [\n'

            if not os.path.exists(entities):
                raise CommandError("Entities file does not exist %s" %
                                   entities)
            with open(entities, 'r') as entities_file:
                entities_content = entities_file.read()

                # Do a basic regex test of the entities file format
                if re.match(r'(\s*<!ENTITY\s*[a-zA-Z0-9_]+\s*.*?>)+\s*\Z',
                            entities_content, flags=re.MULTILINE) is None:
                    raise CommandError("Entities file does not appear to "
                                       "conform to format\n"
                                       'e.g. <!ENTITY entity "value">')
                dtd_header += entities_content.strip()

            dtd_header += '\n]>\n'

        super().run(displayname, H, tmpdir, sambaopts, credopts, versionopts)

        try:
            if tmpdir is None:
                # Create GPT
                self.tmpdir, gpodir = self.construct_tmpdir(tmpdir, self.gpo_name)
                self.gpodir = gpodir

            # Iterate over backup files and restore with DTD
            self.restore_from_backup_to_local_dir(backup, self.gpodir,
                                                  dtd_header)

            keep_new_files = not restore_metadata

            # Copy GPO files over SMB
            copy_directory_local_to_remote(self.conn, self.gpodir,
                                           self.sharepath,
                                           ignore_existing_dir=True,
                                           keep_existing_files=keep_new_files)

            gpo_dn = get_gpo_dn(self.samdb, self.gpo_name)

            # Restore the enabled extensions
            for ext in ('gPCMachineExtensionNames', 'gPCUserExtensionNames'):
                ext_file = os.path.join(backup, ext + '.SAMBAEXT')
                if os.path.exists(ext_file):
                    with open(ext_file, 'rb') as f:
                        data = f.read()

                    m = ldb.Message()
                    m.dn = gpo_dn
                    m[ext] = ldb.MessageElement(data, ldb.FLAG_MOD_REPLACE,
                                                ext)

                    self.samdb.modify(m)

            if tmpdir is None:
                # Without --tmpdir, we created one in /tmp/. It must go.
                shutil.rmtree(self.tmpdir)

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.outf.write(str(e) + '\n')

            self.outf.write("Failed to restore GPO -- deleting...\n")
            cmd = cmd_del()
            cmd.run(self.gpo_name, H, sambaopts, credopts, versionopts)

            raise CommandError("Failed to restore: %s" % e)


class cmd_del(GPOCommand):
    """Delete a GPO."""

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = ['gpo']

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
    ]

    def run(self, gpo, H=None, sambaopts=None, credopts=None,
            versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        self.samdb_connect()

        # Check if valid GPO
        try:
            msg = get_gpo_info(self.samdb, gpo=gpo)[0]
            unc_path = str(msg['gPCFileSysPath'][0])
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)

        # Connect to DC over SMB
        [dom_name, service, sharepath] = parse_unc(unc_path)
        conn = smb_connection(dc_hostname, service, lp=self.lp,
                              creds=self.creds)

        self.samdb.transaction_start()
        try:
            # Check for existing links
            msg = get_gpo_containers(self.samdb, gpo)

            if len(msg):
                self.outf.write("GPO %s is linked to containers\n" % gpo)
                for m in msg:
                    del_gpo_link(self.samdb, m['dn'], gpo)
                    self.outf.write("    Removed link from %s.\n" % m['dn'])

            # Remove LDAP entries
            gpo_dn = get_gpo_dn(self.samdb, gpo)
            self.samdb.delete(ldb.Dn(self.samdb, "CN=User,%s" % str(gpo_dn)), ["tree_delete:1"])
            self.samdb.delete(ldb.Dn(self.samdb, "CN=Machine,%s" % str(gpo_dn)), ["tree_delete:1"])
            self.samdb.delete(gpo_dn)

            # Remove GPO files
            conn.deltree(sharepath)

        except Exception:
            self.samdb.transaction_cancel()
            raise
        else:
            self.samdb.transaction_commit()

        self.outf.write("GPO %s deleted.\n" % gpo)


class cmd_aclcheck(GPOCommand):
    """Check all GPOs have matching LDAP and DS ACLs."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H")
    ]

    def run(self, H=None, sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        self.samdb_connect()

        msg = get_gpo_info(self.samdb, None)

        for m in msg:
            # verify UNC path
            unc = str(m['gPCFileSysPath'][0])
            try:
                [dom_name, service, sharepath] = parse_unc(unc)
            except ValueError:
                raise CommandError("Invalid GPO path (%s)" % unc)

            # SMB connect to DC
            conn = smb_connection(dc_hostname, service, lp=self.lp,
                                  creds=self.creds)

            fs_sd = conn.get_acl(sharepath, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL, security.SEC_FLAG_MAXIMUM_ALLOWED)

            if 'nTSecurityDescriptor' not in m:
                raise CommandError("Could not read nTSecurityDescriptor. "
                                   "This requires an Administrator account")

            ds_sd_ndr = m['nTSecurityDescriptor'][0]
            ds_sd = ndr_unpack(security.descriptor, ds_sd_ndr).as_sddl()

            # Create a file system security descriptor
            domain_sid = security.dom_sid(self.samdb.get_domain_sid())
            expected_fs_sddl = dsacl2fsacl(ds_sd, domain_sid)

            if (fs_sd.as_sddl(domain_sid) != expected_fs_sddl):
                raise CommandError("Invalid GPO ACL %s on path (%s), should be %s" % (fs_sd.as_sddl(domain_sid), sharepath, expected_fs_sddl))

class cmd_admxload(Command):
    """Loads samba admx files to sysvol"""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
        Option("--admx-dir", help="Directory where admx templates are stored",
                type=str, default=os.path.join(param.data_dir(), 'samba/admx'))
    ]

    def run(self, H=None, sambaopts=None, credopts=None, versionopts=None,
            admx_dir=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        smb_dir = '\\'.join([self.lp.get('realm').lower(),
                             'Policies', 'PolicyDefinitions'])
        try:
            conn.mkdir(smb_dir)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            elif e.args[0] != NT_STATUS_OBJECT_NAME_COLLISION:
                raise

        for dirname, dirs, files in os.walk(admx_dir):
            for fname in files:
                path_in_admx = dirname.replace(admx_dir, '')
                full_path = os.path.join(dirname, fname)
                sub_dir = '\\'.join([smb_dir, path_in_admx]).replace('/', '\\')
                smb_path = '\\'.join([sub_dir, fname])
                try:
                    create_directory_hier(conn, sub_dir)
                except NTSTATUSError as e:
                    if e.args[0] == NT_STATUS_ACCESS_DENIED:
                        raise CommandError("The authenticated user does "
                                           "not have sufficient privileges")
                    elif e.args[0] != NT_STATUS_OBJECT_NAME_COLLISION:
                        raise
                with open(full_path, 'rb') as f:
                    try:
                        conn.savefile(smb_path, f.read())
                    except NTSTATUSError as e:
                        if e.args[0] == NT_STATUS_ACCESS_DENIED:
                            raise CommandError("The authenticated user does "
                                               "not have sufficient privileges")
        self.outf.write('Installing ADMX templates to the Central Store '
                        'prevents Windows from displaying its own templates '
                        'in the Group Policy Management Console. You will '
                        'need to install these templates '
                        'from https://www.microsoft.com/en-us/download/102157 '
                        'to continue using Windows Administrative Templates.\n')

class cmd_add_sudoers(GPOCommand):
    """Adds a Samba Sudoers Group Policy to the sysvol

This command adds a sudo rule to the sysvol for applying to winbind clients.

The command argument indicates the final field in the sudo rule.
The user argument indicates the user specified in the parentheses.
The users and groups arguments are comma separated lists, which are combined to
form the first field in the sudo rule.
The --passwd argument specifies whether the sudo entry will require a password
be specified. The default is False, meaning the NOPASSWD field will be
specified in the sudo entry.

Example:
samba-tool gpo manage sudoers add {31B2F340-016D-11D2-945F-00C04FB984F9} ALL ALL fakeu fakeg

The example command will generate the following sudoers entry:
fakeu,fakeg% ALL=(ALL) NOPASSWD: ALL
    """

    synopsis = "%prog <gpo> <command> <user> <users> [groups] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
        Option("--passwd", action='store_true', default=False,
               help="Specify to indicate that sudo entry must provide a password")
    ]

    takes_args = ["gpo", "command", "user", "users", "groups?"]

    def run(self, gpo, command, user, users, groups=None, passwd=None,
            H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Sudo',
                             'SudoersConfiguration'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policysetting = xml_data.getroot().find('policysetting')
            data = policysetting.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so create the xml structure
                xml_data = ET.ElementTree(ET.Element('vgppolicy'))
                policysetting = ET.SubElement(xml_data.getroot(),
                                              'policysetting')
                pv = ET.SubElement(policysetting, 'version')
                pv.text = '1'
                name = ET.SubElement(policysetting, 'name')
                name.text = 'Sudo Policy'
                description = ET.SubElement(policysetting, 'description')
                description.text = 'Sudoers File Configuration Policy'
                apply_mode = ET.SubElement(policysetting, 'apply_mode')
                apply_mode.text = 'merge'
                data = ET.SubElement(policysetting, 'data')
                load_plugin = ET.SubElement(data, 'load_plugin')
                load_plugin.text = 'true'
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        sudoers_entry = ET.SubElement(data, 'sudoers_entry')
        if passwd:
            ET.SubElement(sudoers_entry, 'password')
        command_elm = ET.SubElement(sudoers_entry, 'command')
        command_elm.text = command
        user_elm = ET.SubElement(sudoers_entry, 'user')
        user_elm.text = user
        listelement = ET.SubElement(sudoers_entry, 'listelement')
        for u in users.split(','):
            principal = ET.SubElement(listelement, 'principal')
            principal.text = u
            principal.attrib['type'] = 'user'
        if groups is not None:
            for g in groups.split():
                principal = ET.SubElement(listelement, 'principal')
                principal.text = g
                principal.attrib['type'] = 'group'

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_list_sudoers(Command):
    """List Samba Sudoers Group Policy from the sysvol

This command lists sudo rules from the sysvol that will be applied to winbind clients.

Example:
samba-tool gpo manage sudoers list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                                'MACHINE\\VGP\\VTLA\\Sudo',
                                'SudoersConfiguration\\manifest.xml'])
        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so there is nothing to list
                xml_data = None
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        if xml_data is not None:
            policy = xml_data.find('policysetting')
            data = policy.find('data')
            for entry in data.findall('sudoers_entry'):
                command = entry.find('command').text
                user = entry.find('user').text
                listelements = entry.findall('listelement')
                principals = []
                for listelement in listelements:
                    principals.extend(listelement.findall('principal'))
                if len(principals) > 0:
                    uname = ','.join([u.text if u.attrib['type'] == 'user' \
                        else '%s%%' % u.text for u in principals])
                else:
                    uname = 'ALL'
                nopassword = entry.find('password') is None
                np_entry = ' NOPASSWD:' if nopassword else ''
                p = '%s ALL=(%s)%s %s' % (uname, user, np_entry, command)
                self.outf.write('%s\n' % p)

        pol_file = '\\'.join([realm.lower(), 'Policies', gpo,
                              'MACHINE\\Registry.pol'])
        try:
            pol_data = ndr_unpack(preg.file, conn.loadfile(pol_file))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        # Also list the policies set from the GPME
        keyname = b'Software\\Policies\\Samba\\Unix Settings\\Sudo Rights'
        for entry in pol_data.entries:
            if get_bytes(entry.keyname) == keyname and \
                    get_string(entry.data).strip():
                self.outf.write('%s\n' % entry.data)

class cmd_remove_sudoers(GPOCommand):
    """Removes a Samba Sudoers Group Policy from the sysvol

This command removes a sudo rule from the sysvol from applying to winbind clients.

Example:
samba-tool gpo manage sudoers remove {31B2F340-016D-11D2-945F-00C04FB984F9} 'fakeu ALL=(ALL) NOPASSWD: ALL'
    """

    synopsis = "%prog <gpo> <entry> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "entry"]

    def run(self, gpo, entry, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Sudo',
                             'SudoersConfiguration'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policysetting = xml_data.getroot().find('policysetting')
            data = policysetting.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                data = None
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        pol_file = '\\'.join([realm.lower(), 'Policies', gpo,
                              'MACHINE\\Registry.pol'])
        try:
            pol_data = ndr_unpack(preg.file, conn.loadfile(pol_file))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                pol_data = None
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        entries = {}
        for e in data.findall('sudoers_entry') if data else []:
            command = e.find('command').text
            user = e.find('user').text
            listelements = e.findall('listelement')
            principals = []
            for listelement in listelements:
                principals.extend(listelement.findall('principal'))
            if len(principals) > 0:
                uname = ','.join([u.text if u.attrib['type'] == 'user' \
                    else '%s%%' % u.text for u in principals])
            else:
                uname = 'ALL'
            nopassword = e.find('password') is None
            np_entry = ' NOPASSWD:' if nopassword else ''
            p = '%s ALL=(%s)%s %s' % (uname, user, np_entry, command)
            entries[p] = e

        if entry in entries.keys():
            data.remove(entries[entry])

            out = BytesIO()
            xml_data.write(out, encoding='UTF-8', xml_declaration=True)
            out.seek(0)
            try:
                create_directory_hier(conn, vgp_dir)
                conn.savefile(vgp_xml, out.read())
                reg.increment_gpt_ini(machine_changed=True)
            except NTSTATUSError as e:
                if e.args[0] == NT_STATUS_ACCESS_DENIED:
                    raise CommandError("The authenticated user does "
                                       "not have sufficient privileges")
                raise
        elif entry in ([e.data for e in pol_data.entries] if pol_data else []):
            entries = [e for e in pol_data.entries if e.data != entry]
            pol_data.num_entries = len(entries)
            pol_data.entries = entries

            try:
                conn.savefile(pol_file, ndr_pack(pol_data))
                reg.increment_gpt_ini(machine_changed=True)
            except NTSTATUSError as e:
                if e.args[0] == NT_STATUS_ACCESS_DENIED:
                    raise CommandError("The authenticated user does "
                                       "not have sufficient privileges")
                raise
        else:
            raise CommandError("Cannot remove '%s' because it does not exist" %
                               entry)

class cmd_sudoers(SuperCommand):
    """Manage Sudoers Group Policy Objects"""
    subcommands = {}
    subcommands["add"] = cmd_add_sudoers()
    subcommands["list"] = cmd_list_sudoers()
    subcommands["remove"] = cmd_remove_sudoers()

class cmd_set_security(GPOCommand):
    """Set Samba Security Group Policy to the sysvol

This command sets a security setting to the sysvol for applying to winbind
clients. Not providing a value will unset the policy.
These settings only apply to the ADDC.

Example:
samba-tool gpo manage security set {31B2F340-016D-11D2-945F-00C04FB984F9} MaxTicketAge 10

Possible policies:
MaxTicketAge            Maximum lifetime for user ticket
                        Defined in hours

MaxServiceAge           Maximum lifetime for service ticket
                        Defined in minutes

MaxRenewAge             Maximum lifetime for user ticket renewal
                        Defined in minutes

MinimumPasswordAge      Minimum password age
                        Defined in days

MaximumPasswordAge      Maximum password age
                        Defined in days

MinimumPasswordLength   Minimum password length
                        Defined in characters

PasswordComplexity      Password must meet complexity requirements
                        1 is Enabled, 0 is Disabled
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "policy", "value?"]

    def run(self, gpo, policy, value=None, H=None, sambaopts=None,
            credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        inf_dir = '\\'.join([realm.lower(), 'Policies', gpo,
            'MACHINE\\Microsoft\\Windows NT\\SecEdit'])
        inf_file = '\\'.join([inf_dir, 'GptTmpl.inf'])
        try:
            inf_data = ConfigParser(interpolation=None)
            inf_data.optionxform=str
            raw = conn.loadfile(inf_file)
            try:
                inf_data.read_file(StringIO(raw.decode()))
            except UnicodeDecodeError:
                inf_data.read_file(StringIO(raw.decode('utf-16')))
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            if e.args[0] not in [NT_STATUS_OBJECT_NAME_INVALID,
                                 NT_STATUS_OBJECT_NAME_NOT_FOUND,
                                 NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                raise

        section_map = { 'MaxTicketAge' : 'Kerberos Policy',
                        'MaxServiceAge' : 'Kerberos Policy',
                        'MaxRenewAge' : 'Kerberos Policy',
                        'MinimumPasswordAge' : 'System Access',
                        'MaximumPasswordAge' : 'System Access',
                        'MinimumPasswordLength' : 'System Access',
                        'PasswordComplexity' : 'System Access'
                    }

        section = section_map[policy]
        if not inf_data.has_section(section):
            inf_data.add_section(section)
        if value is not None:
            inf_data.set(section, policy, value)
        else:
            inf_data.remove_option(section, policy)
            if len(inf_data.options(section)) == 0:
                inf_data.remove_section(section)

        out = StringIO()
        inf_data.write(out)
        try:
            create_directory_hier(conn, inf_dir)
            conn.savefile(inf_file, get_bytes(out.getvalue()))
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

class cmd_list_security(Command):
    """List Samba Security Group Policy from the sysvol

This command lists security settings from the sysvol that will be applied to winbind clients.
These settings only apply to the ADDC.

Example:
samba-tool gpo manage security list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        inf_file = '\\'.join([realm.lower(), 'Policies', gpo,
            'MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf'])
        try:
            inf_data = ConfigParser(interpolation=None)
            inf_data.optionxform=str
            raw = conn.loadfile(inf_file)
            try:
                inf_data.read_file(StringIO(raw.decode()))
            except UnicodeDecodeError:
                inf_data.read_file(StringIO(raw.decode('utf-16')))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        for section in inf_data.sections():
            if section not in ['Kerberos Policy', 'System Access']:
                continue
            for key, value in inf_data.items(section):
                self.outf.write('%s = %s\n' % (key, value))

class cmd_security(SuperCommand):
    """Manage Security Group Policy Objects"""
    subcommands = {}
    subcommands["set"] = cmd_set_security()
    subcommands["list"] = cmd_list_security()

class cmd_list_smb_conf(Command):
    """List Samba smb.conf Group Policy from the sysvol

This command lists smb.conf settings from the sysvol that will be applied to winbind clients.

Example:
samba-tool gpo manage smb_conf list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        pol_file = '\\'.join([realm.lower(), 'Policies', gpo,
                                'MACHINE\\Registry.pol'])
        try:
            pol_data = ndr_unpack(preg.file, conn.loadfile(pol_file))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        keyname = b'Software\\Policies\\Samba\\smb_conf'
        lp = param.LoadParm()
        for entry in pol_data.entries:
            if get_bytes(entry.keyname) == keyname:
                lp.set(entry.valuename, str(entry.data))
                val = lp.get(entry.valuename)
                self.outf.write('%s = %s\n' % (entry.valuename, val))

class cmd_set_smb_conf(GPOCommand):
    """Sets a Samba smb.conf Group Policy to the sysvol

This command sets an smb.conf setting to the sysvol for applying to winbind
clients. Not providing a value will unset the policy.

Example:
samba-tool gpo manage smb_conf set {31B2F340-016D-11D2-945F-00C04FB984F9} 'apply gpo policies' yes
    """

    synopsis = "%prog <gpo> <entry> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "setting", "value?"]

    def run(self, gpo, setting, value=None, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        pol_dir = '\\'.join([realm.lower(), 'Policies', gpo, 'MACHINE'])
        pol_file = '\\'.join([pol_dir, 'Registry.pol'])
        try:
            pol_data = ndr_unpack(preg.file, conn.loadfile(pol_file))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                pol_data = preg.file() # The file doesn't exist
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        if value is None:
            if setting not in [e.valuename for e in pol_data.entries]:
                raise CommandError("Cannot remove '%s' because it does "
                                    "not exist" % setting)
            entries = [e for e in pol_data.entries \
                if e.valuename != setting]
            pol_data.entries = entries
            pol_data.num_entries = len(entries)
        else:
            if get_string(value).lower() in ['yes', 'true', '1']:
                etype = 4
                val = 1
            elif get_string(value).lower() in ['no', 'false', '0']:
                etype = 4
                val = 0
            elif get_string(value).isnumeric():
                etype = 4
                val = int(get_string(value))
            else:
                etype = 1
                val = get_bytes(value)
            e = preg.entry()
            e.keyname = b'Software\\Policies\\Samba\\smb_conf'
            e.valuename = get_bytes(setting)
            e.type = etype
            e.data = val
            entries = list(pol_data.entries)
            entries.append(e)
            pol_data.entries = entries
            pol_data.num_entries = len(entries)

        try:
            create_directory_hier(conn, pol_dir)
            conn.savefile(pol_file, ndr_pack(pol_data))
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_smb_conf(SuperCommand):
    """Manage smb.conf Group Policy Objects"""
    subcommands = {}
    subcommands["list"] = cmd_list_smb_conf()
    subcommands["set"] = cmd_set_smb_conf()

class cmd_list_symlink(Command):
    """List VGP Symbolic Link Group Policy from the sysvol

This command lists symlink settings from the sysvol that will be applied to winbind clients.

Example:
samba-tool gpo manage symlink list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                                'MACHINE\\VGP\\VTLA\\Unix',
                                'Symlink\\manifest.xml'])
        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        policy = xml_data.find('policysetting')
        data = policy.find('data')
        for file_properties in data.findall('file_properties'):
            source = file_properties.find('source')
            target = file_properties.find('target')
            self.outf.write('ln -s %s %s\n' % (source.text, target.text))

class cmd_add_symlink(GPOCommand):
    """Adds a VGP Symbolic Link Group Policy to the sysvol

This command adds a symlink setting to the sysvol that will be applied to winbind clients.

Example:
samba-tool gpo manage symlink add {31B2F340-016D-11D2-945F-00C04FB984F9} /tmp/source /tmp/target
    """

    synopsis = "%prog <gpo> <source> <target> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "source", "target"]

    def run(self, gpo, source, target, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Unix\\Symlink'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so create the xml structure
                xml_data = ET.ElementTree(ET.Element('vgppolicy'))
                policysetting = ET.SubElement(xml_data.getroot(),
                                              'policysetting')
                pv = ET.SubElement(policysetting, 'version')
                pv.text = '1'
                name = ET.SubElement(policysetting, 'name')
                name.text = 'Symlink Policy'
                description = ET.SubElement(policysetting, 'description')
                description.text = 'Specifies symbolic link data'
                data = ET.SubElement(policysetting, 'data')
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        file_properties = ET.SubElement(data, 'file_properties')
        source_elm = ET.SubElement(file_properties, 'source')
        source_elm.text = source
        target_elm = ET.SubElement(file_properties, 'target')
        target_elm.text = target

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_remove_symlink(GPOCommand):
    """Removes a VGP Symbolic Link Group Policy from the sysvol

This command removes a symlink setting from the sysvol from applying to winbind
clients.

Example:
samba-tool gpo manage symlink remove {31B2F340-016D-11D2-945F-00C04FB984F9} /tmp/source /tmp/target
    """

    synopsis = "%prog <gpo> <source> <target> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "source", "target"]

    def run(self, gpo, source, target, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Unix\\Symlink'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                raise CommandError("Cannot remove link from '%s' to '%s' "
                    "because it does not exist" % source, target)
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        for file_properties in data.findall('file_properties'):
            source_elm = file_properties.find('source')
            target_elm = file_properties.find('target')
            if source_elm.text == source and target_elm.text == target:
                data.remove(file_properties)
                break
        else:
            raise CommandError("Cannot remove link from '%s' to '%s' "
                               "because it does not exist" % source, target)


        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_symlink(SuperCommand):
    """Manage symlink Group Policy Objects"""
    subcommands = {}
    subcommands["list"] = cmd_list_symlink()
    subcommands["add"] = cmd_add_symlink()
    subcommands["remove"] = cmd_remove_symlink()

class cmd_list_files(Command):
    """List VGP Files Group Policy from the sysvol

This command lists files which will be copied from the sysvol and applied to winbind clients.

Example:
samba-tool gpo manage files list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                                'MACHINE\\VGP\\VTLA\\Unix',
                                'Files\\manifest.xml'])
        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        policy = xml_data.find('policysetting')
        data = policy.find('data')
        for entry in data.findall('file_properties'):
            source = entry.find('source').text
            target = entry.find('target').text
            user = entry.find('user').text
            group = entry.find('group').text
            mode = calc_mode(entry)
            p = '%s\t%s\t%s\t%s -> %s' % \
                    (stat_from_mode(mode), user, group, target, source)
            self.outf.write('%s\n' % p)

class cmd_add_files(GPOCommand):
    """Add VGP Files Group Policy to the sysvol

This command adds files which will be copied from the sysvol and applied to winbind clients.

Example:
samba-tool gpo manage files add {31B2F340-016D-11D2-945F-00C04FB984F9} ./source.txt /usr/share/doc/target.txt root root 600
    """

    synopsis = "%prog <gpo> <source> <target> <user> <group> <mode> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "source", "target", "user", "group", "mode"]

    def run(self, gpo, source, target, user, group, mode, H=None,
            sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        if not os.path.exists(source):
            raise CommandError("Source '%s' does not exist" % source)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Unix\\Files'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so create the xml structure
                xml_data = ET.ElementTree(ET.Element('vgppolicy'))
                policysetting = ET.SubElement(xml_data.getroot(),
                                              'policysetting')
                pv = ET.SubElement(policysetting, 'version')
                pv.text = '1'
                name = ET.SubElement(policysetting, 'name')
                name.text = 'Files'
                description = ET.SubElement(policysetting, 'description')
                description.text = 'Represents file data to set/copy on clients'
                data = ET.SubElement(policysetting, 'data')
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        file_properties = ET.SubElement(data, 'file_properties')
        source_elm = ET.SubElement(file_properties, 'source')
        source_elm.text = os.path.basename(source)
        target_elm = ET.SubElement(file_properties, 'target')
        target_elm.text = target
        user_elm = ET.SubElement(file_properties, 'user')
        user_elm.text = user
        group_elm = ET.SubElement(file_properties, 'group')
        group_elm.text = group
        for ptype, shift in [('user', 6), ('group', 3), ('other', 0)]:
            permissions = ET.SubElement(file_properties, 'permissions')
            permissions.set('type', ptype)
            if int(mode, 8) & (0o4 << shift):
                ET.SubElement(permissions, 'read')
            if int(mode, 8) & (0o2 << shift):
                ET.SubElement(permissions, 'write')
            if int(mode, 8) & (0o1 << shift):
                ET.SubElement(permissions, 'execute')

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        with open(source, 'rb') as f:
            source_data = f.read()
        sysvol_source = '\\'.join([vgp_dir, os.path.basename(source)])
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            conn.savefile(sysvol_source, source_data)
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_remove_files(GPOCommand):
    """Remove VGP Files Group Policy from the sysvol

This command removes files which would be copied from the sysvol and applied to winbind clients.

Example:
samba-tool gpo manage files remove {31B2F340-016D-11D2-945F-00C04FB984F9} /usr/share/doc/target.txt
    """

    synopsis = "%prog <gpo> <target> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "target"]

    def run(self, gpo, target, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Unix\\Files'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                raise CommandError("Cannot remove file '%s' "
                    "because it does not exist" % target)
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        for file_properties in data.findall('file_properties'):
            source_elm = file_properties.find('source')
            target_elm = file_properties.find('target')
            if target_elm.text == target:
                source = '\\'.join([vgp_dir, source_elm.text])
                conn.unlink(source)
                data.remove(file_properties)
                break
        else:
            raise CommandError("Cannot remove file '%s' "
                               "because it does not exist" % target)


        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_files(SuperCommand):
    """Manage Files Group Policy Objects"""
    subcommands = {}
    subcommands["list"] = cmd_list_files()
    subcommands["add"] = cmd_add_files()
    subcommands["remove"] = cmd_remove_files()

class cmd_list_openssh(Command):
    """List VGP OpenSSH Group Policy from the sysvol

This command lists openssh options from the sysvol that will be applied to winbind clients.

Example:
samba-tool gpo manage openssh list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                                'MACHINE\\VGP\\VTLA\\SshCfg',
                                'SshD\\manifest.xml'])
        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        policy = xml_data.find('policysetting')
        data = policy.find('data')
        configfile = data.find('configfile')
        for configsection in configfile.findall('configsection'):
            if configsection.find('sectionname').text:
                continue
            for kv in configsection.findall('keyvaluepair'):
                self.outf.write('%s %s\n' % (kv.find('key').text,
                                             kv.find('value').text))

class cmd_set_openssh(GPOCommand):
    """Sets a VGP OpenSSH Group Policy to the sysvol

This command sets an openssh setting to the sysvol for applying to winbind
clients. Not providing a value will unset the policy.

Example:
samba-tool gpo manage openssh set {31B2F340-016D-11D2-945F-00C04FB984F9} KerberosAuthentication Yes
    """

    synopsis = "%prog <gpo> <setting> [value] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "setting", "value?"]

    def run(self, gpo, setting, value=None, H=None, sambaopts=None,
            credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\SshCfg\\SshD'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
            configfile = data.find('configfile')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so create the xml structure
                xml_data = ET.ElementTree(ET.Element('vgppolicy'))
                policysetting = ET.SubElement(xml_data.getroot(),
                                              'policysetting')
                pv = ET.SubElement(policysetting, 'version')
                pv.text = '1'
                name = ET.SubElement(policysetting, 'name')
                name.text = 'Configuration File'
                description = ET.SubElement(policysetting, 'description')
                description.text = 'Represents Unix configuration file settings'
                apply_mode = ET.SubElement(policysetting, 'apply_mode')
                apply_mode.text = 'merge'
                data = ET.SubElement(policysetting, 'data')
                configfile = ET.SubElement(data, 'configfile')
                configsection = ET.SubElement(configfile, 'configsection')
                ET.SubElement(configsection, 'sectionname')
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        if value is not None:
            for configsection in configfile.findall('configsection'):
                if configsection.find('sectionname').text:
                    continue # Ignore Quest SSH settings
                settings = {}
                for kv in configsection.findall('keyvaluepair'):
                    settings[kv.find('key')] = kv
                if setting in settings.keys():
                    settings[setting].text = value
                else:
                    keyvaluepair = ET.SubElement(configsection, 'keyvaluepair')
                    key = ET.SubElement(keyvaluepair, 'key')
                    key.text = setting
                    dvalue = ET.SubElement(keyvaluepair, 'value')
                    dvalue.text = value
        else:
            for configsection in configfile.findall('configsection'):
                if configsection.find('sectionname').text:
                    continue # Ignore Quest SSH settings
                settings = {}
                for kv in configsection.findall('keyvaluepair'):
                    settings[kv.find('key').text] = kv
                if setting in settings.keys():
                    configsection.remove(settings[setting])
                else:
                    raise CommandError("Cannot remove '%s' because it does " \
                                       "not exist" % setting)

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_openssh(SuperCommand):
    """Manage OpenSSH Group Policy Objects"""
    subcommands = {}
    subcommands["list"] = cmd_list_openssh()
    subcommands["set"] = cmd_set_openssh()

class cmd_list_startup(Command):
    """List VGP Startup Script Group Policy from the sysvol

This command lists the startup script policies currently set on the sysvol.

Example:
samba-tool gpo manage scripts startup list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                                'MACHINE\\VGP\\VTLA\\Unix',
                                'Scripts\\Startup\\manifest.xml'])
        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        policy = xml_data.find('policysetting')
        data = policy.find('data')
        for listelement in data.findall('listelement'):
            script = listelement.find('script')
            script_path = '\\'.join(['\\', realm.lower(), 'Policies', gpo,
                                     'MACHINE\\VGP\\VTLA\\Unix\\Scripts',
                                     'Startup', script.text])
            parameters = listelement.find('parameters')
            run_as = listelement.find('run_as')
            if run_as is not None:
                run_as = run_as.text
            else:
                run_as = 'root'
            if parameters is not None:
                parameters = parameters.text
            else:
                parameters = ''
            self.outf.write('@reboot %s %s %s\n' % (run_as, script_path,
                                                  parameters))

class cmd_add_startup(GPOCommand):
    """Adds VGP Startup Script Group Policy to the sysvol

This command adds a startup script policy to the sysvol.

Example:
samba-tool gpo manage scripts startup add {31B2F340-016D-11D2-945F-00C04FB984F9} test_script.sh '\\-n \\-p all'
    """

    synopsis = "%prog <gpo> <script> [args] [run_as] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
        Option("--run-once", dest="run_once", default=False, action='store_true',
               help="Whether to run the script only once"),
    ]

    takes_args = ["gpo", "script", "args?", "run_as?"]

    def run(self, gpo, script, args=None, run_as=None, run_once=None,
            H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        if not os.path.exists(script):
            raise CommandError("Script '%s' does not exist" % script)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Unix\\Scripts\\Startup'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so create the xml structure
                xml_data = ET.ElementTree(ET.Element('vgppolicy'))
                policysetting = ET.SubElement(xml_data.getroot(),
                                              'policysetting')
                pv = ET.SubElement(policysetting, 'version')
                pv.text = '1'
                name = ET.SubElement(policysetting, 'name')
                name.text = 'Unix Scripts'
                description = ET.SubElement(policysetting, 'description')
                description.text = \
                    'Represents Unix scripts to run on Group Policy clients'
                data = ET.SubElement(policysetting, 'data')
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        with open(script, 'rb') as f:
            script_data = f.read()
        listelement = ET.SubElement(data, 'listelement')
        script_elm = ET.SubElement(listelement, 'script')
        script_elm.text = os.path.basename(script)
        hash = ET.SubElement(listelement, 'hash')
        hash.text = hashlib.md5(script_data).hexdigest().upper()
        if args is not None:
            parameters = ET.SubElement(listelement, 'parameters')
            parameters.text = args.strip('"').strip("'").replace('\\-', '-')
        if run_as is not None:
            run_as_elm = ET.SubElement(listelement, 'run_as')
            run_as_elm.text = run_as
        if run_once:
            ET.SubElement(listelement, 'run_once')

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        sysvol_script = '\\'.join([vgp_dir, os.path.basename(script)])
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            conn.savefile(sysvol_script, script_data)
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_remove_startup(GPOCommand):
    """Removes VGP Startup Script Group Policy from the sysvol

This command removes a startup script policy from the sysvol.

Example:
samba-tool gpo manage scripts startup remove {31B2F340-016D-11D2-945F-00C04FB984F9} test_script.sh
    """

    synopsis = "%prog <gpo> <script> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "script"]

    def run(self, gpo, script, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Unix\\Scripts\\Startup'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                raise CommandError("Cannot remove script '%s' "
                    "because it does not exist" % script)
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        for listelement in data.findall('listelement'):
            script_elm = listelement.find('script')
            if script_elm.text == os.path.basename(script.replace('\\', '/')):
                data.remove(listelement)
                break
        else:
            raise CommandError("Cannot remove script '%s' "
                "because it does not exist" % script)

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_startup(SuperCommand):
    """Manage Startup Scripts Group Policy Objects"""
    subcommands = {}
    subcommands["list"] = cmd_list_startup()
    subcommands["add"] = cmd_add_startup()
    subcommands["remove"] = cmd_remove_startup()

class cmd_scripts(SuperCommand):
    """Manage Scripts Group Policy Objects"""
    subcommands = {}
    subcommands["startup"] = cmd_startup()

class cmd_list_motd(Command):
    """List VGP MOTD Group Policy from the sysvol

This command lists the Message of the Day from the sysvol that will be applied
to winbind clients.

Example:
samba-tool gpo manage motd list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                                'MACHINE\\VGP\\VTLA\\Unix',
                                'MOTD\\manifest.xml'])
        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        policy = xml_data.find('policysetting')
        data = policy.find('data')
        text = data.find('text')
        self.outf.write(text.text)

class cmd_set_motd(GPOCommand):
    """Sets a VGP MOTD Group Policy to the sysvol

This command sets the Message of the Day to the sysvol for applying to winbind
clients. Not providing a value will unset the policy.

Example:
samba-tool gpo manage motd set {31B2F340-016D-11D2-945F-00C04FB984F9} "Message for today"
    """

    synopsis = "%prog <gpo> [value] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "value?"]

    def run(self, gpo, value=None, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Unix\\MOTD'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])

        if value is None:
            conn.unlink(vgp_xml)
            reg.increment_gpt_ini(machine_changed=True)
            return

        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so create the xml structure
                xml_data = ET.ElementTree(ET.Element('vgppolicy'))
                policysetting = ET.SubElement(xml_data.getroot(),
                                              'policysetting')
                pv = ET.SubElement(policysetting, 'version')
                pv.text = '1'
                name = ET.SubElement(policysetting, 'name')
                name.text = 'Text File'
                description = ET.SubElement(policysetting, 'description')
                description.text = 'Represents a Generic Text File'
                apply_mode = ET.SubElement(policysetting, 'apply_mode')
                apply_mode.text = 'replace'
                data = ET.SubElement(policysetting, 'data')
                filename = ET.SubElement(data, 'filename')
                filename.text = 'motd'
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        text = ET.SubElement(data, 'text')
        text.text = value

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_motd(SuperCommand):
    """Manage Message of the Day Group Policy Objects"""
    subcommands = {}
    subcommands["list"] = cmd_list_motd()
    subcommands["set"] = cmd_set_motd()

class cmd_list_issue(Command):
    """List VGP Issue Group Policy from the sysvol

This command lists the Prelogin Message from the sysvol that will be applied
to winbind clients.

Example:
samba-tool gpo manage issue list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                                'MACHINE\\VGP\\VTLA\\Unix',
                                'Issue\\manifest.xml'])
        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                return # The file doesn't exist, so there is nothing to list
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

        policy = xml_data.find('policysetting')
        data = policy.find('data')
        text = data.find('text')
        self.outf.write(text.text)

class cmd_set_issue(GPOCommand):
    """Sets a VGP Issue Group Policy to the sysvol

This command sets the Prelogin Message to the sysvol for applying to winbind
clients. Not providing a value will unset the policy.

Example:
samba-tool gpo manage issue set {31B2F340-016D-11D2-945F-00C04FB984F9} "Welcome to Samba!"
    """

    synopsis = "%prog <gpo> [value] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "value?"]

    def run(self, gpo, value=None, H=None, sambaopts=None, credopts=None,
            versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\Unix\\Issue'])
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])

        if value is None:
            conn.unlink(vgp_xml)
            reg.increment_gpt_ini(machine_changed=True)
            return

        try:
            xml_data = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so create the xml structure
                xml_data = ET.ElementTree(ET.Element('vgppolicy'))
                policysetting = ET.SubElement(xml_data.getroot(),
                                              'policysetting')
                pv = ET.SubElement(policysetting, 'version')
                pv.text = '1'
                name = ET.SubElement(policysetting, 'name')
                name.text = 'Text File'
                description = ET.SubElement(policysetting, 'description')
                description.text = 'Represents a Generic Text File'
                apply_mode = ET.SubElement(policysetting, 'apply_mode')
                apply_mode.text = 'replace'
                data = ET.SubElement(policysetting, 'data')
                filename = ET.SubElement(data, 'filename')
                filename.text = 'issue'
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        text = ET.SubElement(data, 'text')
        text.text = value

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_issue(SuperCommand):
    """Manage Issue Group Policy Objects"""
    subcommands = {}
    subcommands["list"] = cmd_list_issue()
    subcommands["set"] = cmd_set_issue()

class cmd_list_access(Command):
    """List VGP Host Access Group Policy from the sysvol

This command lists host access rules from the sysvol that will be applied to winbind clients.

Example:
samba-tool gpo manage access list {31B2F340-016D-11D2-945F-00C04FB984F9}
    """

    synopsis = "%prog <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo"]

    def run(self, gpo, H=None, sambaopts=None, credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        realm = self.lp.get('realm')
        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\VAS',
                             'HostAccessControl\\Allow\\manifest.xml'])
        try:
            allow = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                allow = None # The file doesn't exist, ignore it
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        if allow is not None:
            policy = allow.find('policysetting')
            data = policy.find('data')
            for listelement in data.findall('listelement'):
                adobject = listelement.find('adobject')
                name = adobject.find('name')
                domain = adobject.find('domain')
                self.outf.write('+:%s\\%s:ALL\n' % (domain.text, name.text))

        vgp_xml = '\\'.join([realm.lower(), 'Policies', gpo,
                             'MACHINE\\VGP\\VTLA\\VAS',
                             'HostAccessControl\\Deny\\manifest.xml'])
        try:
            deny = ET.fromstring(conn.loadfile(vgp_xml))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                deny = None # The file doesn't exist, ignore it
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        if deny is not None:
            policy = deny.find('policysetting')
            data = policy.find('data')
            for listelement in data.findall('listelement'):
                adobject = listelement.find('adobject')
                name = adobject.find('name')
                domain = adobject.find('domain')
                self.outf.write('-:%s\\%s:ALL\n' % (domain.text, name.text))

class cmd_add_access(GPOCommand):
    """Adds a VGP Host Access Group Policy to the sysvol

This command adds a host access setting to the sysvol for applying to winbind
clients. Any time an allow entry is detected by the client, an implicit deny
ALL will be assumed.

Example:
samba-tool gpo manage access add {31B2F340-016D-11D2-945F-00C04FB984F9} allow goodguy example.com
    """

    synopsis = "%prog <gpo> <allow/deny> <cn> <domain> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "etype", "cn", "domain"]

    def run(self, gpo, etype, cn, domain, H=None, sambaopts=None,
            credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        if etype == 'allow':
            vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                                 'MACHINE\\VGP\\VTLA\\VAS',
                                 'HostAccessControl\\Allow'])
        elif etype == 'deny':
            vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                                 'MACHINE\\VGP\\VTLA\\VAS',
                                 'HostAccessControl\\Deny'])
        else:
            raise CommandError("The entry type must be either 'allow' or "
                               "'deny'. Unknown type '%s'" % etype)
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                # The file doesn't exist, so create the xml structure
                xml_data = ET.ElementTree(ET.Element('vgppolicy'))
                policysetting = ET.SubElement(xml_data.getroot(),
                                              'policysetting')
                pv = ET.SubElement(policysetting, 'version')
                pv.text = '1'
                name = ET.SubElement(policysetting, 'name')
                name.text = 'Host Access Control'
                description = ET.SubElement(policysetting, 'description')
                description.text = 'Represents host access control data (pam_access)'
                apply_mode = ET.SubElement(policysetting, 'apply_mode')
                apply_mode.text = 'merge'
                data = ET.SubElement(policysetting, 'data')
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        url = dc_url(self.lp, self.creds, dc=domain)
        samdb = SamDB(url=url, session_info=system_session(),
                      credentials=self.creds, lp=self.lp)

        res = samdb.search(base=samdb.domain_dn(),
                           scope=ldb.SCOPE_SUBTREE,
                           expression="(cn=%s)" % cn,
                           attrs=['userPrincipalName',
                                  'samaccountname',
                                  'objectClass'])
        if len(res) == 0:
            raise CommandError('Unable to find user or group "%s"' % cn)

        objectclass = get_string(res[0]['objectClass'][-1])
        if objectclass not in ['user', 'group']:
            raise CommandError('%s is not a user or group' % cn)

        listelement = ET.SubElement(data, 'listelement')
        etype = ET.SubElement(listelement, 'type')
        etype.text = objectclass.upper()
        entry = ET.SubElement(listelement, 'entry')
        entry.text = '%s\\%s' % (samdb.domain_netbios_name(),
                                 get_string(res[0]['samaccountname'][-1]))
        if objectclass == 'group':
            groupattr = ET.SubElement(data, 'groupattr')
            groupattr.text = 'samAccountName'
        adobject = ET.SubElement(listelement, 'adobject')
        name = ET.SubElement(adobject, 'name')
        name.text = get_string(res[0]['samaccountname'][-1])
        domain_elm = ET.SubElement(adobject, 'domain')
        domain_elm.text = domain
        etype = ET.SubElement(adobject, 'type')
        etype.text = objectclass

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_remove_access(GPOCommand):
    """Remove a VGP Host Access Group Policy from the sysvol

This command removes a host access setting from the sysvol for applying to
winbind clients.

Example:
samba-tool gpo manage access remove {31B2F340-016D-11D2-945F-00C04FB984F9} allow goodguy example.com
    """

    synopsis = "%prog <gpo> <allow/deny> <name> <domain> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
    ]

    takes_args = ["gpo", "etype", "name", "domain"]

    def run(self, gpo, etype, name, domain, H=None, sambaopts=None,
            credopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        # We need to know writable DC to setup SMB connection
        if H and H.startswith('ldap://'):
            dc_hostname = H[7:]
            self.url = H
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)
            self.url = dc_url(self.lp, self.creds, dc=dc_hostname)

        # SMB connect to DC
        conn = smb_connection(dc_hostname,
                              'sysvol',
                              lp=self.lp,
                              creds=self.creds)

        self.samdb_connect()
        reg = RegistryGroupPolicies(gpo, self.lp, self.creds, self.samdb, H)

        realm = self.lp.get('realm')
        if etype == 'allow':
            vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                                 'MACHINE\\VGP\\VTLA\\VAS',
                                 'HostAccessControl\\Allow'])
        elif etype == 'deny':
            vgp_dir = '\\'.join([realm.lower(), 'Policies', gpo,
                                 'MACHINE\\VGP\\VTLA\\VAS',
                                 'HostAccessControl\\Deny'])
        else:
            raise CommandError("The entry type must be either 'allow' or "
                               "'deny'. Unknown type '%s'" % etype)
        vgp_xml = '\\'.join([vgp_dir, 'manifest.xml'])
        try:
            xml_data = ET.ElementTree(ET.fromstring(conn.loadfile(vgp_xml)))
            policy = xml_data.getroot().find('policysetting')
            data = policy.find('data')
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                raise CommandError("Cannot remove %s entry because it does "
                                   "not exist" % etype)
            elif e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            else:
                raise

        for listelement in data.findall('listelement'):
            adobject = listelement.find('adobject')
            name_elm = adobject.find('name')
            domain_elm = adobject.find('domain')
            if name_elm is not None and name_elm.text == name and \
               domain_elm is not None and domain_elm.text == domain:
                data.remove(listelement)
                break
        else:
            raise CommandError("Cannot remove %s entry because it does "
                                   "not exist" % etype)

        out = BytesIO()
        xml_data.write(out, encoding='UTF-8', xml_declaration=True)
        out.seek(0)
        try:
            create_directory_hier(conn, vgp_dir)
            conn.savefile(vgp_xml, out.read())
            reg.increment_gpt_ini(machine_changed=True)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_ACCESS_DENIED:
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            raise

class cmd_cse_register(Command):
    """Register a Client Side Extension (CSE) on the current host

This command takes a CSE filename as an argument, and registers it for
applying policy on the current host. This is not necessary for CSEs which
are distributed with the current version of Samba, but is useful for installing
experimental CSEs or custom built CSEs.
The <cse_file> argument MUST be a permanent location for the CSE. The register
command does not copy the file to some other directory. The samba-gpupdate
command will execute the CSE from the exact location specified from this
command.

Example:
samba-tool gpo cse register ./gp_chromium_ext.py gp_chromium_ext --machine
    """

    synopsis = "%prog <cse_file> <cse_name> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("--machine", default=False, action='store_true',
               help="Whether to register the CSE as Machine policy"),
        Option("--user", default=False, action='store_true',
               help="Whether to register the CSE as User policy"),
    ]

    takes_args = ["cse_file", "cse_name"]

    def run(self, cse_file, cse_name, machine=False, user=False,
            sambaopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()

        if machine == False and user == False:
            raise CommandError("Either --machine or --user must be selected")

        ext_guid = "{%s}" % str(uuid.uuid4())
        ext_path = os.path.realpath(cse_file)
        ret = register_gp_extension(ext_guid, cse_name, ext_path,
                                    smb_conf=self.lp.configfile,
                                    machine=machine, user=user)
        if not ret:
            raise CommandError('Failed to register CSE "%s"' % cse_name)

class cmd_cse_list(Command):
    """List the registered Client Side Extensions (CSEs) on the current host

This command lists the currently registered CSEs on the host.

Example:
samba-tool gpo cse list
    """

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, sambaopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()

        cses = list_gp_extensions(self.lp.configfile)
        for guid, gp_ext in cses.items():
            self.outf.write("UniqueGUID         : %s\n" % guid)
            self.outf.write("FileName           : %s\n" % gp_ext['DllName'])
            self.outf.write("ProcessGroupPolicy : %s\n" % \
                    gp_ext['ProcessGroupPolicy'])
            self.outf.write("MachinePolicy      : %s\n" % \
                    str(gp_ext['MachinePolicy']))
            self.outf.write("UserPolicy         : %s\n\n" % \
                    str(gp_ext['UserPolicy']))

class cmd_cse_unregister(Command):
    """Unregister a Client Side Extension (CSE) from the current host

This command takes a unique GUID as an argument (representing a registered
CSE), and unregisters it for applying policy on the current host. Use the
`samba-tool gpo cse list` command to determine the unique GUIDs of CSEs.

Example:
samba-tool gpo cse unregister {3F60F344-92BF-11ED-A1EB-0242AC120002}
    """

    synopsis = "%prog <guid> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
    }

    takes_args = ["guid"]

    def run(self, guid, sambaopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()

        ret = unregister_gp_extension(guid, self.lp.configfile)
        if not ret:
            raise CommandError('Failed to unregister CSE "%s"' % guid)

class cmd_cse(SuperCommand):
    """Manage Client Side Extensions"""
    subcommands = {}
    subcommands["register"] = cmd_cse_register()
    subcommands["list"] = cmd_cse_list()
    subcommands["unregister"] = cmd_cse_unregister()

class cmd_access(SuperCommand):
    """Manage Host Access Group Policy Objects"""
    subcommands = {}
    subcommands["list"] = cmd_list_access()
    subcommands["add"] = cmd_add_access()
    subcommands["remove"] = cmd_remove_access()

class cmd_manage(SuperCommand):
    """Manage Group Policy Objects"""
    subcommands = {}
    subcommands["sudoers"] = cmd_sudoers()
    subcommands["security"] = cmd_security()
    subcommands["smb_conf"] = cmd_smb_conf()
    subcommands["symlink"] = cmd_symlink()
    subcommands["files"] = cmd_files()
    subcommands["openssh"] = cmd_openssh()
    subcommands["scripts"] = cmd_scripts()
    subcommands["motd"] = cmd_motd()
    subcommands["issue"] = cmd_issue()
    subcommands["access"] = cmd_access()

class cmd_gpo(SuperCommand):
    """Group Policy Object (GPO) management."""

    subcommands = {}
    subcommands["listall"] = cmd_listall()
    subcommands["list"] = cmd_list()
    subcommands["show"] = cmd_show()
    subcommands["load"] = cmd_load()
    subcommands["remove"] = cmd_remove()
    subcommands["getlink"] = cmd_getlink()
    subcommands["setlink"] = cmd_setlink()
    subcommands["dellink"] = cmd_dellink()
    subcommands["listcontainers"] = cmd_listcontainers()
    subcommands["getinheritance"] = cmd_getinheritance()
    subcommands["setinheritance"] = cmd_setinheritance()
    subcommands["fetch"] = cmd_fetch()
    subcommands["create"] = cmd_create()
    subcommands["del"] = cmd_del()
    subcommands["aclcheck"] = cmd_aclcheck()
    subcommands["backup"] = cmd_backup()
    subcommands["restore"] = cmd_restore()
    subcommands["admxload"] = cmd_admxload()
    subcommands["manage"] = cmd_manage()
    subcommands["cse"] = cmd_cse()

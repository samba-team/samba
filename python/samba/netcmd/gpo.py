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
from __future__ import print_function
import os
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
from samba.ndr import ndr_unpack
import samba.security
import samba.auth
from samba.auth import AUTH_SESSION_INFO_DEFAULT_GROUPS, AUTH_SESSION_INFO_AUTHENTICATED, AUTH_SESSION_INFO_SIMPLE_PRIVILEGES
from samba.netcmd.common import netcmd_finddc
from samba import policy
from samba.samba3 import param as s3param
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


def attr_default(msg, attrname, default):
    '''get an attribute from a ldap msg with a default'''
    if attrname in msg:
        return msg[attrname][0]
    return default


def gpo_flags_string(value):
    '''return gpo flags string'''
    flags = policy.get_gpo_flags(value)
    if not flags:
        ret = 'NONE'
    else:
        ret = ' '.join(flags)
    return ret


def gplink_options_string(value):
    '''return gplink options string'''
    options = policy.get_gplink_options(value)
    if not options:
        ret = 'NONE'
    else:
        ret = ' '.join(options)
    return ret


def parse_gplink(gplink):
    '''parse a gPLink into an array of dn and options'''
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
    '''Encode an array of dn and options into gPLink string'''
    ret = "".join("[LDAP://%s;%d]" % (g['dn'], g['options']) for g in gplist)
    return ret


def dc_url(lp, creds, url=None, dc=None):
    '''If URL is not specified, return URL for writable DC.
    If dc is provided, use that to construct ldap URL'''

    if url is None:
        if dc is None:
            try:
                dc = netcmd_finddc(lp, creds)
            except Exception as e:
                raise RuntimeError("Could not find a DC for domain", e)
        url = 'ldap://' + dc
    return url


def get_gpo_dn(samdb, gpo):
    '''Construct the DN for gpo'''

    dn = samdb.get_default_basedn()
    dn.add_child(ldb.Dn(samdb, "CN=Policies,CN=System"))
    dn.add_child(ldb.Dn(samdb, "CN=%s" % gpo))
    return dn


def get_gpo_info(samdb, gpo=None, displayname=None, dn=None,
                 sd_flags=(security.SECINFO_OWNER |
                           security.SECINFO_GROUP |
                           security.SECINFO_DACL |
                           security.SECINFO_SACL)):
    '''Get GPO information using gpo, displayname or dn'''

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
    '''lists dn of containers for a GPO'''

    search_expr = "(&(objectClass=*)(gPLink=*%s*))" % gpo
    try:
        msg = samdb.search(expression=search_expr, attrs=['gPLink'])
    except Exception as e:
        raise CommandError("Could not find container(s) with GPO %s" % gpo, e)

    return msg


def del_gpo_link(samdb, container_dn, gpo):
    '''delete GPO link for the container'''
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
    '''Parse UNC string into a hostname, a service, and a filepath'''
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
                open(l_name, 'wb').write(data)


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

                data = open(l_name, 'rb').read()
                conn.savefile(r_name, data)


def create_directory_hier(conn, remotedir):
    elems = remotedir.replace('/', '\\').split('\\')
    path = ""
    for e in elems:
        path = path + '\\' + e
        if not conn.chkpath(path):
            conn.mkdir(path)

def smb_connection(dc_hostname, service, lp, creds, sign=False):
    # SMB connect to DC
    try:
        # the SMB bindings rely on having a s3 loadparm
        s3_lp = s3param.get_context()
        s3_lp.load(lp.configfile)
        conn = libsmb.Conn(dc_hostname, service, lp=s3_lp, creds=creds, sign=sign)
    except Exception:
        raise CommandError("Error connecting to '%s' using SMB" % dc_hostname)
    return conn


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
        '''make a ldap connection to the server'''
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

        self.url = dc_url(self.lp, self.creds, H)

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
        self.outf.write("dn           : %s\n" % msg.dn)
        self.outf.write("version      : %s\n" % attr_default(msg, 'versionNumber', '0'))
        self.outf.write("flags        : %s\n" % gpo_flags_string(int(attr_default(msg, 'flags', 0))))
        self.outf.write("ACL          : %s\n" % secdesc_sddl)
        self.outf.write("\n")


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
            msg = get_gpo_info(self.samdb, gpo=gpo)[0]
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
                              creds=self.creds, sign=True)

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
            open(os.path.join(gpodir, "GPT.INI"), "w").write(gpt_contents)
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
            sddl = dsacl2fsacl(ds_sd, domain_sid)
            fs_sd = security.descriptor.from_sddl(sddl, domain_sid)

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
                if re.match('(\s*<!ENTITY\s*[a-zA-Z0-9_]+\s*.*?>)+\s*\Z',
                            entities_content, flags=re.MULTILINE) is None:
                    raise CommandError("Entities file does not appear to "
                                       "conform to format\n"
                                       'e.g. <!ENTITY entity "value">')
                dtd_header += entities_content.strip()

            dtd_header += '\n]>\n'

        super(cmd_restore, self).run(displayname, H, tmpdir, sambaopts,
                                     credopts, versionopts)

        try:
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
            self.samdb.delete(ldb.Dn(self.samdb, "CN=User,%s" % str(gpo_dn)))
            self.samdb.delete(ldb.Dn(self.samdb, "CN=Machine,%s" % str(gpo_dn)))
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
                              creds=self.creds,
                              sign=True)

        smb_dir = '\\'.join([self.lp.get('realm').lower(),
                             'Policies', 'PolicyDefinitions'])
        try:
            conn.mkdir(smb_dir)
        except NTSTATUSError as e:
            if e.args[0] == 0xC0000022: # STATUS_ACCESS_DENIED
                raise CommandError("The authenticated user does "
                                   "not have sufficient privileges")
            elif e.args[0] != 0xC0000035: # STATUS_OBJECT_NAME_COLLISION
                raise

        for dirname, dirs, files in os.walk(admx_dir):
            for fname in files:
                path_in_admx = dirname.replace(admx_dir, '')
                full_path = os.path.join(dirname, fname)
                sub_dir = '\\'.join([smb_dir, path_in_admx]).replace('/', '\\')
                smb_path = '\\'.join([sub_dir, fname])
                try:
                    conn.mkdir(sub_dir)
                except NTSTATUSError as e:
                    if e.args[0] == 0xC0000022: # STATUS_ACCESS_DENIED
                        raise CommandError("The authenticated user does "
                                           "not have sufficient privileges")
                    elif e.args[0] != 0xC0000035: # STATUS_OBJECT_NAME_COLLISION
                        raise
                with open(full_path, 'rb') as f:
                    try:
                        conn.savefile(smb_path, f.read())
                    except NTSTATUSError as e:
                        if e.args[0] == 0xC0000022: # STATUS_ACCESS_DENIED
                            raise CommandError("The authenticated user does "
                                               "not have sufficient privileges")

class cmd_gpo(SuperCommand):
    """Group Policy Object (GPO) management."""

    subcommands = {}
    subcommands["listall"] = cmd_listall()
    subcommands["list"] = cmd_list()
    subcommands["show"] = cmd_show()
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

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
import samba.getopt as options
import ldb

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
from samba import smb
import uuid
from samba.ntacls import dsacl2fsacl
from samba.dcerpc import nbt
from samba.net import Net


def samdb_connect(ctx):
    '''make a ldap connection to the server'''
    try:
        ctx.samdb = SamDB(url=ctx.url,
                          session_info=system_session(),
                          credentials=ctx.creds, lp=ctx.lp)
    except Exception, e:
        raise CommandError("LDAP connection to %s failed " % ctx.url, e)


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
    a = gplink.split(']')
    for g in a:
        if not g:
            continue
        d = g.split(';')
        if len(d) != 2 or not d[0].startswith("[LDAP://"):
            raise RuntimeError("Badly formed gPLink '%s'" % g)
        ret.append({ 'dn' : d[0][8:], 'options' : int(d[1])})
    return ret


def encode_gplink(gplist):
    '''Encode an array of dn and options into gPLink string'''
    ret = ''
    for g in gplist:
        ret += "[LDAP://%s;%d]" % (g['dn'], g['options'])
    return ret


def dc_url(lp, creds, url=None, dc=None):
    '''If URL is not specified, return URL for writable DC.
    If dc is provided, use that to construct ldap URL'''

    if url is None:
        if dc is None:
            try:
                dc = netcmd_finddc(lp, creds)
            except Exception, e:
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
                 sd_flags=security.SECINFO_OWNER|security.SECINFO_GROUP|security.SECINFO_DACL|security.SECINFO_SACL):
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
                                    'gPCFileSysPath'],
                            controls=['sd_flags:1:%d' % sd_flags])
    except Exception, e:
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
    except Exception, e:
        raise CommandError("Could not find container(s) with GPO %s" % gpo, e)

    return msg


def del_gpo_link(samdb, container_dn, gpo):
    '''delete GPO link for the container'''
    # Check if valid Container DN and get existing GPlinks
    try:
        msg = samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                            expression="(objectClass=*)",
                            attrs=['gPLink'])[0]
    except Exception, e:
        raise CommandError("Container '%s' does not exist" % container_dn, e)

    found = False
    gpo_dn = str(get_gpo_dn(samdb, gpo))
    if 'gPLink' in msg:
        gplist = parse_gplink(msg['gPLink'][0])
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
    except Exception, e:
        raise CommandError("Error removing GPO from container", e)


def parse_unc(unc):
    '''Parse UNC string into a hostname, a service, and a filepath'''
    if unc.startswith('\\\\') and unc.startswith('//'):
        raise ValueError("UNC doesn't start with \\\\ or //")
    tmp = unc[2:].split('/', 2)
    if len(tmp) == 3:
        return tmp
    tmp = unc[2:].split('\\', 2)
    if len(tmp) == 3:
        return tmp
    raise ValueError("Invalid UNC string: %s" % unc)


def copy_directory_remote_to_local(conn, remotedir, localdir):
    if not os.path.isdir(localdir):
        os.mkdir(localdir)
    r_dirs = [ remotedir ]
    l_dirs = [ localdir ]
    while r_dirs:
        r_dir = r_dirs.pop()
        l_dir = l_dirs.pop()

        dirlist = conn.list(r_dir)
        for e in dirlist:
            r_name = r_dir + '\\' + e['name']
            l_name = os.path.join(l_dir, e['name'])

            if e['attrib'] & smb.FILE_ATTRIBUTE_DIRECTORY:
                r_dirs.append(r_name)
                l_dirs.append(l_name)
                os.mkdir(l_name)
            else:
                data = conn.loadfile(r_name)
                file(l_name, 'w').write(data)


def copy_directory_local_to_remote(conn, localdir, remotedir):
    if not conn.chkpath(remotedir):
        conn.mkdir(remotedir)
    l_dirs = [ localdir ]
    r_dirs = [ remotedir ]
    while l_dirs:
        l_dir = l_dirs.pop()
        r_dir = r_dirs.pop()

        dirlist = os.listdir(l_dir)
        for e in dirlist:
            l_name = os.path.join(l_dir, e)
            r_name = r_dir + '\\' + e

            if os.path.isdir(l_name):
                l_dirs.append(l_name)
                r_dirs.append(r_name)
                conn.mkdir(r_name)
            else:
                data = file(l_name, 'r').read()
                conn.savefile(r_name, data)


def create_directory_hier(conn, remotedir):
    elems = remotedir.replace('/', '\\').split('\\')
    path = ""
    for e in elems:
        path = path + '\\' + e
        if not conn.chkpath(path):
            conn.mkdir(path)


class cmd_listall(Command):
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

        samdb_connect(self)

        msg = get_gpo_info(self.samdb, None)

        for m in msg:
            self.outf.write("GPO          : %s\n" % m['name'][0])
            self.outf.write("display name : %s\n" % m['displayName'][0])
            self.outf.write("path         : %s\n" % m['gPCFileSysPath'][0])
            self.outf.write("dn           : %s\n" % m.dn)
            self.outf.write("version      : %s\n" % attr_default(m, 'versionNumber', '0'))
            self.outf.write("flags        : %s\n" % gpo_flags_string(int(attr_default(m, 'flags', 0))))
            self.outf.write("\n")


class cmd_list(Command):
    """List GPOs for an account."""

    synopsis = "%prog <username> [options]"

    takes_args = ['username']
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
            type=str, metavar="URL", dest="H")
        ]

    def run(self, username, H=None, sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        samdb_connect(self)

        try:
            msg = self.samdb.search(expression='(&(|(samAccountName=%s)(samAccountName=%s$))(objectClass=User))' %
                                                (ldb.binary_encode(username),ldb.binary_encode(username)))
            user_dn = msg[0].dn
        except Exception:
            raise CommandError("Failed to find account %s" % username)

        # check if its a computer account
        try:
            msg = self.samdb.search(base=user_dn, scope=ldb.SCOPE_BASE, attrs=['objectClass'])[0]
            is_computer = 'computer' in msg['objectClass']
        except Exception:
            raise CommandError("Failed to find objectClass for user %s" % username)

        session_info_flags = ( AUTH_SESSION_INFO_DEFAULT_GROUPS |
                               AUTH_SESSION_INFO_AUTHENTICATED )

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
                glist = parse_gplink(msg['gPLink'][0])
                for g in glist:
                    if not inherit and not (g['options'] & dsdb.GPLINK_OPT_ENFORCE):
                        continue
                    if g['options'] & dsdb.GPLINK_OPT_DISABLE:
                        continue

                    try:
                        sd_flags=security.SECINFO_OWNER|security.SECINFO_GROUP|security.SECINFO_DACL
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

        self.outf.write("GPOs for %s %s\n" % (msg_str, username))
        for g in gpos:
            self.outf.write("    %s %s\n" % (g[0], g[1]))


class cmd_show(Command):
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

        samdb_connect(self)

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


class cmd_getlink(Command):
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

        samdb_connect(self)

        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPLink'])[0]
        except Exception:
            raise CommandError("Container '%s' does not exist" % container_dn)

        if msg['gPLink']:
            self.outf.write("GPO(s) linked to DN %s\n" % container_dn)
            gplist = parse_gplink(msg['gPLink'][0])
            for g in gplist:
                msg = get_gpo_info(self.samdb, dn=g['dn'])
                self.outf.write("    GPO     : %s\n" % msg[0]['name'][0])
                self.outf.write("    Name    : %s\n" % msg[0]['displayName'][0])
                self.outf.write("    Options : %s\n" % gplink_options_string(g['options']))
                self.outf.write("\n")
        else:
            self.outf.write("No GPO(s) linked to DN=%s\n" % container_dn)


class cmd_setlink(Command):
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

        samdb_connect(self)

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
            gplist = parse_gplink(msg['gPLink'][0])
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
                gplist.insert(0, { 'dn' : gpo_dn, 'options' : gplink_options })
        else:
            gplist = []
            gplist.append({ 'dn' : gpo_dn, 'options' : gplink_options })

        gplink_str = encode_gplink(gplist)

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, container_dn)

        if existing_gplink:
            m['new_value'] = ldb.MessageElement(gplink_str, ldb.FLAG_MOD_REPLACE, 'gPLink')
        else:
            m['new_value'] = ldb.MessageElement(gplink_str, ldb.FLAG_MOD_ADD, 'gPLink')

        try:
            self.samdb.modify(m)
        except Exception, e:
            raise CommandError("Error adding GPO Link", e)

        self.outf.write("Added/Updated GPO link\n")
        cmd_getlink().run(container_dn, H, sambaopts, credopts, versionopts)


class cmd_dellink(Command):
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

        samdb_connect(self)

        # Check if valid GPO
        try:
            get_gpo_info(self.samdb, gpo=gpo)[0]
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)

        container_dn = ldb.Dn(self.samdb, container)
        del_gpo_link(self.samdb, container_dn, gpo)
        self.outf.write("Deleted GPO link.\n")
        cmd_getlink().run(container_dn, H, sambaopts, credopts, versionopts)


class cmd_listcontainers(Command):
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

        samdb_connect(self)

        msg = get_gpo_containers(self.samdb, gpo)
        if len(msg):
            self.outf.write("Container(s) using GPO %s\n" % gpo)
            for m in msg:
                self.outf.write("    DN: %s\n" % m['dn'])
        else:
            self.outf.write("No Containers using GPO %s\n" % gpo)


class cmd_getinheritance(Command):
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

        samdb_connect(self)

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


class cmd_setinheritance(Command):
    """Set inheritance flag on a container."""

    synopsis = "%prog <container_dn> <block|inherit> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = [ 'container_dn', 'inherit_state' ]

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

        samdb_connect(self)
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
        except Exception, e:
            raise CommandError("Error setting inheritance state %s" % inherit_state, e)


class cmd_fetch(Command):
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

        samdb_connect(self)
        try:
            msg = get_gpo_info(self.samdb, gpo)[0]
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)

        # verify UNC path
        unc = msg['gPCFileSysPath'][0]
        try:
            [dom_name, service, sharepath] = parse_unc(unc)
        except ValueError:
            raise CommandError("Invalid GPO path (%s)" % unc)

        # SMB connect to DC
        try:
            conn = smb.SMB(dc_hostname, service, lp=self.lp, creds=self.creds)
        except Exception:
            raise CommandError("Error connecting to '%s' using SMB" % dc_hostname)

        # Copy GPT
        if tmpdir is None:
            tmpdir = "/tmp"
        if not os.path.isdir(tmpdir):
            raise CommandError("Temoprary directory '%s' does not exist" % tmpdir)

        localdir = os.path.join(tmpdir, "policy")
        if not os.path.isdir(localdir):
            os.mkdir(localdir)

        gpodir = os.path.join(localdir, gpo)
        if os.path.isdir(gpodir):
            raise CommandError("GPO directory '%s' already exists, refusing to overwrite" % gpodir)

        try:
            os.mkdir(gpodir)
            copy_directory_remote_to_local(conn, sharepath, gpodir)
        except Exception, e:
            # FIXME: Catch more specific exception
            raise CommandError("Error copying GPO from DC", e)
        self.outf.write('GPO copied to %s\n' % gpodir)


class cmd_create(Command):
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

        samdb_connect(self)

        msg = get_gpo_info(self.samdb, displayname=displayname)
        if msg.count > 0:
            raise CommandError("A GPO already existing with name '%s'" % displayname)

        # Create new GUID
        guid  = str(uuid.uuid4())
        gpo = "{%s}" % guid.upper()
        realm = cldap_ret.dns_domain
        unc_path = "\\\\%s\\sysvol\\%s\\Policies\\%s" % (realm, realm, gpo)

        # Create GPT
        if tmpdir is None:
            tmpdir = "/tmp"
        if not os.path.isdir(tmpdir):
            raise CommandError("Temporary directory '%s' does not exist" % tmpdir)

        localdir = os.path.join(tmpdir, "policy")
        if not os.path.isdir(localdir):
            os.mkdir(localdir)

        gpodir = os.path.join(localdir, gpo)
        if os.path.isdir(gpodir):
            raise CommandError("GPO directory '%s' already exists, refusing to overwrite" % gpodir)

        try:
            os.mkdir(gpodir)
            os.mkdir(os.path.join(gpodir, "Machine"))
            os.mkdir(os.path.join(gpodir, "User"))
            gpt_contents = "[General]\r\nVersion=0\r\n"
            file(os.path.join(gpodir, "GPT.INI"), "w").write(gpt_contents)
        except Exception, e:
            raise CommandError("Error Creating GPO files", e)

        # Connect to DC over SMB
        [dom_name, service, sharepath] = parse_unc(unc_path)
        try:
            conn = smb.SMB(dc_hostname, service, lp=self.lp, creds=self.creds)
        except Exception, e:
            raise CommandError("Error connecting to '%s' using SMB" % dc_hostname, e)

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
            ds_sd_flags = ( security.SECINFO_OWNER |
                            security.SECINFO_GROUP |
                            security.SECINFO_DACL )
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
            sio = ( security.SECINFO_OWNER |
                    security.SECINFO_GROUP |
                    security.SECINFO_DACL |
                    security.SECINFO_PROTECTED_DACL )
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
            controls=["permissive_modify:0"]
            self.samdb.modify(m, controls=controls)
        except Exception:
            self.samdb.transaction_cancel()
            raise
        else:
            self.samdb.transaction_commit()

        self.outf.write("GPO '%s' created as %s\n" % (displayname, gpo))


class cmd_del(Command):
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

        samdb_connect(self)

        # Check if valid GPO
        try:
            msg = get_gpo_info(self.samdb, gpo=gpo)[0]
            unc_path = msg['gPCFileSysPath'][0]
        except Exception:
            raise CommandError("GPO '%s' does not exist" % gpo)

        # Connect to DC over SMB
        [dom_name, service, sharepath] = parse_unc(unc_path)
        try:
            conn = smb.SMB(dc_hostname, service, lp=self.lp, creds=self.creds)
        except Exception, e:
            raise CommandError("Error connecting to '%s' using SMB" % dc_hostname, e)

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


class cmd_aclcheck(Command):
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

        samdb_connect(self)

        msg = get_gpo_info(self.samdb, None)

        for m in msg:
            # verify UNC path
            unc = m['gPCFileSysPath'][0]
            try:
                [dom_name, service, sharepath] = parse_unc(unc)
            except ValueError:
                raise CommandError("Invalid GPO path (%s)" % unc)

            # SMB connect to DC
            try:
                conn = smb.SMB(dc_hostname, service, lp=self.lp, creds=self.creds)
            except Exception:
                raise CommandError("Error connecting to '%s' using SMB" % dc_hostname)

            fs_sd = conn.get_acl(sharepath, security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL, security.SEC_FLAG_MAXIMUM_ALLOWED)

            ds_sd_ndr = m['nTSecurityDescriptor'][0]
            ds_sd = ndr_unpack(security.descriptor, ds_sd_ndr).as_sddl()

            # Create a file system security descriptor
            domain_sid = security.dom_sid(self.samdb.get_domain_sid())
            expected_fs_sddl = dsacl2fsacl(ds_sd, domain_sid)

            if (fs_sd.as_sddl(domain_sid) != expected_fs_sddl):
                raise CommandError("Invalid GPO ACL %s on path (%s), should be %s" % (fs_sd.as_sddl(domain_sid), sharepath, expected_fs_sddl))


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

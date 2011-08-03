#!/usr/bin/env python
#
# implement samba_tool gpo commands
#
# Copyright Andrew Tridgell 2010
# Copyright Giampaolo Lauria 2011 <lauria2@yahoo.com>
# Copyright Amitay Isaacs 2011 <amitay@gmail.com>
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
from samba import drs_utils, nttime2string, dsdb, dcerpc
from samba.dcerpc import misc
from samba.ndr import ndr_unpack
import samba.security
import samba.auth
from samba.auth import AUTH_SESSION_INFO_DEFAULT_GROUPS, AUTH_SESSION_INFO_AUTHENTICATED, AUTH_SESSION_INFO_SIMPLE_PRIVILEGES
from samba.netcmd.common import netcmd_finddc
from samba import policy
from samba import smb
import uuid


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
                raise RunTimeError("Could not find a DC for domain", e)
        url = 'ldap://' + dc
    return url


def get_gpo_dn(samdb, gpo):
    '''Construct the DN for gpo'''

    dn = samdb.get_default_basedn()
    dn.add_child(ldb.Dn(samdb, "CN=Policies,DC=System"))
    dn.add_child(ldb.Dn(samdb, "CN=%s" % gpo))
    return dn


def get_gpo_info(samdb, gpo=None, displayname=None, dn=None):
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
                                    'gPCFileSysPath'])
    except Exception, e:
        if gpo is not None:
            mesg = "Cannot get information for GPO %s" % gpo
        else:
            mesg = "Cannot get information for GPOs"
        raise CommandError(mesg, e)

    return msg


def parse_unc(unc):
    '''Parse UNC string into a hostname, a service, and a filepath'''
    if unc.startswith('\\\\') and unc.startswith('//'):
        return []
    tmp = unc[2:].split('/', 2)
    if len(tmp) == 3:
        return tmp
    tmp = unc[2:].split('\\', 2)
    if len(tmp) == 3:
        return tmp;
    return []


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
    """list all GPOs"""

    synopsis = "%prog gpo listall [options]"

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
            print("GPO          : %s" % m['name'][0])
            print("display name : %s" % m['displayName'][0])
            print("path         : %s" % m['gPCFileSysPath'][0])
            print("dn           : %s" % m.dn)
            print("version      : %s" % attr_default(m, 'versionNumber', '0'))
            print("flags        : %s" % gpo_flags_string(int(attr_default(m, 'flags', 0))))
            print("")


class cmd_list(Command):
    """list GPOs for an account"""

    synopsis = "%prog gpo list <username> [options]"

    takes_args = [ 'username' ]

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H")
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
        except Exception, e:
            raise CommandError("Failed to find account %s" % username, e)

        # check if its a computer account
        try:
            msg = self.samdb.search(base=user_dn, scope=ldb.SCOPE_BASE, attrs=['objectClass'])[0]
            is_computer = 'computer' in msg['objectClass']
        except Exception, e:
            raise CommandError("Failed to find objectClass for user %s" % username, e)

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
                        gmsg = self.samdb.search(base=g['dn'], scope=ldb.SCOPE_BASE,
                                                 attrs=['name', 'displayName', 'flags',
                                                        'ntSecurityDescriptor'])
                    except Exception:
                        print("Failed to fetch gpo object %s" % g['dn'])
                        continue

                    secdesc_ndr = gmsg[0]['ntSecurityDescriptor'][0]
                    secdesc = ndr_unpack(dcerpc.security.descriptor, secdesc_ndr)

                    try:
                        samba.security.access_check(secdesc, token,
                                                    dcerpc.security.SEC_STD_READ_CONTROL |
                                                    dcerpc.security.SEC_ADS_LIST |
                                                    dcerpc.security.SEC_ADS_READ_PROP)
                    except RuntimeError:
                        print("Failed access check on %s" % msg.dn)
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

        print("GPOs for %s %s" % (msg_str, username))
        for g in gpos:
            print("    %s %s" % (g[0], g[1]))


class cmd_show(Command):
    """Show information for a GPO"""

    synopsis = "%prog gpo show <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = [ 'gpo' ]

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
        except Exception, e:
            raise CommandError("GPO %s does not exist" % gpo, e)

        secdesc_ndr = msg['ntSecurityDescriptor'][0]
        secdesc = ndr_unpack(dcerpc.security.descriptor, secdesc_ndr)

        print("GPO          : %s" % msg['name'][0])
        print("display name : %s" % msg['displayName'][0])
        print("path         : %s" % msg['gPCFileSysPath'][0])
        print("dn           : %s" % msg.dn)
        print("version      : %s" % attr_default(msg, 'versionNumber', '0'))
        print("flags        : %s" % gpo_flags_string(int(attr_default(msg, 'flags', 0))))
        print("ACL          : %s" % secdesc.as_sddl())
        print("")


class cmd_getlink(Command):
    """List GPO Links for a container"""

    synopsis = "%prog gpo getlink <container_dn> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = [ 'container_dn' ]

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
                                    attrs=['gPlink'])[0]
        except Exception, e:
            raise CommandError("Could not find Container DN %s (%s)" % container_dn, e)

        if 'gPLink' in msg:
            print("GPO(s) linked to DN %s" % container_dn)
            gplist = parse_gplink(msg['gPLink'][0])
            for g in gplist:
                msg = get_gpo_info(self.samdb, dn=g['dn'])
                print("    GPO     : %s" % msg[0]['name'][0])
                print("    Name    : %s" % msg[0]['displayName'][0])
                print("    Options : %s" % gplink_options_string(g['options']))
                print("")
        else:
            print("No GPO(s) linked to DN=%s" % container_dn)


class cmd_setlink(Command):
    """Add or Update a GPO link to a container"""

    synopsis = "%prog gpo setlink <container_dn> <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = [ 'container_dn', 'gpo' ]

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
        except Exception, e:
            raise CommandError("GPO %s does not exist" % gpo_dn, e)
        gpo_dn = get_gpo_dn(self.samdb, gpo)

        # Check if valid Container DN
        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPlink'])[0]
        except Exception, e:
            raise CommandError("Could not find container DN %s" % container_dn, e)

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
            if not found:
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

        print("Added/Updated GPO link")
        cmd_getlink().run(container_dn, H, sambaopts, credopts, versionopts)


class cmd_dellink(Command):
    """Delete GPO link from a container"""

    synopsis = "%prog gpo dellink <container_dn> <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = [ 'container_dn', 'gpo' ]

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        ]

    def run(self, container_dn, gpo_dn, H=None, sambaopts=None, credopts=None,
                versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        samdb_connect(self)

        # Check if valid GPO
        try:
            msg = get_gpo_info(self.sambdb, gpo=gpo)[0]
        except Exception, e:
                raise CommandError("GPO %s does not exist" % gpo, e)
        gpo_dn = get_gpo_dn(self.samdb, gpo)

        # Check if valid Container DN and get existing GPlinks
        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPlink'])[0]
        except Exception, e:
            raise CommandError("Could not find container DN %s" % dn, e)

        if 'gPLink' in msg:
            gplist = parse_gplink(msg['gPLink'][0])
            for g in gplist:
                if g['dn'].lower() == gpo_dn.lower():
                    gplist.remove(g)
                    break
        else:
            raise CommandError("Specified GPO is not linked to this container");

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, container_dn)

        if gplist:
            gplink_str = encode_gplink(gplist)
            m['new_value'] = ldb.MessageElement(gplink_str, ldb.FLAG_MOD_REPLACE, 'gPLink')
        else:
            m['new_value'] = ldb.MessageElement('', ldb.FLAG_MOD_DELETE, 'gPLink')

        try:
            self.samdb.modify(m)
        except Exception, e:
            raise CommandError("Error Removing GPO Link (%s)" % e)

        print("Deleted GPO link.")
        cmd_getlink().run(container_dn, H, sambaopts, credopts, versionopts)


class cmd_getinheritance(Command):
    """Get inheritance flag for a container"""

    synopsis = "%prog gpo getinheritance <container_dn> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = [ 'container_dn' ]

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str)
        ]

    def run(self, container_dn, H=None, sambaopts=None, credopts=None,
                versionopts=None):

        self.url = H
        self.lp = sambaopts.get_loadparm()

        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        samdb_connect(self)

        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPOptions'])[0]
        except Exception, e:
            raise CommandError("Could not find Container DN %s" % container_dn, e)

        inheritance = 0
        if 'gPOptions' in msg:
            inheritance = int(msg['gPOptions'][0]);

        if inheritance == dsdb.GPO_BLOCK_INHERITANCE:
            print("Container has GPO_BLOCK_INHERITANCE")
        else:
            print("Container has GPO_INHERIT")


class cmd_setinheritance(Command):
    """Set inheritance flag on a container"""

    synopsis = "%prog gpo setinheritance <container_dn> <block|inherit> [options]"

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

        self.url = H
        self.lp = sambaopts.get_loadparm()

        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        samdb_connect(self)

        try:
            msg = self.samdb.search(base=container_dn, scope=ldb.SCOPE_BASE,
                                    expression="(objectClass=*)",
                                    attrs=['gPOptions'])[0]
        except Exception, e:
            raise CommandError("Could not find Container DN %s" % container_dn, e)

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, container_dn)

        if 'gPOptions' in msg:
            m['new_value'] = ldb.MessageElement(str(inheritance), ldb.FLAG_MOD_REPLACE, 'gPOptions')
        else:
            m['new_value'] = ldb.MessageElement(str(inheritance), ldb.FLAG_MOD_ADD, 'gPOptions');

        try:
            self.samdb.modify(m)
        except Exception, e:
            raise CommandError("Error setting inheritance state %s" % inherit_state, e)


class cmd_fetch(Command):
    """Download a GPO"""

    synopsis = "%prog gpo fetch <gpo> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = [ 'gpo' ]

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--tmpdir", help="Temporary directory for copying policy files", type=str)
        ]

    def run(self, gpo, H=None, tmpdir=None, sambaopts=None, credopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        dc_hostname = netcmd_finddc(self.lp, self.creds)
        self.url = dc_url(self.lp, self.creds, H, dc=dc_hostname)

        samdb_connect(self)
        try:
            msg = get_gpo_info(self.samdb, gpo)[0]
        except Exception, e:
            raise CommandError("GPO %s does not exist" % gpo)

        # verify UNC path
        unc = msg['gPCFileSysPath'][0]
        try:
            [dom_name, service, sharepath] = parse_unc(unc)
        except:
            raise CommandError("Invalid GPO path (%s)" % unc)

        # SMB connect to DC
        try:
            conn = smb.SMB(dc_hostname, service, lp=self.lp, creds=self.creds)
        except Exception, e:
            raise CommandError("Error connecting to '%s' using SMB" % dc_hostname, e)

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
            raise CommandError("Error copying GPO from DC", e)
        print('GPO copied to %s' % gpodir)


class cmd_create(Command):
    """Create an empty GPO"""

    synopsis = "%prog gpo create <displayname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_args = [ 'displayname' ]

    takes_options = [
        Option("-H", help="LDB URL for database or target server", type=str),
        Option("--tmpdir", help="Temporary directory for copying policy files", type=str)
        ]

    def run(self, displayname, H=None, tmpdir=None, sambaopts=None, credopts=None, 
            versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.url = dc_url(self.lp, self.creds, H)

        dc_hostname = netcmd_finddc(self.lp, self.creds)
        samdb_connect(self)

        msg = get_gpo_info(self.samdb, displayname=displayname)
        if msg.count > 0:
            raise CommandError("A GPO already existing with name '%s'" % displayname)

        # Create new GUID
        guid  = str(uuid.uuid4())
        gpo = "{%s}" % guid.upper()
        realm = self.lp.get('realm')
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

        # Add cn=<guid>
        gpo_dn = self.samdb.get_default_basedn()
        gpo_dn.add_child(ldb.Dn(self.samdb, "CN=Policies,CN=System"))
        gpo_dn.add_child(ldb.Dn(self.samdb, "CN=%s" % gpo))

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, gpo_dn.get_linearized())
        m['a01'] = ldb.MessageElement("groupPolicyContainer", ldb.FLAG_MOD_ADD, "objectClass")
        m['a02'] = ldb.MessageElement(displayname, ldb.FLAG_MOD_ADD, "displayName")
        m['a03'] = ldb.MessageElement(unc_path, ldb.FLAG_MOD_ADD, "gPCFileSysPath")
        m['a04'] = ldb.MessageElement("0", ldb.FLAG_MOD_ADD, "flags")
        m['a05'] = ldb.MessageElement("0", ldb.FLAG_MOD_ADD, "versionNumber")
        m['a06'] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_ADD, "showInAdvancedViewOnly")
        m['a07'] = ldb.MessageElement("2", ldb.FLAG_MOD_ADD, "gpcFunctionalityVersion")
        try:
            self.samdb.add(m)
        except Exception, e:
            raise CommandError("Error adding GPO in AD", e)

        # Add cn=User,cn=<guid>
        child_dn = gpo_dn
        child_dn.add_child(ldb.Dn(self.samdb, "CN=User"))

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, child_dn.get_linearized())
        m['a01'] = ldb.MessageElement("container", ldb.FLAG_MOD_ADD, "objectClass")
        m['a02'] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_ADD, "showInAdvancedViewOnly")
        try:
            self.samdb.add(m)
        except Exception, e:
            raise CommandError("Error adding GPO in AD", e)

        # Add cn=User,cn=<guid>
        child_dn = gpo_dn
        child_dn.add_child(ldb.Dn(self.samdb, "CN=Machine"))

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, child_dn.get_linearized())
        m['a01'] = ldb.MessageElement("container", ldb.FLAG_MOD_ADD, "objectClass")
        m['a02'] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_ADD, "showInAdvancedViewOnly")
        try:
            self.samdb.add(m)
        except Exception, e:
            raise CommandError("Error adding GPO in AD", e)

        # Copy GPO files over SMB
        [dom_name, service, sharepath] = parse_unc(unc_path)
        try:
            conn = smb.SMB(dc_hostname, service, lp=self.lp, creds=self.creds)
        except Exception, e:
            raise CommandError("Error connecting to '%s' using SMB" % dc_hostname, e)

        try:
            create_directory_hier(conn, sharepath)
            copy_directory_local_to_remote(conn, gpodir, sharepath)
        except Exception, e:
            raise CommandError("Error Copying GPO to DC", e)

        # Get new security descriptor
        msg = get_gpo_info(self.samdb, gpo=gpo)[0]
        ds_sd_ndr = msg['ntSecurityDescriptor'][0]
        ds_sd = ndr_unpack(dcerpc.security.descriptor, ds_sd_ndr)

        # Create a file system security descriptor
        fs_sd = dcerpc.security.descriptor()
        fs_sd.owner_sid = ds_sd.owner_sid
        fs_sd.group_sid = ds_sd.group_sid
        fs_sd.type = ds_sd.type
        fs_sd.revision = ds_sd.revision

        # Copy sacl
        fs_sd.sacl = ds_sd.sacl

        # Copy dacl
        dacl = ds_sd.dacl
        for ace in dacl.aces:
            # Don't add the allow for SID_BUILTIN_PREW2K
            if (not (ace.type & dcerpc.security.SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT) and 
                    ace.trustee == dcerpc.security.SID_BUILTIN_PREW2K):
                continue

            # Copy the ace from the directory server security descriptor
            new_ace = ace

            # Set specific inheritance flags for within the GPO
            new_ace.flags |= (dcerpc.security.SEC_ACE_FLAG_OBJECT_INHERIT |
                             dcerpc.security.SEC_ACE_FLAG_CONTAINER_INHERIT)
            if ace.trustee == dcerpc.security.SID_CREATOR_OWNER:
                new_ace.flags |= dcerpc.security.SEC_ACE_FLAG_INHERIT_ONLY

            # Get a directory access mask from the assigned access mask on the ldap object
            new_ace.access_mask = policy.ads_to_dir_access_mask(ace.access_mask)

            # Add the ace to DACL
            fs_sd.dacl_add(new_ace)

        # Set ACL
        try:
            conn.set_acl(sharepath, fs_sd)
        except Exception, e:
            raise CommandError("Error setting ACL on GPT", e)

        print "GPO '%s' created as %s" % (displayname, gpo)


class cmd_gpo(SuperCommand):
    """Group Policy Object (GPO) commands"""

    subcommands = {}
    subcommands["listall"] = cmd_listall()
    subcommands["list"] = cmd_list()
    subcommands["show"] = cmd_show()
    subcommands["getlink"] = cmd_getlink()
    subcommands["setlink"] = cmd_setlink()
    subcommands["dellink"] = cmd_dellink()
    subcommands["getinheritance"] = cmd_getinheritance()
    subcommands["setinheritance"] = cmd_setinheritance()
    subcommands["fetch"] = cmd_fetch()
    subcommands["create"] = cmd_create()

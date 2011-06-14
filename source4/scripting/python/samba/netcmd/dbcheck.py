#!/usr/bin/env python
#
# Samba4 AD database checker
#
# Copyright (C) Andrew Tridgell 2011
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

import samba, ldb
import samba.getopt as options
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dcerpc import security
from samba.netcmd import (
    Command,
    CommandError,
    Option
    )

def confirm(self, msg):
    '''confirm an action with the user'''
    if self.yes:
        print("%s [YES]" % msg)
        return True
    v = raw_input(msg + ' [y/N] ')
    return v.upper() in ['Y', 'YES']


def empty_attribute(self, dn, attrname):
    '''fix empty attributes'''
    print("ERROR: Empty attribute %s in %s" % (attrname, dn))
    if not self.fix:
        return
    if not confirm(self, 'Remove empty attribute %s from %s?' % (attrname, dn)):
        print("Not fixing empty attribute %s" % attrname)
        return

    m = ldb.Message()
    m.dn = dn
    m[attrname] = ldb.MessageElement('', ldb.FLAG_MOD_DELETE, attrname)
    try:
        self.samdb.modify(m, controls=["relax:0"], validate=False)
    except Exception, msg:
        print("Failed to remove empty attribute %s : %s" % (attrname, msg))
        return
    print("Removed empty attribute %s" % attrname)



def check_object(self, dn):
    '''check one object'''
    if self.verbose:
        print("Checking object %s" % dn)
    res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE)
    if len(res) != 1:
        print("Object %s disappeared during check" % dn)
        return
    obj = res[0]
    for attrname in obj:
        if attrname == 'dn':
            continue
        for val in obj[attrname]:
            if val == '':
                empty_attribute(self, dn, attrname)
                continue


class cmd_dbcheck(Command):
    """check local AD database for errors"""
    synopsis = "dbcheck <DN> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptionsDouble,
    }

    takes_args = ["DN?"]

    takes_options = [
        Option("--scope", dest="scope", default="SUB",
            help="Pass search scope that builds DN list. Options: SUB, ONE, BASE"),
        Option("--fix", dest="fix", default=False, action='store_true',
               help='Fix any errors found'),
        Option("--yes", dest="yes", default=False, action='store_true',
               help="don't confirm changes, just do them all"),
        Option("-v", "--verbose", dest="verbose", action="store_true", default=False,
            help="Print more details of checking"),
        ]

    def run(self, DN=None, verbose=False, fix=False, yes=False,
            scope="SUB", credopts=None, sambaopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.samdb = SamDB(session_info=system_session(), url=None,
                           credentials=self.creds, lp=self.lp)
        self.verbose = verbose
        self.fix = fix
        self.yes = yes

        scope_map = { "SUB": ldb.SCOPE_SUBTREE, "BASE":ldb.SCOPE_BASE, "ONE":ldb.SCOPE_ONELEVEL }
        scope = scope.upper()
        if not scope in scope_map:
            raise CommandError("Unknown scope %s" % scope)
        self.search_scope = scope_map[scope]

        res = self.samdb.search(base=DN, scope=self.search_scope, attrs=['dn'])
        for object in res:
            check_object(self, object.dn)
        print('Checked %u objects' % len(res))

#!/usr/bin/python

# Unix SMB/CIFS implementation.
# Vampire a remote domain
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

from net import libnet
import optparse
import samba.getopt as options
import param
from auth import system_session
import sys

parser = optparse.OptionParser("vampire [options] <domain>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

def vampire(domain, session_info, credentials, lp):
    ctx = libnet(lp_ctx=lp)
    ctx.cred = credentials
    machine_creds = Credentials();
    machine_creds.set_domain(domain);
    if not machine_creds.set_machine_account():
        raise Exception("Failed to access domain join information!")
    ctx.samsync_ldb(vampire_ctx, machine_creds=machine_creds, 
                    session_info=session_info)

lp = sambaopts.get_loadparm()
vampire(args[0], session_info=system_session(), 
        credentials=credopts.get_credentials(), lp=lp)

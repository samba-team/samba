# Samba common group policy functions
#
# Copyright Andrew Tridgell 2010
# Copyright Amitay Isaacs 2011-2012 <amitay@gmail.com>
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
import ldb
from samba.credentials import SMB_SIGNING_REQUIRED
from samba.samba3 import param as s3param
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.netcmd import CommandError

def get_gpo_dn(samdb, gpo):
    '''Construct the DN for gpo'''

    dn = samdb.get_default_basedn()
    dn.add_child(ldb.Dn(samdb, "CN=Policies,CN=System"))
    dn.add_child(ldb.Dn(samdb, "CN=%s" % gpo))
    return dn

def create_directory_hier(conn, remotedir):
    elems = remotedir.replace('/', '\\').split('\\')
    path = ""
    for e in elems:
        path = path + '\\' + e
        if not conn.chkpath(path):
            conn.mkdir(path)

def smb_connection(dc_hostname, service, lp, creds):
    # SMB connect to DC
    # Force signing for the smb connection
    saved_signing_state = creds.get_smb_signing()
    creds.set_smb_signing(SMB_SIGNING_REQUIRED)
    try:
        # the SMB bindings rely on having a s3 loadparm
        s3_lp = s3param.get_context()
        s3_lp.load(lp.configfile)
        conn = libsmb.Conn(dc_hostname, service, lp=s3_lp, creds=creds)
    except Exception:
        raise CommandError("Error connecting to '%s' using SMB" % dc_hostname)
    # Reset signing state
    creds.set_smb_signing(saved_signing_state)
    return conn

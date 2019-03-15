# common functions for samba-tool python commands
#
# Copyright Andrew Tridgell 2010
# Copyright Giampaolo Lauria 2011 <lauria2@yahoo.com>
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

import re
from samba.dcerpc import nbt
from samba.net import Net
import ldb

def _get_user_realm_domain(user):
    r""" get the realm or the domain and the base user
        from user like:
        * username
        * DOMAIN\username
        * username@REALM
    """
    baseuser = user
    realm = ""
    domain = ""
    m = re.match(r"(\w+)\\(\w+$)", user)
    if m:
        domain = m.group(1)
        baseuser = m.group(2)
        return (baseuser.lower(), domain.upper(), realm)
    m = re.match(r"(\w+)@(\w+)", user)
    if m:
        baseuser = m.group(1)
        realm = m.group(2)
    return (baseuser.lower(), domain, realm.upper())


def netcmd_dnsname(lp):
    '''return the full DNS name of our own host. Used as a default
       for hostname when running status queries'''
    return lp.get('netbios name').lower() + "." + lp.get('realm').lower()


def netcmd_finddc(lp, creds, realm=None):
    '''Return domain-name of a writable/ldap-capable DC for the default
       domain (parameter "realm" in smb.conf) unless another realm has been
       specified as argument'''
    net = Net(creds=creds, lp=lp)
    if realm is None:
        realm = lp.get('realm')
    cldap_ret = net.finddc(domain=realm,
                           flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE)
    return cldap_ret.pdc_dns_name


def netcmd_get_domain_infos_via_cldap(lp, creds, address=None):
    '''Return domain information (CLDAP record) of the ldap-capable
       DC with the specified address'''
    net = Net(creds=creds, lp=lp)
    cldap_ret = net.finddc(address=address,
                           flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS)
    return cldap_ret

def is_printable_attr_val(val):
    import unicodedata

    # The value must be convertable to a string value.
    try:
        str_val = str(val)
    except:
        return False

    # Characters of the Unicode Character Category "C" ("Other") are
    # supposed to be not printable. The category "C" includes control
    # characters, format specifier and others.
    for c in str_val:
        if unicodedata.category(c)[0] == 'C':
            return False

    return True

def get_ldif_for_editor(samdb, msg):

    # Copy the given message, because we do not
    # want to modify the original message.
    m = ldb.Message()
    m.dn = msg.dn

    for k in msg.keys():
        if k == "dn":
            continue
        vals = msg[k]
        m[k] = vals
        need_base64 = False
        for v in vals:
            if is_printable_attr_val(v):
                continue
            need_base64 = True
            break
        if not need_base64:
            m[k].set_flags(ldb.FLAG_FORCE_NO_BASE64_LDIF)

    result_ldif = samdb.write_ldif(m, ldb.CHANGETYPE_NONE)

    return result_ldif

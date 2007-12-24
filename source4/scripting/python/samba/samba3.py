#!/usr/bin/python

# Unix SMB/CIFS implementation.
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

"""Support for reading Samba 3 data files."""

REGISTRY_VALUE_PREFIX = "SAMBA_REGVAL"
REGISTRY_DB_VERSION = 1

import os
import tdb

class Registry:
    """Simple read-only support for reading the Samba3 registry."""
    def __init__(self, file):
        self.tdb = tdb.Tdb(file, flags=os.O_RDONLY)

    def close(self):
        self.tdb.close()

    def __len__(self):
        """Return the number of keys."""
        return len(self.keys())

    def keys(self):
        """Return list with all the keys."""
        return [k.rstrip("\x00") for k in self.tdb.keys() if not k.startswith(REGISTRY_VALUE_PREFIX)]

    def subkeys(self, key):
        data = self.tdb.get("%s\x00" % key)
        if data is None:
            return []
        # FIXME: Parse data
        return []

    def values(self, key):
        """Return a dictionary with the values set for a specific key."""
        data = self.tdb.get("%s/%s\x00" % (REGISTRY_VALUE_PREFIX, key))
        if data is None:
            return {}
        # FIXME: Parse data
        return {}


class PolicyDatabase:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file, flags=os.O_RDONLY)
        self.min_password_length = self.tdb.fetch_uint32("min password length\x00")
        self.password_history = self.tdb.fetch_uint32("password history\x00")
        self.user_must_logon_to_change_password = self.tdb.fetch_uint32("user must logon to change pasword\x00")
        self.maximum_password_age = self.tdb.fetch_uint32("maximum password age\x00")
        self.minimum_password_age = self.tdb.fetch_uint32("minimum password age\x00")
        self.lockout_duration = self.tdb.fetch_uint32("lockout duration\x00")
        self.reset_count_minutes = self.tdb.fetch_uint32("reset count minutes\x00")
        self.bad_lockout_minutes = self.tdb.fetch_uint32("bad lockout minutes\x00")
        self.disconnect_time = self.tdb.fetch_int32("disconnect time\x00")
        self.refuse_machine_password_change = self.tdb.fetch_uint32("refuse machine password change\x00")

        # FIXME: Read privileges as well

    def close(self):
        self.tdb.close()


GROUPDB_DATABASE_VERSION_V1 = 1 # native byte format.
GROUPDB_DATABASE_VERSION_V2 = 2 # le format.

GROUP_PREFIX = "UNIXGROUP/"

# Alias memberships are stored reverse, as memberships. The performance
# critical operation is to determine the aliases a SID is member of, not
# listing alias members. So we store a list of alias SIDs a SID is member of
# hanging of the member as key.
MEMBEROF_PREFIX = "MEMBEROF/"

class GroupMappingDatabase:
    def __init__(self, file): 
        self.tdb = tdb.Tdb(file, flags=os.O_RDONLY)
        assert self.tdb.fetch_int32("INFO/version\x00") in (GROUPDB_DATABASE_VERSION_V1, GROUPDB_DATABASE_VERSION_V2)

    def groupsids(self):
        for k in self.tdb.keys():
            if k.startswith(GROUP_PREFIX):
                yield k[len(GROUP_PREFIX):].rstrip("\0")

    def aliases(self):
        for k in self.tdb.keys():
            if k.startswith(MEMBEROF_PREFIX):
                yield k[len(MEMBEROF_PREFIX):].rstrip("\0")

    def close(self):
        self.tdb.close()


# High water mark keys
IDMAP_HWM_GROUP = "GROUP HWM\0"
IDMAP_HWM_USER = "USER HWM\0"

IDMAP_GROUP_PREFIX = "GID "
IDMAP_USER_PREFIX = "UID "

# idmap version determines auto-conversion
IDMAP_VERSION_V2 = 2

class IdmapDatabase:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file, flags=os.O_RDONLY)
        assert self.tdb.fetch_int32("IDMAP_VERSION\0") == IDMAP_VERSION_V2

    def uids(self):
        for k in self.tdb.keys():
            if k.startswith(IDMAP_USER_PREFIX):
                yield int(k[len(IDMAP_USER_PREFIX):].rstrip("\0"))

    def gids(self):
        for k in self.tdb.keys():
            if k.startswith(IDMAP_GROUP_PREFIX):
                yield int(k[len(IDMAP_GROUP_PREFIX):].rstrip("\0"))

    def get_user_sid(self, uid):
        data = self.tdb.get("%s%d\0" % (IDMAP_USER_PREFIX, uid))
        if data is None:
            return data
        return data.rstrip("\0")

    def get_group_sid(self, gid):
        data = self.tdb.get("%s%d\0" % (IDMAP_GROUP_PREFIX, gid))
        if data is None:
            return data
        return data.rstrip("\0")

    def get_user_hwm(self):
        return self.tdb.fetch_uint32(IDMAP_HWM_USER)

    def get_group_hwm(self):
        return self.tdb.fetch_uint32(IDMAP_HWM_GROUP)

    def close(self):
        self.tdb.close()


class SecretsDatabase:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file, flags=os.O_RDONLY)

    def get_auth_password(self):
        return self.tdb.get("SECRETS/AUTH_PASSWORD")

    def get_auth_domain(self):
        return self.tdb.get("SECRETS/AUTH_DOMAIN")

    def get_auth_user(self):
        return self.tdb.get("SECRETS/AUTH_USER")

    def get_dom_guid(self, host):
        return self.tdb.get("SECRETS/DOMGUID/%s" % host)

    def ldap_dns(self):
        for k in self.tdb.keys():
            if k.startswith("SECRETS/LDAP_BIND_PW/"):
                yield k[len("SECRETS/LDAP_BIND_PW/"):].rstrip("\0")

    def domains(self):
        for k in self.tdb.keys():
            if k.startswith("SECRETS/SID/"):
                yield k[len("SECRETS/SID/"):].rstrip("\0")

    def get_ldap_bind_pw(self, host):
        return self.tdb.get("SECRETS/LDAP_BIND_PW/%s" % host)
    
    def get_afs_keyfile(self, host):
        return self.tdb.get("SECRETS/AFS_KEYFILE/%s" % host)

    def get_machine_sec_channel_type(self, host):
        return self.tdb.fetch_uint32("SECRETS/MACHINE_SEC_CHANNEL_TYPE/%s" % host)

    def get_machine_last_change_time(self, host):
        return self.tdb.fetch_uint32("SECRETS/MACHINE_LAST_CHANGE_TIME/%s" % host)
            
    def get_machine_password(self, host):
        return self.tdb.get("SECRETS/MACHINE_PASSWORD/%s" % host)

    def get_machine_acc(self, host):
        return self.tdb.get("SECRETS/$MACHINE.ACC/%s" % host)

    def get_domtrust_acc(self, host):
        return self.tdb.get("SECRETS/$DOMTRUST.ACC/%s" % host)

    def trusted_domains(self):
        for k in self.tdb.keys():
            if k.startswith("SECRETS/$DOMTRUST.ACC/"):
                yield k[len("SECRETS/$DOMTRUST.ACC/"):].rstrip("\0")

    def get_random_seed(self):
        return self.tdb.get("INFO/random_seed")

    def get_sid(self, host):
        return self.tdb.get("SECRETS/SID/%s" % host.upper())

    def close(self):
        self.tdb.close()


SHARE_DATABASE_VERSION_V1 = 1
SHARE_DATABASE_VERSION_V2 = 2

class ShareInfoDatabase:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file, flags=os.O_RDONLY)
        assert self.tdb.fetch_int32("INFO/version") in (SHARE_DATABASE_VERSION_V1, SHARE_DATABASE_VERSION_V2)

    def get_secdesc(self, name):
        secdesc = self.tdb.get("SECDESC/%s" % name)
        # FIXME: Run ndr_pull_security_descriptor
        return secdesc

    def close(self):
        self.tdb.close()

ACB_DISABLED = 0x00000001
ACB_HOMDIRREQ = 0x00000002
ACB_PWNOTREQ = 0x00000004
ACB_TEMPDUP = 0x00000008
ACB_NORMAL = 0x00000010
ACB_MNS = 0x00000020
ACB_DOMTRUST = 0x00000040
ACB_WSTRUST = 0x00000080
ACB_SVRTRUST = 0x00000100
ACB_PWNOEXP = 0x00000200
ACB_AUTOLOCK = 0x00000400
ACB_ENC_TXT_PWD_ALLOWED = 0x00000800
ACB_SMARTCARD_REQUIRED = 0x00001000
ACB_TRUSTED_FOR_DELEGATION = 0x00002000
ACB_NOT_DELEGATED = 0x00004000
ACB_USE_DES_KEY_ONLY = 0x00008000
ACB_DONT_REQUIRE_PREAUTH = 0x00010000
ACB_PW_EXPIRED = 0x00020000
ACB_NO_AUTH_DATA_REQD = 0x00080000

acb_info_mapping = {
        'N': ACB_PWNOTREQ,  # 'N'o password. 
        'D': ACB_DISABLED,  # 'D'isabled.
		'H': ACB_HOMDIRREQ, # 'H'omedir required.
		'T': ACB_TEMPDUP,   # 'T'emp account.
		'U': ACB_NORMAL,    # 'U'ser account (normal).
		'M': ACB_MNS,       # 'M'NS logon user account. What is this ?
		'W': ACB_WSTRUST,   # 'W'orkstation account.
		'S': ACB_SVRTRUST,  # 'S'erver account. 
		'L': ACB_AUTOLOCK,  # 'L'ocked account.
		'X': ACB_PWNOEXP,   # No 'X'piry on password
		'I': ACB_DOMTRUST,  # 'I'nterdomain trust account.
        ' ': 0
        }

def decode_acb(text):
    assert not "[" in text and not "]" in text
    ret = 0
    for x in text:
        ret |= acb_info_mapping[x]
    return ret


class SmbpasswdFile:
    def __init__(self, file):
        self.users = {}
        f = open(file, 'r')
        for l in f.readlines():
            if len(l) == 0 or l[0] == "#":
                continue # Skip comments and blank lines
            parts = l.split(":")
            username = parts[0]
            uid = int(parts[1])
            acct_ctrl = 0
            last_change_time = None
            if parts[2] == "NO PASSWORD":
                acct_ctrl |= ACB_PWNOTREQ
                lm_password = None
            elif parts[2][0] in ("*", "X"):
                # No password set
                lm_password = None
            else:
                lm_password = parts[2]

            if parts[3][0] in ("*", "X"):
                # No password set
                nt_password = None
            else:
                nt_password = parts[3]

            if parts[4][0] == '[':
                assert "]" in parts[4]
                acct_ctrl |= decode_acb(parts[4][1:-1])
                if parts[5].startswith("LCT-"):
                    last_change_time = int(parts[5][len("LCT-"):], 16)
            else: # old style file
                if username[-1] == "$":
                    acct_ctrl &= ~ACB_NORMAL
                    acct_ctrl |= ACB_WSTRUST

            self.users[username] = (uid, lm_password, nt_password, acct_ctrl, last_change_time)

        f.close()

    def __len__(self):
        return len(self.users)

    def __getitem__(self, name):
        return self.users[name]

    def __iter__(self):
        return iter(self.entries)

    def close(self): # For consistency
        pass


TDBSAM_FORMAT_STRING_V0 = "ddddddBBBBBBBBBBBBddBBwdwdBwwd"
TDBSAM_FORMAT_STRING_V1 = "dddddddBBBBBBBBBBBBddBBwdwdBwwd"
TDBSAM_FORMAT_STRING_V2 = "dddddddBBBBBBBBBBBBddBBBwwdBwwd"
TDBSAM_USER_PREFIX = "USER_"


class TdbSam:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file, flags=os.O_RDONLY)
        self.version = self.tdb.fetch_uint32("INFO/version") or 0
        assert self.version in (0, 1, 2)

    def usernames(self):
        for k in self.tdb.keys():
            if k.startswith(TDBSAM_USER_PREFIX):
                yield k[len(TDBSAM_USER_PREFIX):].rstrip("\0")

    def close(self):
        self.tdb.close()


def shellsplit(text):
    """Very simple shell-like line splitting.
    
    :param text: Text to split.
    :return: List with parts of the line as strings.
    """
    ret = list()
    inquotes = False
    current = ""
    for c in text:
        if c == "\"":
            inquotes = not inquotes
        elif c in ("\t", "\n", " ") and not inquotes:
            ret.append(current)
            current = ""
        else:
            current += c
    if current != "":
        ret.append(current)
    return ret


class WinsDatabase:
    def __init__(self, file):
        self.entries = {}
        f = open(file, 'r')
        assert f.readline().rstrip("\n") == "VERSION 1 0"
        for l in f.readlines():
            if l[0] == "#": # skip comments
                continue
            entries = shellsplit(l.rstrip("\n"))
            name = entries[0]
            ttl = int(entries[1])
            i = 2
            ips = []
            while "." in entries[i]:
                ips.append(entries[i])
                i+=1
            nb_flags = entries[i]
            assert not name in self.entries, "Name %s exists twice" % name
            self.entries[name] = (ttl, ips, nb_flags)
        f.close()

    def __getitem__(self, name):
        return self.entries[name]

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def close(self): # for consistency
        pass

class Samba3:
    def __init__(self, libdir, smbconfpath):
        self.smbconfpath = smbconfpath
        self.libdir = libdir

    def get_policy_db(self):
        return PolicyDatabase(os.path.join(self.libdir, "account_policy.tdb"))
    
    def get_registry(self):
        return Registry(os.path.join(self.libdir, "registry.tdb"))

    def get_secrets_db(self):
        return SecretsDatabase(os.path.join(self.libdir, "secrets.tdb"))

    def get_shares_db(self):
        return ShareInfoDatabase(os.path.join(self.libdir, "share_info.tdb"))

    def get_idmap_db(self):
        return IdmapDatabase(os.path.join(self.libdir, "winbindd_idmap.tdb"))

    def get_wins_db(self):
        return WinsDatabase(os.path.join(self.libdir, "wins.dat"))

    def get_groupmapping_db(self):
        return GroupMappingDatabase(os.path.join(self.libdir, "group_mapping.tdb"))

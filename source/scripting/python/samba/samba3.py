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

import tdb

class Registry:
    """Simple read-only support for reading the Samba3 registry."""
    def __init__(self, file):
        self.tdb = tdb.Tdb(file)

    def __len__(self):
        """Return the number of keys."""
        return len(self.keys())

    def keys(self):
        """Return list with all the keys."""
        return [k.rstrip("\x00") for k in self.tdb.keys() if not k.startswith(REGISTRY_VALUE_PREFIX)]

    def subkeys(self, key):
        data = self.tdb.get(key)
        if data is None:
            return []
        # FIXME: Parse data
        return []

    def values(self, key):
        """Return a dictionary with the values set for a specific key."""
        data = self.tdb.get("%s/%s" % (REGISTRY_VALUE_PREFIX, key))
        if data is None:
            return {}
        # FIXME: Parse data
        return {}


class PolicyDatabase:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file)
        self.min_password_length = tdb.fetch_uint32("min password length")
        self.user_must_logon_to_change_password = tdb.fetch_uint32("password history")
        self.user_must_logon_to_change_password = tdb.fetch_uint32("user must logon to change pasword")
        self.maximum_password_age = tdb.fetch_uint32("maximum password age")
        self.minimum_password_age = tdb.fetch_uint32("minimum password age")
        self.lockout_duration = tdb.fetch_uint32("lockout duration")
        self.reset_count_minutes = tdb.fetch_uint32("reset count minutes")
        self.bad_lockout_minutes = tdb.fetch_uint32("bad lockout minutes")
        self.disconnect_time = tdb.fetch_uint32("disconnect time")
        self.refuse_machine_password_change = tdb.fetch_uint32("refuse machine password change")

        # FIXME: Read privileges as well


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
        self.tdb = tdb.Tdb(file)


# High water mark keys
HWM_GROUP = "GROUP HWM"
HWM_USER = "USER HWM"

# idmap version determines auto-conversion
IDMAP_VERSION = 2

class IdmapDatabase:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file)
        assert self.tdb.fetch_int32("IDMAP_VERSION") == IDMAP_VERSION


class SecretsDatabase:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file)
        self.domains = {}
        for k, v in self.tdb.items():
            if k == "SECRETS/AUTH_PASSWORD":
                self.auth_password = v
            elif k == "SECRETS/AUTH_DOMAIN":
                self.auth_domain = v
            elif k == "SECRETS/AUTH_USER":
                self.auth_user = v
            elif k.startswith("SECRETS/SID/"):
                pass # FIXME
            elif k.startswith("SECRETS/DOMGUID/"):
                pass # FIXME
            elif k.startswith("SECRETS/LDAP_BIND_PW/"):
                pass # FIXME
            elif k.startswith("SECRETS/AFS_KEYFILE/"):
                pass # FIXME
            elif k.startswith("SECRETS/MACHINE_SEC_CHANNEL_TYPE/"):
                pass # FIXME
            elif k.startswith("SECRETS/MACHINE_LAST_CHANGE_TIME/"):
                pass # FIXME
            elif k.startswith("SECRETS/MACHINE_PASSWORD/"):
                pass # FIXME
            elif k.startswith("SECRETS/$MACHINE.ACC/"):
                pass # FIXME
            elif k.startswith("SECRETS/$DOMTRUST.ACC/"):
                pass # FIXME
            elif k == "INFO/random_seed":
                self.random_seed = v
            else:
                raise "Unknown key %s in secrets database" % k

SHARE_DATABASE_VERSION_V1 = 1
SHARE_DATABASE_VERSION_V2 = 2

class ShareInfoDatabase:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file)
        assert self.tdb.fetch_int32("INFO/version") in (SHARE_DATABASE_VERSION_V1, SHARE_DATABASE_VERSION_V2)

    def get_secdesc(self, name):
        secdesc = self.tdb.get("SECDESC/%s" % name)
        # FIXME: Run ndr_pull_security_descriptor


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


class Smbpasswd:
    def __init__(self, file):
        pass


class TdbSam:
    def __init__(self, file):
        self.tdb = tdb.Tdb(file)


class WinsDatabase:
    def __init__(self, file):
        pass


class Samba3:
    def __init__(self, smbconfpath, libdir):
        self.smbconfpath = smbconfpath
        self.libdir = libdir

    def get_policy_db(self):
        return PolicyDatabase(os.path.join(libdir, "account_policy.tdb"))
    
    def get_registry(self):
        return Registry(os.path.join(libdir, "registry.tdb"))

    def get_secrets_db(self):
        return SecretsDatabase(os.path.join(libdir, "secrets.tdb"))

    def get_shares_db(self):
        return ShareInfoDatabase(os.path.join(libdir, "share_info.tdb"))

    def get_idmap_db(self):
        return IdmapDatabase(os.path.join(libdir, "winbindd_idmap.tdb"))

    def get_wins_db(self):
        return WinsDatabase(os.path.join(libdir, "wins.dat"))

    def get_groupmapping_db(self):
        return GroupMappingDatabase(os.path.join(libdir, "group_mapping.tdb"))

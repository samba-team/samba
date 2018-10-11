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

__docformat__ = "restructuredText"

REGISTRY_VALUE_PREFIX = b"SAMBA_REGVAL"
REGISTRY_DB_VERSION = 1

import os
import struct
import tdb

from samba.samba3 import passdb
from samba.samba3 import param as s3param
from samba.compat import get_bytes

def fetch_uint32(db, key):
    try:
        data = db[key]
    except KeyError:
        return None
    assert len(data) == 4
    return struct.unpack("<L", data)[0]


def fetch_int32(db, key):
    try:
        data = db[key]
    except KeyError:
        return None
    assert len(data) == 4
    return struct.unpack("<l", data)[0]


class DbDatabase(object):
    """Simple Samba 3 TDB database reader."""
    def __init__(self, file):
        """Open a file.

        :param file: Path of the file to open, appending .tdb or .ntdb.
        """
        self.db = tdb.Tdb(file + ".tdb", flags=os.O_RDONLY)
        self._check_version()

    def _check_version(self):
        pass

    def close(self):
        """Close resources associated with this object."""
        self.db.close()


class Registry(DbDatabase):
    """Simple read-only support for reading the Samba3 registry.

    :note: This object uses the same syntax for registry key paths as
        Samba 3. This particular format uses forward slashes for key path
        separators and abbreviations for the predefined key names.
        e.g.: HKLM/Software/Bar.
    """
    def __len__(self):
        """Return the number of keys."""
        return len(self.keys())

    def keys(self):
        """Return list with all the keys."""
        return [k.rstrip(b"\x00") for k in self.db if not k.startswith(REGISTRY_VALUE_PREFIX)]

    def subkeys(self, key):
        """Retrieve the subkeys for the specified key.

        :param key: Key path.
        :return: list with key names
        """
        data = self.db.get(key + b"\x00")
        if data is None:
            return []
        (num, ) = struct.unpack("<L", data[0:4])
        keys = data[4:].split(b"\0")
        assert keys[-1] == b""
        keys.pop()
        assert len(keys) == num
        return keys

    def values(self, key):
        """Return a dictionary with the values set for a specific key.

        :param key: Key to retrieve values for.
        :return: Dictionary with value names as key, tuple with type and
            data as value."""
        data = self.db.get(REGISTRY_VALUE_PREFIX + b'/' + key + b'\x00')
        if data is None:
            return {}
        ret = {}
        (num, ) = struct.unpack("<L", data[0:4])
        data = data[4:]
        for i in range(num):
            # Value name
            (name, data) = data.split(b"\0", 1)

            (type, ) = struct.unpack("<L", data[0:4])
            data = data[4:]
            (value_len, ) = struct.unpack("<L", data[0:4])
            data = data[4:]

            ret[name] = (type, data[:value_len])
            data = data[value_len:]

        return ret


# High water mark keys
IDMAP_HWM_GROUP = b"GROUP HWM\0"
IDMAP_HWM_USER = b"USER HWM\0"

IDMAP_GROUP_PREFIX = b"GID "
IDMAP_USER_PREFIX = b"UID "

# idmap version determines auto-conversion
IDMAP_VERSION_V2 = 2


class IdmapDatabase(DbDatabase):
    """Samba 3 ID map database reader."""

    def _check_version(self):
        assert fetch_int32(self.db, b"IDMAP_VERSION\0") == IDMAP_VERSION_V2

    def ids(self):
        """Retrieve a list of all ids in this database."""
        for k in self.db:
            if k.startswith(IDMAP_USER_PREFIX):
                yield k.rstrip(b"\0").split(b" ")
            if k.startswith(IDMAP_GROUP_PREFIX):
                yield k.rstrip(b"\0").split(b" ")

    def uids(self):
        """Retrieve a list of all uids in this database."""
        for k in self.db:
            if k.startswith(IDMAP_USER_PREFIX):
                yield int(k[len(IDMAP_USER_PREFIX):].rstrip(b"\0"))

    def gids(self):
        """Retrieve a list of all gids in this database."""
        for k in self.db:
            if k.startswith(IDMAP_GROUP_PREFIX):
                yield int(k[len(IDMAP_GROUP_PREFIX):].rstrip(b"\0"))

    def get_sid(self, xid, id_type):
        """Retrive SID associated with a particular id and type.

        :param xid: UID or GID to retrieve SID for.
        :param id_type: Type of id specified - 'UID' or 'GID'
        """
        data = self.db.get(get_bytes("%s %s\0" % (id_type, str(xid))))
        if data is None:
            return data
        return data.rstrip("\0")

    def get_user_sid(self, uid):
        """Retrieve the SID associated with a particular uid.

        :param uid: UID to retrieve SID for.
        :return: A SID or None if no mapping was found.
        """
        data = self.db.get(IDMAP_USER_PREFIX + str(uid).encode() + b'\0')
        if data is None:
            return data
        return data.rstrip(b"\0")

    def get_group_sid(self, gid):
        data = self.db.get(IDMAP_GROUP_PREFIX + str(gid).encode() + b'\0')
        if data is None:
            return data
        return data.rstrip(b"\0")

    def get_user_hwm(self):
        """Obtain the user high-water mark."""
        return fetch_uint32(self.db, IDMAP_HWM_USER)

    def get_group_hwm(self):
        """Obtain the group high-water mark."""
        return fetch_uint32(self.db, IDMAP_HWM_GROUP)


class SecretsDatabase(DbDatabase):
    """Samba 3 Secrets database reader."""

    def get_auth_password(self):
        return self.db.get(b"SECRETS/AUTH_PASSWORD")

    def get_auth_domain(self):
        return self.db.get(b"SECRETS/AUTH_DOMAIN")

    def get_auth_user(self):
        return self.db.get(b"SECRETS/AUTH_USER")

    def get_domain_guid(self, host):
        return self.db.get(b"SECRETS/DOMGUID/%s" % host)

    def ldap_dns(self):
        for k in self.db:
            if k.startswith("SECRETS/LDAP_BIND_PW/"):
                yield k[len("SECRETS/LDAP_BIND_PW/"):].rstrip("\0")

    def domains(self):
        """Iterate over domains in this database.

        :return: Iterator over the names of domains in this database.
        """
        for k in self.db:
            if k.startswith("SECRETS/SID/"):
                yield k[len("SECRETS/SID/"):].rstrip("\0")

    def get_ldap_bind_pw(self, host):
        return self.db.get(get_bytes("SECRETS/LDAP_BIND_PW/%s" % host))

    def get_afs_keyfile(self, host):
        return self.db.get(get_bytes("SECRETS/AFS_KEYFILE/%s" % host))

    def get_machine_sec_channel_type(self, host):
        return fetch_uint32(self.db, get_bytes("SECRETS/MACHINE_SEC_CHANNEL_TYPE/%s" % host))

    def get_machine_last_change_time(self, host):
        return fetch_uint32(self.db, "SECRETS/MACHINE_LAST_CHANGE_TIME/%s" % host)

    def get_machine_password(self, host):
        return self.db.get(get_bytes("SECRETS/MACHINE_PASSWORD/%s" % host))

    def get_machine_acc(self, host):
        return self.db.get(get_bytes("SECRETS/$MACHINE.ACC/%s" % host))

    def get_domtrust_acc(self, host):
        return self.db.get(get_bytes("SECRETS/$DOMTRUST.ACC/%s" % host))

    def trusted_domains(self):
        for k in self.db:
            if k.startswith("SECRETS/$DOMTRUST.ACC/"):
                yield k[len("SECRETS/$DOMTRUST.ACC/"):].rstrip("\0")

    def get_random_seed(self):
        return self.db.get(b"INFO/random_seed")

    def get_sid(self, host):
        return self.db.get(get_bytes("SECRETS/SID/%s" % host.upper()))


SHARE_DATABASE_VERSION_V1 = 1
SHARE_DATABASE_VERSION_V2 = 2


class ShareInfoDatabase(DbDatabase):
    """Samba 3 Share Info database reader."""

    def _check_version(self):
        assert fetch_int32(self.db, "INFO/version\0") in (SHARE_DATABASE_VERSION_V1, SHARE_DATABASE_VERSION_V2)

    def get_secdesc(self, name):
        """Obtain the security descriptor on a particular share.

        :param name: Name of the share
        """
        secdesc = self.db.get(get_bytes("SECDESC/%s" % name))
        # FIXME: Run ndr_pull_security_descriptor
        return secdesc


class Shares(object):
    """Container for share objects."""
    def __init__(self, lp, shareinfo):
        self.lp = lp
        self.shareinfo = shareinfo

    def __len__(self):
        """Number of shares."""
        return len(self.lp) - 1

    def __iter__(self):
        """Iterate over the share names."""
        return self.lp.__iter__()


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
            if current != "":
                ret.append(current)
            current = ""
        else:
            current += c
    if current != "":
        ret.append(current)
    return ret


class WinsDatabase(object):
    """Samba 3 WINS database reader."""
    def __init__(self, file):
        self.entries = {}
        f = open(file, 'r')
        assert f.readline().rstrip("\n") == "VERSION 1 0"
        for l in f.readlines():
            if l[0] == "#":  # skip comments
                continue
            entries = shellsplit(l.rstrip("\n"))
            name = entries[0]
            ttl = int(entries[1])
            i = 2
            ips = []
            while "." in entries[i]:
                ips.append(entries[i])
                i += 1
            nb_flags = int(entries[i][:-1], 16)
            assert name not in self.entries, "Name %s exists twice" % name
            self.entries[name] = (ttl, ips, nb_flags)
        f.close()

    def __getitem__(self, name):
        return self.entries[name]

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def items(self):
        """Return the entries in this WINS database."""
        return self.entries.items()

    def close(self):  # for consistency
        pass


class Samba3(object):
    """Samba 3 configuration and state data reader."""

    def __init__(self, smbconfpath, s3_lp_ctx=None):
        """Open the configuration and data for a Samba 3 installation.

        :param smbconfpath: Path to the smb.conf file.
        :param s3_lp_ctx: Samba3 Loadparm context
        """
        self.smbconfpath = smbconfpath
        if s3_lp_ctx:
            self.lp = s3_lp_ctx
        else:
            self.lp = s3param.get_context()
            self.lp.load(smbconfpath)

    def statedir_path(self, path):
        if path[0] == "/" or path[0] == ".":
            return path
        return os.path.join(self.lp.get("state directory"), path)

    def privatedir_path(self, path):
        if path[0] == "/" or path[0] == ".":
            return path
        return os.path.join(self.lp.get("private dir"), path)

    def get_conf(self):
        return self.lp

    def get_sam_db(self):
        return passdb.PDB(self.lp.get('passdb backend'))

    def get_registry(self):
        return Registry(self.statedir_path("registry"))

    def get_secrets_db(self):
        return SecretsDatabase(self.privatedir_path("secrets"))

    def get_shareinfo_db(self):
        return ShareInfoDatabase(self.statedir_path("share_info"))

    def get_idmap_db(self):
        return IdmapDatabase(self.statedir_path("winbindd_idmap"))

    def get_wins_db(self):
        return WinsDatabase(self.statedir_path("wins.dat"))

    def get_shares(self):
        return Shares(self.get_conf(), self.get_shareinfo_db())

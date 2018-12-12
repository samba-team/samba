#!/usr/bin/env python3

from __future__ import print_function
import sys
import os
import subprocess
from samba.compat import get_string


if len(sys.argv) != 3:
    print("Usage: test_wbinfo_sids2xids_int.py wbinfo net")
    sys.exit(1)

wbinfo = sys.argv[1]
netcmd = sys.argv[2]


def run(cmd):
    """
    Run a cmd, return bytes str for py2 and unicode str for py3.

    NOTE: subprocess api always return bytes, in both py2 and py3.
    """
    output = subprocess.check_output(cmd).strip()
    return get_string(output)


def flush_cache(sids=[], uids=[], gids=[]):
    for sid in sids:
        os.system(netcmd + (" cache del IDMAP/SID2XID/%s" % (sid)))
    for uids in uids:
        os.system(netcmd + (" cache del IDMAP/UID2SID/%s" % (uid)))
    for gids in gids:
        os.system(netcmd + (" cache del IDMAP/GID2SID/%s" % (gid)))


def fill_cache(inids, idtype='gid'):
    for inid in inids:
        if inid is None:
            continue
        run([wbinfo, '--%s-to-sid=%s' % (idtype, inid)])


domain = run([wbinfo, "--own-domain"])
domsid = run([wbinfo, "-n", domain + "/"])
domsid = domsid.split(' ')[0]

# print domain
# print domsid

sids = [domsid + '-512', 'S-1-5-32-545', domsid + '-513', 'S-1-1-0', 'S-1-3-1', 'S-1-5-1']

flush_cache(sids=sids)

sids2xids = run([wbinfo, '--sids-to-unix-ids=' + ','.join(sids)])

gids = []
uids = []
idtypes = []

for line in sids2xids.split('\n'):
    result = line.split(' ')[2:]
    idtypes.append(result[0])

    gid = None
    uid = None
    if result[0] == 'gid':
        gid = result[1]
    elif result[0] == 'uid':
        uid = result[1]
    elif result[0] == 'uid/gid':
        gid = result[1]
        uid = result[1]

    if gid == '-1':
        gid = ''
    gids.append(gid)

    if uid == '-1':
        uid = ''
    uids.append(uid)

# Check the list produced by the sids-to-xids call with the
# singular variant (sid-to-xid) for each sid in turn.


def check_singular(sids, ids, idtype='gid'):
    i = 0
    for sid in sids:
        if ids[i] is None:
            continue

        outid = run([wbinfo, '--sid-to-%s' % idtype, sid])
        if outid != ids[i]:
            print("Expected %s, got %s\n" % (outid, ids[i]))
            flush_cache(sids=sids, uids=uids, gids=gids)
            sys.exit(1)
        i += 1

# Check the list produced by the sids-to-xids call with the
# multiple variant (sid-to-xid) for each sid in turn.


def check_multiple(sids, idtypes):
    sids2xids = run([wbinfo, '--sids-to-unix-ids=' + ','.join(sids)])
    # print sids2xids
    i = 0
    for line in sids2xids.split('\n'):
        result = line.split(' ')[2:]

        if result[0] != idtypes[i]:
            print("Expected %s, got %s\n" % (idtypes[i], result[0]))
            flush_cache(sids=sids, uids=uids, gids=gids)
            sys.exit(1)
        i += 1


# first round: with filled cache via sid-to-id
check_singular(sids, gids, 'gid')
check_singular(sids, uids, 'uid')

# second round: with empty cache
flush_cache(sids=sids, gids=gids)
check_singular(sids, gids, 'gid')
flush_cache(sids=sids, uids=uids)
check_singular(sids, uids, 'uid')

# third round: with filled cache via uid-to-sid
flush_cache(sids=uids, uids=uids)
fill_cache(uids, 'uid')
check_multiple(sids, idtypes)

# fourth round: with filled cache via gid-to-sid
flush_cache(sids=sids, gids=gids)
fill_cache(gids, 'gid')
check_multiple(sids, idtypes)

# flush the cache so any incorrect mappings don't break other tests
flush_cache(sids=sids, uids=uids, gids=gids)

sys.exit(0)

#!/usr/bin/env python

import sys,os,subprocess


if len(sys.argv) != 3:
    print "Usage: test_wbinfo_sids2xids_int.py wbinfo net"
    sys.exit(1)

wbinfo = sys.argv[1]
netcmd = sys.argv[2]

def flush_cache():
    os.system(netcmd + "cache flush")

domain = subprocess.Popen([wbinfo, "--own-domain"],
                          stdout=subprocess.PIPE).communicate()[0].strip()
domsid = subprocess.Popen([wbinfo, "-n", domain + "/"],
                          stdout=subprocess.PIPE).communicate()[0]
domsid = domsid.split(' ')[0]

#print domain
#print domsid

sids=[ domsid + '-512', 'S-1-5-32-545', domsid + '-513' ]

flush_cache

sids2xids = subprocess.Popen([wbinfo, '--sids-to-unix-ids=' +  ','.join(sids)],
                             stdout=subprocess.PIPE).communicate()[0].strip()

gids=[]

for line in sids2xids.split('\n'):
    result = line.split(' ')[2:]

    if result[0] == 'gid' or result[0] == 'uid/gid':
        gid = result[1]
    else:
        gid = ''
    if gid == '-1':
        gid = ''
    gids.append(gid)

# Check the list produced by the sids-to-xids call with the
# singular variant (sid-to-gid) for each sid in turn.
def check_singular(sids, gids):
    i=0
    for sid in sids:
        gid = subprocess.Popen([wbinfo, '--sid-to-gid', sid],
                               stdout=subprocess.PIPE).communicate()[0].strip()
        if gid != gids[i]:
            print "Expected %s, got %s\n", gid, gids[i]
            sys.exit(1)
        i+=1

# first round: with filled cache
check_singular(sids, gids)

# second round: with empty cache
flush_cache
check_singular(sids, gids)

sys.exit(0)

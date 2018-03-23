#!/usr/bin/python


from __future__ import print_function
import optparse
import sys
import base64

sys.path.insert(0, "bin/python")

import samba.getopt as options
from samba.dcerpc import drsblobs, misc
from samba.ndr import ndr_pack, ndr_unpack
from samba import Ldb

parser = optparse.OptionParser("get-descriptor [options]")
sambaopts = options.SambaOptions(parser)
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)

parser.add_option("-b", type="string", metavar="BASE",
                  help="set base DN for the search")
parser.add_option("--host", type="string", metavar="HOST",
                  help="Ip of the host")

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

opts = parser.parse_args()[0]

def printdirsync(ctl):
        arr = ctl.split(':')
        if arr[0] == 'dirsync':
            print("Need to continue: %s" % arr[1])
            cookie = ndr_unpack(drsblobs.ldapControlDirSyncCookie, base64.b64decode(arr[3]))
            print("DC's NTDS guid: %s " % cookie.blob.guid1)
            print("highest usn %s" % cookie.blob.highwatermark.highest_usn)
            print("tmp higest usn %s" % cookie.blob.highwatermark.tmp_highest_usn)
            print("reserved usn %s" % cookie.blob.highwatermark.reserved_usn)
            if cookie.blob.extra_length >0:
                print("highest usn in extra %s" % cookie.blob.extra.ctr.cursors[0].highest_usn)
        return cookie

remote_ldb= Ldb("ldap://" + opts.host + ":389", credentials=creds, lp=lp)
tab = []
if opts.b:
    base = opts.b
else:
    base = None

guid = None
(msgs, ctrls) = remote_ldb.search(expression="(samaccountname=administrator)", base=base, attrs=["objectClass"], controls=["dirsync:1:1:50"])
if (len(ctrls)):
    for ctl in ctrls:
        arr = ctl.split(':')
        if arr[0] == 'dirsync':
            cookie = ndr_unpack(drsblobs.ldapControlDirSyncCookie, base64.b64decode(arr[3]))
            guid = cookie.blob.guid1
            pass
if not guid:
    print("No dirsync control ... strange")
    sys.exit(1)

print("")
print("Getting first guest without any cookie")
(msgs, ctrls) = remote_ldb.searchex(expression="(samaccountname=guest)", base=base, attrs=["objectClass"], controls=["dirsync:1:1:50"])
cookie = None
if (len(ctrls)):
    for ctl in ctrls:
        cookie = printdirsync(ctl)
    print("Returned %d entries" % len(msgs))

savedcookie = cookie

print("")
print("Getting allusers with cookie")
controls=["dirsync:1:1:50:%s" % base64.b64encode(ndr_pack(cookie))]
(msgs, ctrls) = remote_ldb.searchex(expression="(samaccountname=*)", base=base, attrs=["objectClass"], controls=controls)
if (len(ctrls)):
    for ctl in ctrls:
        cookie = printdirsync(ctl)
    print("Returned %d entries" % len(msgs))

cookie = savedcookie
cookie.blob.guid1 = misc.GUID("128a99bf-e2df-4832-ac0a-1fb625e530db")
if cookie.blob.extra_length > 0:
    cookie.blob.extra.ctr.cursors[0].source_dsa_invocation_id = misc.GUID("128a99bf-e2df-4832-ac0a-1fb625e530db")

print("")
print("Getting all the entries")
controls=["dirsync:1:1:50:%s" % base64.b64encode(ndr_pack(cookie))]
(msgs, ctrls) = remote_ldb.searchex(expression="(objectclass=*)", base=base, controls=controls)
cont = 0
if (len(ctrls)):
    for ctl in ctrls:
        cookie = printdirsync(ctl)
    if cookie != None:
        cont = (ctl.split(':'))[1]
    print("Returned %d entries" % len(msgs))

usn = cookie.blob.highwatermark.tmp_highest_usn
if cookie.blob.extra_length > 0:
    bigusn = cookie.blob.extra.ctr.cursors[0].highest_usn
else:
    bigusn  = usn + 1000
while (cont == "1"):
    print("")
    controls=["dirsync:1:1:50:%s" % base64.b64encode(ndr_pack(cookie))]
    (msgs, ctrls) = remote_ldb.searchex(expression="(objectclass=*)", base=base, controls=controls)
    if (len(ctrls)):
        for ctl in ctrls:
            cookie = printdirsync(ctl)
        if cookie != None:
            cont = (ctl.split(':'))[1]
        print("Returned %d entries" % len(msgs))

print("")
print("Getting with cookie but usn changed to %d we should use the one in extra" % (bigusn - 1))
cookie.blob.highwatermark.highest_usn = 0
cookie.blob.highwatermark.tmp_highest_usn = usn - 2
if cookie.blob.extra_length > 0:
    print("here")
    cookie.blob.extra.ctr.cursors[0].highest_usn = bigusn - 1
controls=["dirsync:1:1:50:%s" % base64.b64encode(ndr_pack(cookie))]
(msgs, ctrls) = remote_ldb.searchex(expression="(objectclass=*)", base=base, controls=controls)
if (len(ctrls)):
    for ctl in ctrls:
        cookie = printdirsync(ctl)
    print("Returned %d entries" % len(msgs))

print("")
print("Getting with cookie but usn %d changed and extra/cursor GUID too" % (usn - 2))
print(" so that it's (tmp)highest_usn that drives the limit")
cookie.blob.highwatermark.highest_usn = 0
cookie.blob.highwatermark.tmp_highest_usn = usn - 2
if cookie.blob.extra_length > 0:
    cookie.blob.extra.ctr.cursors[0].source_dsa_invocation_id = misc.GUID("128a99bf-e2df-4832-ac0a-1fb625e530db")
    cookie.blob.extra.ctr.cursors[0].highest_usn = bigusn - 1
controls=["dirsync:1:1:50:%s" % base64.b64encode(ndr_pack(cookie))]
(msgs, ctrls) = remote_ldb.searchex(expression="(objectclass=*)", base=base, controls=controls)
if (len(ctrls)):
    for ctl in ctrls:
        cookie = printdirsync(ctl)
    print("Returned %d entries" % len(msgs))

print("")
print("Getting with cookie but usn changed to %d" % (usn - 2))
cookie.blob.highwatermark.highest_usn = 0
cookie.blob.highwatermark.tmp_highest_usn = (usn - 2)
if cookie.blob.extra_length > 0:
    cookie.blob.extra.ctr.cursors[0].highest_usn = (usn - 2)
controls=["dirsync:1:1:50:%s" % base64.b64encode(ndr_pack(cookie))]
(msgs, ctrls) = remote_ldb.searchex(expression="(objectclass=*)", base=base, controls=controls)
if (len(ctrls)):
    for ctl in ctrls:
        cookie = printdirsync(ctl)
    print("Returned %d entries" % len(msgs))

#!/usr/bin/python

# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Tridgell 2009
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

"""Tests the possibleInferiors generation in the schema_fsmo ldb module"""

import optparse
import sys


# Find right directory when running from source tree
sys.path.insert(0, "bin/python")

import samba
from samba import getopt as options, Ldb
import ldb

parser = optparse.OptionParser("possibleinferiors.py <URL> [<CLASS>]")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
parser.add_option_group(options.VersionOptions(parser))

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

url = args[0]
if (len(args) > 1):
    objectclass = args[1]
else:
    objectclass = None

def uniq_list(alist):
    """return a unique list"""
    set = {}
    return [set.setdefault(e,e) for e in alist if e not in set]


lp_ctx = sambaopts.get_loadparm()

creds = credopts.get_credentials(lp_ctx)
db = Ldb(url, credentials=creds, lp=lp_ctx, options=["modules:paged_searches"])

# get the rootDSE
res = db.search(base="", expression="",
                scope=ldb.SCOPE_BASE,
                attrs=["schemaNamingContext"])
rootDse = res[0]

schema_base = rootDse["schemaNamingContext"][0]

def possible_inferiors_search(db, oc):
    """return the possible inferiors via a search for the possibleInferiors attribute"""
    res = db.search(base=schema_base,
                    expression=("ldapdisplayname=%s" % oc),
                    attrs=["possibleInferiors"])

    poss=[]
    if len(res) == 0 or res[0].get("possibleInferiors") is None:
        return poss
    for item in res[0]["possibleInferiors"]:
        poss.append(str(item))
    poss = uniq_list(poss)
    poss.sort()
    return poss;



# see [MS-ADTS] section 3.1.1.4.5.21
# for this algorithm

# !systemOnly=TRUE
# !objectClassCategory=2
# !objectClassCategory=3

def POSSINFERIORS(db, oc):
    """returns a list of possible inferiors to a class. Returned list has the ldapdisplayname, systemOnly and objectClassCategory for each element"""
    expanded = [oc]
    res = db.search(base=schema_base,
                    expression=("subclassof=%s" % str(oc["ldapdisplayname"][0])),
                    attrs=["ldapdisplayname", "systemOnly", "objectClassCategory"])
    for r in res:
        expanded.extend(POSSINFERIORS(db,r))
    return expanded

def possible_inferiors_constructed(db, oc):
    """return the possbible inferiors via a recursive search and match"""
    res = db.search(base=schema_base,
                    expression=("(&(objectclass=classSchema)(|(posssuperiors=%s)(systemposssuperiors=%s)))" % (oc,oc)),
                    attrs=["ldapdisplayname", "systemOnly", "objectClassCategory"])

    poss = []
    for r in res:
        poss.extend(POSSINFERIORS(db,r))
        
    poss2 = []
    for p in poss:
        if (not (p["systemOnly"][0] == "TRUE" or
                 int(p["objectClassCategory"][0]) == 2 or
                 int(p["objectClassCategory"][0]) == 3)):
            poss2.append(p["ldapdisplayname"][0])
            
    poss2 = uniq_list(poss2)
    poss2.sort()
    return poss2

def test_class(db, oc):
    """test to see if one objectclass returns the correct possibleInferiors"""
    poss1 = possible_inferiors_search(db, oc)
    poss2 = possible_inferiors_constructed(db, oc)
    if poss1 != poss2:
        print "Returned incorrect list for objectclass %s" % oc
        print poss1
        print poss2
        for i in range(0,min(len(poss1),len(poss2))):
            print "%30s %30s" % (poss1[i], poss2[i])
        exit(1)

def get_object_classes(db):
    """return a list of all object classes"""
    res = db.search(base=schema_base,
                    expression="objectClass=classSchema",
                    attrs=["ldapdisplayname"])
    list=[]
    for item in res:
        list.append(item["ldapdisplayname"][0])
    return list

if objectclass is None:
    for oc in get_object_classes(db):
        print "testing objectClass %s" % oc
        test_class(db,oc)
else:
    test_class(db,objectclass)

print "Lists match OK"

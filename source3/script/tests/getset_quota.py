#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Tests for smbcquotas
# Copyright (C) Noel Power 2017

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import traceback
import logging
import os

USER_QUOTAS = 1
USER_DEFAULT_QUOTAS = 2
GROUP_QUOTAS = 3
GROUP_DEFAULT_QUOTAS = 4

#Quota model

class Quota:
    def __init__(self):
        self.flags = 0
        self.quotatype = USER_DEFAULT_QUOTAS
        self.uid = 0
        self.usedblocks = 0
        self.softlimit = 0
        self.hardlimit = 0
        self.hardlimit = 0
        self.usedinodes = 0
        self.slimitinodes = 0
        self.hlimitinodes = 0

def quota_to_str(item):
    result = str(item.flags) + " " + str(item.usedblocks) + " " + str(item.softlimit) + " " + str(item.hardlimit) + " " + str(item.usedinodes) + " " + str(item.slimitinodes) + " " + str(item.hlimitinodes)
    return result

def quota_to_db_str(item):
    result = item.uid + " " + str(item.usedblocks) + " " + str(item.softlimit) + " " + str(item.hardlimit) + " " + str(item.usedinodes) + " " + str(item.slimitinodes) + " " + str(item.hlimitinodes)
    return result

def load_quotas(input_file):
    fileContents = open(input_file,"r")
    lineno = 0
    quotas = []
    for line in fileContents:
        if line.strip().startswith("#"):
            continue
        content = line.strip().split()
        quota = Quota()
        if len(content) < 7:
            logging.debug("ignoring line %d, doesn't have enough fields\n"%lineno)
        else:
            quota.flags = 2
            quota.uid = content[0]
            quota.usedblocks = content[1]
            quota.softlimit = content[2]
            quota.hardlimit = content[3]
            quota.usedinodes = content[4]
            quota.slimitinodes = content[5]
            quota.hlimitinodes = content[6]
            quotas.append(quota)

    fileContents.close()
    return quotas

def set_quotas(quota_list, output_file):
    filecontents = open(output_file,"w+")
    if filecontents == None:
        return False;
    lines = ""
    for quota in quota_list:
        next_line = quota_to_db_str(quota)
        if next_line:
            lines = lines + next_line + "\n"
    filecontents.write(lines)
    filecontents.close()
    return True

def get_quotas(uid, quota_list):
    logging.debug("in get_quotas\n")
    for quota in quota_list:
        if quota.uid == uid:
            return quota
    return None

def main():
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
    logging.debug("system args passed are %s\n"% str(sys.argv))
    quota_file_dir = os.path.dirname(sys.argv[0]);
    quota_file_db = os.path.join(quota_file_dir,"quotas.db")
    logging.debug("quota db is located %s\n", quota_file_db)
    quota_list = load_quotas(quota_file_db)
    logging.debug("quotas loaded have %s entries\n", len(quota_list))
    result = None
    if len(sys.argv) == 4:
        # Get Quota
        directory = sys.argv[1]
        if sys.argv[2] == "1":
            query_type = USER_QUOTAS
        elif sys.argv[2] == "2":
            query_type = USER_DEFAULT_QUOTAS
        elif sys.argv[2] == "3":
            query_type = GROUP_QUOTAS
        elif sys.argv[2] == "4":
            query_type = GROUP_DEFAULT_QUOTAS
        uid = sys.argv[3]
        quota = get_quotas(uid, quota_list)
        if quota is None:
            logging.debug("no result for uid %s"%uid)
        else:
            result = quota_to_str(quota)
            logging.debug("got result for uid %s\n"%uid);
        if result is None:
            result = "0 0 0 0 0 0 0"
        logging.debug("for uid %s returning quotas %s\n"%(uid,result))
        print("%s"%result)
    elif len(sys.argv) > 8:
        # Set Quota
        quota = Quota()
        directory = sys.argv[1]
        quota.query_type = sys.argv[2]
        quota.uid = sys.argv[3]
        quota.flags = sys.argv[4]
        quota.softlimit = sys.argv[5]
        quota.hardlimit = sys.argv[6]
        quota.slimitinodes = sys.argv[7]
        quota.hlimitinodes = sys.argv[8]
        found = get_quotas(quota.uid, quota_list)
        if found:
            found.query_type = quota.query_type
            found.uid = quota.uid
            found.flags = quota.flags
            found.softlimit = quota.softlimit
            found.hardlimit = quota.hardlimit
            found.slimitinodes = quota.slimitinodes
            found.hlimitinodes = quota.hlimitinodes
        else:
            quota_list.append(quota)
        if set_quotas(quota_list,quota_file_db):
            print ("%s\n"%quota_to_str(quota_list[-1]))
    return
if __name__ == '__main__':
    main()

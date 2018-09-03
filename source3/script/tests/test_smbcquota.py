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

import os, subprocess, sys
import traceback
import logging
import shutil

USER_QUOTAS = 1
USER_DEFAULT_QUOTAS = 2
GROUP_QUOTAS = 3
GROUP_DEFAULT_QUOTAS = 4
BLOCK_SIZE = 1024
DEFAULT_SOFTLIM = 2
DEFAULT_HARDLIM = 4

class test_env:
    def __init__(self):
        self.server = None
        self.domain = None
        self.username = None
        self.password = None
        self.envdir = None
        self.quota_db = None
        self.smbcquotas = None
        self.users = []

class user_info:
    def __init__(self):
        self.uid = 0
        self.username = ""
        self.softlim = 0
        self.hardlim = 0

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

def init_quota_db(users, output_file):
    filecontents = open(output_file,"w+")
    lines = ""
    default_values = "0 " + str(DEFAULT_SOFTLIM) + " " + str(DEFAULT_HARDLIM) + " 0 0 0"
    for user in users:
        lines = lines + user.uid + " " + default_values + "\n"
    filecontents.write(lines)
    filecontents.close()

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

def get_quotas(uid, quota_list):
    for quota in quota_list:
        if quota.uid == uid:
            return quota
    return None

def get_users():
    output = subprocess.Popen(['getent', 'passwd'],
                              stdout=subprocess.PIPE).communicate()[0].decode("utf-8").split('\n')
    users = []
    for line in output:
        info = line.split(':')
        if len(info) > 3 and info[0]:
            user = user_info()
            user.username = info[0]
            user.uid = info[2]
            logging.debug("Adding user ->%s<-\n"%user.username)
            users.append(user)
    return users



def smbcquota_output_to_userinfo(output):
    infos = []
    for line in output:
        if len(line) > 1:
            username = line.strip(':').split()[0]
            quota_info = line.split(':')[1].split('/')
            if len(quota_info) > 2:
                info = user_info()
                info.username = username.strip()
                info.softlim = int(quota_info[1].strip()) / BLOCK_SIZE
                info.hardlim = int(quota_info[2].strip()) / BLOCK_SIZE
                infos.append(info)
    return infos

def check_quota_limits(infos, softlim, hardlim):
    if len(infos) < 1:
        logging.debug("no users info to check :-(\n")
        return False
    for info in infos:
        if int(info.softlim) != softlim:
            logging.debug("expected softlimit %s got ->%s<-\n"%(softlim, info.softlim))
            return False
        if int(info.hardlim) != hardlim:
            logging.debug("expected hardlimit limit %s got %s\n"%(hardlim,info.hardlim))
            return False
    return True

class test_base:
    def __init__(self, env):
        self.env = env
    def run(self, protocol):
        pass

class listtest(test_base):
    def run(self, protocol):
        init_quota_db(self.env.users, self.env.quota_db)
        quotas = load_quotas(self.env.quota_db)
        args = [self.env.smbcquotas];
        remaining_args = ['-U' + self.env.username + "%" + self.env.password, '-L', '//' + self.env.server + '/quotadir']
        if protocol == 'smb2':
            args.append('-m smb2')
        args.extend(remaining_args)
        output = subprocess.Popen([self.env.smbcquotas, '-U' + self.env.username + "%" + self.env.password, '-L', '//' + self.env.server + '/quotadir'], stdout=subprocess.PIPE).communicate()[0].decode("utf-8").split('\n')
        infos = smbcquota_output_to_userinfo(output)
        return check_quota_limits(infos, DEFAULT_SOFTLIM, DEFAULT_HARDLIM)
def get_uid(name, users):
    for user in users:
        if user.username == name:
            return user.uid
    return None

class gettest(test_base):
    def run(self, protocol):
        init_quota_db(self.env.users, self.env.quota_db)
        quotas = load_quotas(self.env.quota_db)
        uid = get_uid(self.env.username, self.env.users)
        output = subprocess.Popen([self.env.smbcquotas, '-U' + self.env.username + "%" + self.env.password, '-u' + self.env.username, '//' + self.env.server + '/quotadir'], stdout=subprocess.PIPE).communicate()[0].decode("utf-8").split('\n')
        user_infos = smbcquota_output_to_userinfo(output)
        db_user_info = get_quotas(uid, quotas)
        # double check, we compare the results from the db file
        # the quota script the server uses compared to what
        # smbcquota is telling us
        return check_quota_limits(user_infos, int(db_user_info.softlimit), int(db_user_info.hardlimit))

class settest(test_base):
    def run(self, protocol):
        init_quota_db(self.env.users, self.env.quota_db)
        quotas = load_quotas(self.env.quota_db)
        uid = get_uid(self.env.username, self.env.users)
        old_db_user_info = get_quotas(uid, quotas)

        #increase limits by 2 blocks
        new_soft_limit = (int(old_db_user_info.softlimit) + 2) * BLOCK_SIZE
        new_hard_limit = (int(old_db_user_info.hardlimit) + 2) * BLOCK_SIZE

        new_limits = "UQLIM:%s:%d/%d"%(self.env.username, new_soft_limit, new_hard_limit)
        logging.debug("setting new limits %s"%new_limits)

        output = subprocess.Popen([self.env.smbcquotas, '-U' + self.env.username + "%" + self.env.password, '//' + self.env.server + '/quotadir', '-S', new_limits], stdout=subprocess.PIPE).communicate()[0].decode("utf-8").split('\n')
        logging.debug("output from smbcquota is %s"%output)
        user_infos = smbcquota_output_to_userinfo(output)
        return check_quota_limits(user_infos, new_soft_limit / BLOCK_SIZE, new_hard_limit / BLOCK_SIZE)

# map of tests
subtest_descriptions = {
        "list test" : listtest,
        "get test" : gettest,
        "set test" : settest
}

def main():
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

    logging.debug("got args %s\n"%str(sys.argv))

    if len(sys.argv) < 7:
        logging.debug ("Usage: test_smbcquota.py server domain username password envdir smbcquotas\n")
        sys.exit(1)
    env = test_env()
    env.server = sys.argv[1]
    env.domain = sys.argv[2]
    env.username = sys.argv[3]
    env.password = sys.argv[4]
    env.envdir = sys.argv[5]
    env.smbcquotas = sys.argv[6]
    quota_script = os.path.join(os.path.dirname(sys.argv[0]),
                                "getset_quota.py")
    #copy the quota script to the evironment
    shutil.copy2(quota_script, env.envdir)

    env.quota_db = os.path.join(env.envdir, "quotas.db")
    env.users = get_users()
    for protocol in ['smb1', 'smb2']:
        for key in subtest_descriptions.keys():
            test = subtest_descriptions[key](env)
            logging.debug("running subtest '%s' using protocol '%s'\n"%(key,protocol))
            result = test.run(protocol)
            if result == False:
                logging.debug("subtest '%s' for '%s' failed\n"%(key,protocol))
                sys.exit(1)
            else:
                logging.debug("subtest '%s' for '%s' passed\n"%(key,protocol))
    sys.exit(0)

if __name__ == '__main__':
    main()

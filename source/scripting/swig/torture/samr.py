#!/usr/bin/python

import sys, dcerpc
from optparse import OptionParser

def test_Connect(handle):

    print 'testing samr_Connect'

    r = {}
    r['system_name'] = 0;
    r['access_mask'] = 0x02000000

    result = dcerpc.samr_Connect(pipe, r)

    s = {}
    s['handle'] = result['connect_handle']

    dcerpc.samr_Close(pipe, s)

    print 'testing samr_Connect2'

    r = {}
    r['system_name'] = None
    r['access_mask'] = 0x02000000

    result = dcerpc.samr_Connect2(pipe, r)

    s = {}
    s['handle'] = result['connect_handle']

    dcerpc.samr_Close(pipe, s)
    
    print 'testing samr_Connect3'

    r = {}
    r['system_name'] = None
    r['unknown'] = 0
    r['access_mask'] = 0x02000000

    result = dcerpc.samr_Connect3(pipe, r)

    s = {}
    s['handle'] = result['connect_handle']

    dcerpc.samr_Close(pipe, s)

    print 'testing samr_Connect4'

    r = {}
    r['system_name'] = None
    r['unknown'] = 0
    r['access_mask'] = 0x02000000

    result = dcerpc.samr_Connect4(pipe, r)

    s = {}
    s['handle'] = result['connect_handle']
    
    dcerpc.samr_Close(pipe, s)

    print 'testing samr_Connect5'

    r = {}
    r['system_name'] = None
    r['access_mask'] = 0x02000000
    r['level'] = 1
    r['info'] = {}
    r['info']['info1'] = {}
    r['info']['info1']['unknown1'] = 0
    r['info']['info1']['unknown2'] = 0

    result = dcerpc.samr_Connect5(pipe, r)

    return result['connect_handle']
    
def test_QuerySecurity(pipe, handle):

    print 'testing samr_QuerySecurity'

    r = {}
    r['handle'] = handle
    r['sec_info'] = 7

    result = dcerpc.samr_QuerySecurity(pipe, r)

    s = {}
    s['handle'] = handle
    s['sec_info'] = 7
    s['sdbuf'] = result['sdbuf']

    dcerpc.samr_SetSecurity(pipe, s)

    dcerpc.samr_QuerySecurity(pipe, r)

def test_GetDomPwInfo(pipe, domain):

    print 'testing samr_GetDomPwInfo'

    r = {}
    r['handle'] = handle
    r['name'] = {}
    r['name']['name_len'] = 0
    r['name']['name_size'] = 0
    r['name']['name'] = domain

    dcerpc.samr_GetDomPwInfo(pipe, r)

    r['name']['name'] = '\\\\%s' % domain

    dcerpc.samr_GetDomPwInfo(pipe, r)

    r['name']['name'] = '\\\\__NONAME__'

    dcerpc.samr_GetDomPwInfo(pipe, r)

    r['name']['name'] = '\\\\Builtin'

    dcerpc.samr_GetDomPwInfo(pipe, r)

def test_RemoveMemberFromForeignDomain(pipe, domain_handle):

    print 'test samr_RemoveMemberFromForeignDomain'

    r = {}
    r['domain_handle'] = domain_handle
    r['sid'] = {}
    r['sid']['sid_rev_num'] = 1
    r['sid']['id_auth'] = [1, 2, 3, 4, 5, 6]
    r['sid']['num_auths'] = 4
    r['sid']['sub_auths'] = [7, 8, 9, 10]

    dcerpc.samr_RemoveMemberFromForeignDomain(pipe, r)

def test_CreateUser2(pipe, domain_handle):

    print 'test samr_CreateUser2'

    r = {}
    r['domain_handle'] = domain_handle
    r['access_mask'] = 0x02000000
    r['account_name'] = {}
    r['account_name']['name_len'] = 0
    r['account_name']['name_size'] = 0
    r['account_name']['name'] = 'samrtorturemach$'
    r['acct_flags'] = 0x0080            # WSTRUST

    try:
        dcerpc.samr_CreateUser2(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] == dcerpc.NT_STATUS_ACCESS_DENIED:
            return
        elif arg[0] == dcerpc.NT_STATUS_USER_EXISTS:
            test_DeleteUser_byname(pipe, domain_handle, 'samrtorturemach$')
            result = dcerpc.samr_CreateUser(pipe, r)
        else:
            raise dcerpc.NTSTATUS(arg)

def test_LookupName(pipe, domain_handle, name):

    print 'test samr_LookupNames'

    r = {}
    r['domain_handle'] = domain_handle
    r['num_names'] = 1
    r['names'] = []
    r['names'].append({'name_len': 0, 'name_size': 0, 'name': name})

    result = dcerpc.samr_LookupNames(pipe, r)

    rid = result['rids']['ids'][0]

    r['num_names'] = 2
    r['names'].append({'name_len': 0, 'name_size': 0, 'name': 'xxNONAMExx'})


    try:
        dcerpc.samr_LookupNames(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] != dcerpc.STATUS_SOME_UNMAPPED:
            raise dcerpc.NTSTATUS(arg)

    r['num_names'] = 0

    dcerpc.samr_LookupNames(pipe, r)

    return rid

def test_OpenUser_byname(pipe, domain_handle, user_name):

    rid = test_LookupName(pipe, domain_handle, user_name)

    r = {}
    r['domain_handle'] = domain_handle
    r['access_mask'] = 0x02000000
    r['rid'] = rid

    result = dcerpc.samr_OpenUser(pipe, r)

    return result['user_handle']

def test_DeleteUser_byname(pipe, domain_handle, user_name):

    user_handle = test_OpenUser_byname(pipe, domain_handle, user_name)
    
    r = {}
    r['user_handle'] = user_handle

    dcerpc.samr_DeleteUser(pipe, r)

def test_QueryUserInfo(pipe, user_handle):

    print 'test samr_QueryUserInfo'

    levels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 20, 21]

    for level in levels:
        r = {}
        r['user_handle'] = user_handle
        r['level'] = level

        dcerpc.samr_QueryUserInfo(pipe, r)

def test_QueryUserInfo2(pipe, user_handle):

    print 'test samr_QueryUserInfo2'

    levels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 20, 21]

    for level in levels:
        r = {}
        r['user_handle'] = user_handle
        r['level'] = level

        dcerpc.samr_QueryUserInfo2(pipe, r)

def test_SetUserInfo(pipe, user_handle):

    r = {}
    r['user_handle'] = user_handle
    r['level'] = 2
    r['info'] = {}
    r['info']['info2'] = {}
    r['info']['info2']['comment'] = {}
    r['info']['info2']['comment']['name_len'] = 0
    r['info']['info2']['comment']['name_size'] = 0
    r['info']['info2']['comment']['name'] = 'hello'
    r['info']['info2']['unknown'] = {}
    r['info']['info2']['unknown']['name_len'] = 0
    r['info']['info2']['unknown']['name_size'] = 0
    r['info']['info2']['unknown']['name'] = None
    r['info']['info2']['country_code'] = 0
    r['info']['info2']['code_page'] = 0

    dcerpc.samr_SetUserInfo(pipe, r)

def test_GetUserPwInfo(pipe, user_handle):

    print 'test samr_GetUserpwInfo'

    r = {}
    r['user_handle'] = user_handle

    dcerpc.samr_GetUserPwInfo(pipe, r)

def test_TestPrivateFunctionsUser(pipe, user_handle):

    print 'test samr.TestPrivateFunctionsUser'

    r = {}
    r['user_handle'] = user_handle

    try:
        dcerpc.samr_TestPrivateFunctionsUser(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] != dcerpc.NT_STATUS_NOT_IMPLEMENTED:
            raise dcerpc.NTSTATUS(arg)

def test_user_ops(pipe, user_handle):

    test_QuerySecurity(pipe, user_handle)

    test_QueryUserInfo(pipe, user_handle)

    test_QueryUserInfo2(pipe, user_handle)

    test_SetUserInfo(pipe, user_handle)

    test_GetUserPwInfo(pipe, user_handle)

    test_TestPrivateFunctionsUser(pipe, user_handle)

def test_CreateUser(pipe, domain_handle):

    print 'test samr_CreateUser'
    
    r = {}
    r['domain_handle'] = domain_handle
    r['account_name'] = {}
    r['account_name']['name_len'] = 0
    r['account_name']['name_size'] = 0
    r['account_name']['name'] = 'samrtorturetest'
    r['access_mask'] = 0x02000000

    try:
        result = dcerpc.samr_CreateUser(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] == dcerpc.NT_STATUS_ACCESS_DENIED:
            return
        elif arg[0] == dcerpc.NT_STATUS_USER_EXISTS:
            test_DeleteUser_byname(pipe, domain_handle, 'samrtorturetest')
            result = dcerpc.samr_CreateUser(pipe, r)
        else:
            raise dcerpc.NTSTATUS(arg)

    user_handle = result['user_handle']

    q = {}
    q['user_handle'] = user_handle
    q['level'] = 16

    dcerpc.samr_QueryUserInfo(pipe, q)

    test_user_ops(pipe, user_handle)

    return user_handle

def test_DeleteAlias_byname(pipe, domain_handle, alias_name):

    rid = test_LookupName(pipe, domain_handle, alias_name)

    r = {}
    r['domain_handle'] = domain_handle
    r['access_mask'] = 0x02000000
    r['rid'] = rid

    result = dcerpc.samr_OpenAlias(pipe, r)

    s = {}
    s['alias_handle'] = result['alias_handle']

    dcerpc.samr_DeleteDomAlias(pipe, s)

def test_QueryAliasInfo(pipe, alias_handle):

    levels = [1, 2, 3]

    for i in range(0, len(levels)):

        r = {}
        r['alias_handle'] = alias_handle
        r['level']  = levels[i]

        dcerpc.samr_QueryAliasInfo(pipe, r)

def test_SetAliasInfo(pipe, alias_handle):

    r = {}
    r['alias_handle'] = alias_handle
    r['level'] = 2
    r['info'] = {}
    r['info']['name'] = {}
    r['info']['name']['name_len'] = 0
    r['info']['name']['name_size'] = 0
    r['info']['name']['name'] = 'hello'

    dcerpc.samr_SetAliasInfo(pipe, r)

    del(r['info']['name'])

    r['level'] = 3
    r['info']['description'] = {}
    r['info']['description']['name_len'] = 0
    r['info']['description']['name_size'] = 0
    r['info']['description']['name'] = 'this is a description'
    
    dcerpc.samr_SetAliasInfo(pipe, r)

def test_AddMemberToAlias(pipe, alias_handle, domain_sid):

    r = {}
    r['alias_handle'] = alias_handle
    r['sid'] = domain_sid

    r['sid']['num_auths'] = r['sid']['num_auths'] + 1
    r['sid']['sub_auths'].append(512)

    dcerpc.samr_AddAliasMember(pipe, r)

    dcerpc.samr_DeleteAliasMember(pipe, r)

def test_AddMultipleMembersToAlias(pipe, alias_handle):

    r = {}
    r['alias_handle'] = alias_handle
    r['sids'] = {}
    r['sids']['num_sids'] = 2
    r['sids']['sids'] = []

    for i in range(0,2):
        sid = {}
        sid['sid_rev_num'] = 1
        sid['id_auth'] = [0, 0, 0, 0, 0, 5]
        sid['num_auths'] = 5
        sid['sub_auths'] = [21, 737922324, -1292160505, 1285293260, 512 + i]

        r['sids']['sids'].append({'sid': sid})

    dcerpc.samr_AddMultipleMembersToAlias(pipe, r)

    dcerpc.samr_RemoveMultipleMembersFromAlias(pipe, r)

def test_alias_ops(pipe, alias_handle, domain_sid):

    test_QuerySecurity(pipe, alias_handle)

    test_QueryAliasInfo(pipe, alias_handle)

    test_SetAliasInfo(pipe, alias_handle)

    test_AddMemberToAlias(pipe, alias_handle, domain_sid)

    test_AddMultipleMembersToAlias(pipe, alias_handle)

def test_CreateAlias(pipe, domain_handle, domain_sid):

    print 'test samr_CreateAlias'    

    alias_name = 'samrtorturetestalias'

    r = {}
    r['domain_handle'] = domain_handle
    r['aliasname'] = {}
    r['aliasname']['name_len'] = 0
    r['aliasname']['name_size'] = 0
    r['aliasname']['name'] = alias_name
    r['access_mask'] = 0x02000000

    try:
        result = dcerpc.samr_CreateDomAlias(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] == dcerpc.NT_STATUS_ACCESS_DENIED:
            return
        if arg[0] != dcerpc.NT_STATUS_USER_EXISTS:
            raise dcerpc.NTSTATUS(arg)
        test_DeleteAlias_byname(pipe, domain_handle, alias_name)
        result = dcerpc.samr_CreateDomAlias(pipe, r)

    alias_handle = result['alias_handle']

    test_alias_ops(pipe, alias_handle, domain_sid)

    return alias_handle

def test_DeleteGroup_byname(pipe, domain_handle, group_name):
    
    rid = test_LookupName(pipe, domain_handle, group_name)

    r = {}
    r['domain_handle'] = domain_handle
    r['access_mask'] = 0x02000000
    r['rid'] = rid

    result = dcerpc.samr_OpenGroup(pipe, r)

    s = {}
    s['group_handle'] = result['group_handle']

    dcerpc.samr_DeleteDomainGroup(pipe, s)

def test_CreateDomainGroup(pipe, domain_handle):

    print 'testing samr_CreateDomainGroup'

    r = {}
    r['domain_handle'] = domain_handle
    r['name'] = {}
    r['name']['name_len'] = 0
    r['name']['name_size'] = 0
    r['name']['name'] = 'samrtorturetestgroup'
    r['access_mask'] = 0x02000000

    try:
        result = dcerpc.samr_CreateDomainGroup(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] == dcerpc.NT_STATUS_ACCESS_DENIED:
            return
        if arg[0] != dcerpc.NT_STATUS_GROUP_EXISTS:
            raise dcerpc.NTSTATUS(arg)

        test_DeleteGroup_byname(pipe, domain_handle, 'samrtorturetestgroup')

        result = dcerpc.samr_CreateDomainGroup(pipe, r)

    return result['group_handle']

def test_QueryDomainInfo(pipe, domain_handle):

    print 'testing samr_QueryDomainInfo'

    levels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13]
    set_ok = [1, 0, 1, 1, 0, 1, 1, 0, 1,  0,  1,  0]
    
    for i in range(0, len(levels)):

        r = {}
        r['domain_handle'] = domain_handle
        r['level'] = levels[i]

        result = dcerpc.samr_QueryDomainInfo(pipe, r)

        s = {}
        s['domain_handle'] = domain_handle
        s['level'] = levels[i]
        s['info'] = result['info']

        try:
            dcerpc.samr_SetDomainInfo(pipe, s)
        except dcerpc.NTSTATUS, arg:
            if set_ok[i]:
                raise dcerpc.NTSTATUS(arg)
            if arg[0] != dcerpc.NT_STATUS_INVALID_INFO_CLASS:
                raise dcerpc.NTSTATUS(arg)

def test_QueryDomainInfo2(pipe, domain_handle):

    print 'testing samr_QueryDomainInfo'

    levels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13]

    for i in range(0, len(levels)):

        r = {}
        r['domain_handle'] = domain_handle
        r['level'] = levels[i]

        dcerpc.samr_QueryDomainInfo2(pipe, r)

def test_EnumDomainUsers(pipe, domain_handle):

    print 'testing samr_EnumDomainUsers'

    r = {}
    r['domain_handle'] = domain_handle
    r['resume_handle'] = 0
    r['acct_flags'] = 0
    r['max_size'] = -1

    while 1:
        result = dcerpc.samr_EnumDomainUsers(pipe, r)
        if result['result'] == dcerpc.STATUS_MORE_ENTRIES:
            r['resume_handle'] = result['resume_handle']
            continue
        break

def test_EnumDomainGroups(pipe, domain_handle):

    print 'testing samr_EnumDomainGroups'

    r = {}
    r['domain_handle'] = domain_handle
    r['resume_handle'] = 0
    r['acct_flags'] = 0
    r['max_size'] = -1
    
    while 1:
        result = dcerpc.samr_EnumDomainGroups(pipe, r)
        if result['result'] == dcerpc.STATUS_MORE_ENTRIES:
            r['resume_handle'] = result['resume_handle']
            continue
        break

def test_EnumDomainAliases(pipe, domain_handle):

    print 'testing samr_EnumDomainAliases'

    r = {}
    r['domain_handle'] = domain_handle
    r['resume_handle'] = 0
    r['acct_flags'] = 0
    r['max_size'] = -1

    while 1:
        result = dcerpc.samr_EnumDomainAliases(pipe, r)
        if result['result'] == dcerpc.STATUS_MORE_ENTRIES:
            r['resume_handle'] = result['resume_handle']
            continue
        break

def test_QueryDisplayInfo(pipe, domain_handle):

    print 'testing samr_QueryDisplayInfo'

    levels = [1, 2, 3, 4, 5]

    for i in range(0, len(levels)):

        r = {}
        r['domain_handle'] = domain_handle
        r['level'] = levels[i]
        r['start_idx'] = 0
        r['max_entries'] = 1000
        r['buf_size'] = -1

        dcerpc.samr_QueryDisplayInfo(pipe, r)

def test_QueryDisplayInfo2(pipe, domain_handle):

    print 'testing samr_QueryDisplayInfo2'

    levels = [1, 2, 3, 4, 5]

    for i in range(0, len(levels)):

        r = {}
        r['domain_handle'] = domain_handle
        r['level'] = levels[i]
        r['start_idx'] = 0
        r['max_entries'] = 1000
        r['buf_size'] = -1

        dcerpc.samr_QueryDisplayInfo2(pipe, r)
    
def test_QueryDisplayInfo3(pipe, domain_handle):

    print 'testing samr_QueryDisplayInfo3'

    levels = [1, 2, 3, 4, 5]

    for i in range(0, len(levels)):

        r = {}
        r['domain_handle'] = domain_handle
        r['level'] = levels[i]
        r['start_idx'] = 0
        r['max_entries'] = 1000
        r['buf_size'] = -1

        dcerpc.samr_QueryDisplayInfo3(pipe, r)

def test_GetDisplayEnumerationIndex(pipe, domain_handle):

    print 'testing samr_GetDisplayEnumerationIndex'

    levels = [1, 2, 3, 4, 5]
    ok_lvl = [1, 1, 1, 0, 0]

    for i in range(0, len(levels)):

        r = {}
        r['domain_handle'] = domain_handle
        r['level'] = levels[i]
        r['name'] = {}
        r['name']['name_len'] = 0
        r['name']['name_size'] = 0
        r['name']['name'] = 'samrtorturetest'

        try:
            dcerpc.samr_GetDisplayEnumerationIndex(pipe, r)
        except dcerpc.NTSTATUS, arg:
            if ok_lvl[i]:
                raise dcerpc.NTSTATUS(arg)

        r['name']['name'] = 'zzzzzzzz'

        try:
            dcerpc.samr_GetDisplayEnumerationIndex(pipe, r)
        except dcerpc.NTSTATUS, arg:
            if ok_lvl[i]:
                raise dcerpc.NTSTATUS(arg)            

def test_GetDisplayEnumerationIndex2(pipe, domain_handle):

    print 'testing samr_GetDisplayEnumerationIndex2'

    levels = [1, 2, 3, 4, 5]
    ok_lvl = [1, 1, 1, 0, 0]

    for i in range(0, len(levels)):

        r = {}
        r['domain_handle'] = domain_handle
        r['level'] = levels[i]
        r['name'] = {}
        r['name']['name_len'] = 0
        r['name']['name_size'] = 0
        r['name']['name'] = 'samrtorturetest'

        try:
            dcerpc.samr_GetDisplayEnumerationIndex2(pipe, r)
        except dcerpc.NTSTATUS, arg:
            if ok_lvl[i]:
                raise dcerpc.NTSTATUS(arg)

        r['name']['name'] = 'zzzzzzzz'

        try:
            dcerpc.samr_GetDisplayEnumerationIndex2(pipe, r)
        except dcerpc.NTSTATUS, arg:
            if ok_lvl[i]:
                raise dcerpc.NTSTATUS(arg)            

def test_TestPrivateFunctionsDomain(pipe, domain_handle):

    print 'test samr.TestPrivateFunctionsDomain'

    r = {}
    r['domain_handle'] = domain_handle

    try:
        dcerpc.samr_TestPrivateFunctionsDomain(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] != dcerpc.NT_STATUS_NOT_IMPLEMENTED:
            raise dcerpc.NTSTATUS(arg)

def test_RidToSid(pipe, domain_handle):

    print 'testing samr_RidToSid'

    r = {}
    r['domain_handle'] = domain_handle
    r['rid'] = 512

    dcerpc.samr_RidToSid(pipe, r)

def test_GetBootKeyInformation(pipe, domain_handle):

    print 'testing samr_GetBootKeyInformation'

    r = {}
    r['domain_handle'] = domain_handle

    try:
        dcerpc.samr_GetBootKeyInformation(pipe, r)
    except dcerpc.NTSTATUS, arg:
        pass

def test_DeleteUser(pipe, user_handle):

    r = {}
    r['user_handle'] = user_handle

    dcerpc.samr_DeleteUser(pipe, r)

def test_DeleteAlias(pipe, alias_handle):

    r = {}
    r['alias_handle'] = alias_handle

    dcerpc.samr_DeleteDomAlias(pipe, r)
    
def test_DeleteDomainGroup(pipe, group_handle):

    r = {}
    r['group_handle'] = group_handle

    dcerpc.samr_DeleteDomainGroup(pipe, r)

def test_Close(pipe, handle):

    r = {}
    r['handle'] = handle

    dcerpc.samr_Close(pipe, r)

def test_OpenDomain(pipe, connect_handle, domain_sid):

    print 'testing samr_OpenDomain'

    r = {}
    r['connect_handle'] = connect_handle
    r['access_mask'] = 0x02000000
    r['sid'] = domain_sid

    result = dcerpc.samr_OpenDomain(pipe, r)

    domain_handle = result['domain_handle']

    test_QuerySecurity(pipe, domain_handle)

    test_RemoveMemberFromForeignDomain(pipe, domain_handle)

    test_CreateUser2(pipe, domain_handle)

    user_handle = test_CreateUser(pipe, domain_handle)

    alias_handle = test_CreateAlias(pipe, domain_handle, domain_sid)

    group_handle = test_CreateDomainGroup(pipe, domain_handle)

    test_QueryDomainInfo(pipe, domain_handle)
    
    test_QueryDomainInfo2(pipe, domain_handle)

    test_EnumDomainUsers(pipe, domain_handle)

    test_EnumDomainGroups(pipe, domain_handle)

    test_EnumDomainAliases(pipe, domain_handle)

    test_QueryDisplayInfo(pipe, domain_handle)

    test_QueryDisplayInfo2(pipe, domain_handle)
    
    test_QueryDisplayInfo3(pipe, domain_handle)

    test_GetDisplayEnumerationIndex(pipe, domain_handle)

    test_GetDisplayEnumerationIndex2(pipe, domain_handle)

    test_TestPrivateFunctionsDomain(pipe, domain_handle)

    test_RidToSid(pipe, domain_handle)

    test_GetBootKeyInformation(pipe, domain_handle)

    if user_handle != None:
        test_DeleteUser(pipe, user_handle)

    if alias_handle != None:
        test_DeleteAlias(pipe, alias_handle)

    if group_handle != None:
        test_DeleteDomainGroup(pipe, group_handle)

    test_Close(pipe, domain_handle)
    
def test_LookupDomain(pipe, connect_handle, domain):

    print 'testing samr_LookupDomain'

    r = {}
    r['connect_handle'] = connect_handle
    r['domain'] = {}
    r['domain']['name_len'] = 0
    r['domain']['name_size'] = 0
    r['domain']['name'] = None

    try:
        dcerpc.samr_LookupDomain(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] != dcerpc.NT_STATUS_INVALID_PARAMETER:
            raise dcerpc.NTSTATUS(arg)

    r['domain']['name'] = 'xxNODOMAINxx'

    try:
        dcerpc.samr_LookupDomain(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] != dcerpc.NT_STATUS_NO_SUCH_DOMAIN:
            raise dcerpc.NTSTATUS(arg)

    r['domain']['name'] = domain

    result = dcerpc.samr_LookupDomain(pipe, r)

    test_GetDomPwInfo(pipe, domain)

    test_OpenDomain(pipe, handle, result['sid'])
    
def test_EnumDomains(pipe, connect_handle):

    print 'testing samr_EnumDomains'

    r = {}
    r['connect_handle'] = handle
    r['resume_handle'] = 0
    r['buf_size'] = -1

    result = dcerpc.samr_EnumDomains(pipe, r)

    for domain in result['sam']['entries']:
        test_LookupDomain(pipe, handle, domain['name']['name'])

# Parse command line

parser = OptionParser()

parser.add_option("-b", "--binding", action="store", type="string",
                  dest="binding")

parser.add_option("-d", "--domain", action="store", type="string",
                  dest="domain")

parser.add_option("-u", "--username", action="store", type="string",
                  dest="username")

parser.add_option("-p", "--password", action="store", type="string",
                  dest="password")

(options, args) = parser.parse_args()

if not options.binding:
   parser.error('You must supply a binding string')

if not options.username or not options.password or not options.domain:
   parser.error('You must supply a domain, username and password')


binding = options.binding
domain = options.domain
username = options.username
password = options.password

print 'Connecting...'

pipe = dcerpc.pipe_connect(binding,
	dcerpc.DCERPC_SAMR_UUID, dcerpc.DCERPC_SAMR_VERSION,
	domain, username, password)

handle = test_Connect(pipe)

test_QuerySecurity(pipe, handle)

test_EnumDomains(pipe, handle)

print 'Done'

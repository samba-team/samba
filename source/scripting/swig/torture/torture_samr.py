#!/usr/bin/python

import sys
import dcerpc, samr

def test_Connect(pipe):

    print 'testing Connect'

    handle = samr.Connect(pipe)
    handle = samr.Connect2(pipe)
    handle = samr.Connect3(pipe)
    handle = samr.Connect4(pipe)
#    handle = samr.Connect5(pipe) # win2k3 only?

    return handle
    
def test_QuerySecurity(pipe, handle):

    print 'testing QuerySecurity'

    sdbuf = handle.QuerySecurity()
    handle.SetSecurity(sdbuf)


def test_GetDomPwInfo(pipe, handle, domain):

    print 'testing GetDomPwInfo'

    handle.GetDomPwInfo(domain)
    handle.GetDomPwInfo('__NONAME__')
    handle.GetDomPwInfo('Builtin')

def test_RemoveMemberFromForeignDomain(pipe, domain_handle):

    print 'testing RemoveMemberFromForeignDomain'

    sid = samr.string_to_sid('S-1-5-32-12-34-56-78-9')

    domain_handle.RemoveMemberFromForeignDomain(sid)

def test_CreateUser2(pipe, domain_handle):

    print 'testing CreateUser2'

    username = 'samrtorturemach$'

    try:
        return domain_handle.CreateUser2(username, 0x0080) # WSTRUST
    except dcerpc.NTSTATUS, arg:
        if arg[0] == 0x0c0000063L:
            test_OpenUser_byname(pipe, domain_handle, username).DeleteUser()
            return domain_handle.CreateUser2(username)
        raise

def test_LookupName(pipe, domain_handle, name):

    print 'testing samr_LookupNames'

    domain_handle.LookupNames(['Administrator', 'xxNONAMExx'])

    try:
        domain_handle.LookupNames(['xxNONAMExx'])
    except dcerpc.NTSTATUS, arg:
        if arg[0] != 0xc0000073L:
            raise dcerpc.NTSTATUS(arg)

    return domain_handle.LookupNames([name])

def test_OpenUser_byname(pipe, domain_handle, user_name):

    rids, types = test_LookupName(pipe, domain_handle, user_name)

    return domain_handle.OpenUser(rids[0])

def test_DeleteUser_byname(pipe, domain_handle, user_name):

    user_handle = test_OpenUser_byname(pipe, domain_handle, user_name)
    
    r = {}
    r['user_handle'] = user_handle

    dcerpc.samr_DeleteUser(pipe, r)

def test_QueryUserInfo(pipe, user_handle):

    print 'testing samr_QueryUserInfo'

    levels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 20, 21]

    for level in levels:
        r = {}
        r['user_handle'] = user_handle
        r['level'] = level

        dcerpc.samr_QueryUserInfo(pipe, r)

def test_QueryUserInfo2(pipe, user_handle):

    print 'testing samr_QueryUserInfo2'

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
    r['info']['info2']['comment']['name'] = 'hello'
    r['info']['info2']['unknown'] = {}
    r['info']['info2']['unknown']['name'] = None
    r['info']['info2']['country_code'] = 0
    r['info']['info2']['code_page'] = 0

    dcerpc.samr_SetUserInfo(pipe, r)

def test_GetUserPwInfo(pipe, user_handle):

    print 'testing samr_GetUserpwInfo'

    r = {}
    r['user_handle'] = user_handle

    dcerpc.samr_GetUserPwInfo(pipe, r)

def test_TestPrivateFunctionsUser(pipe, user_handle):

    print 'testing samr.TestPrivateFunctionsUser'

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

    username = 'samrtorturetest'

    try:
        return domain_handle.CreateUser(username)
    except dcerpc.NTSTATUS, arg:
        if arg[0] == 0xc0000063L:
            test_OpenUser_byname(pipe, domain_handle, username).DeleteUser()
            return domain_handle.CreateUser(username)

def test_SetAliasInfo(pipe, alias_handle):

    r = {}
    r['alias_handle'] = alias_handle
    r['level'] = 2
    r['info'] = {}
    r['info']['name'] = {}
    r['info']['name']['name'] = 'hello'

    dcerpc.samr_SetAliasInfo(pipe, r)

    del(r['info']['name'])

    r['level'] = 3
    r['info']['description'] = {}
    r['info']['description']['name'] = 'this is a description'
    
    dcerpc.samr_SetAliasInfo(pipe, r)

def test_Aliases(pipe, domain_handle, domain_sid):

    print 'testing aliases'

    aliasname = 'samrtorturetestalias'

    # Create a new alias

    try:

        handle, rid = domain_handle.CreateDomAlias(aliasname)

    except dcerpc.NTSTATUS, arg:

        if arg[0] == 0x0c0000154L:

            # Alias exists, delete it and try again

            rids, types = domain_handle.LookupNames([aliasname])
            domain_handle.OpenAlias(rids[0]).DeleteDomAlias()

            handle, rid = domain_handle.CreateDomAlias(aliasname)
            
        else:
            raise

    # QuerySecurity/GetSecurity

    handle.SetSecurity(handle.QuerySecurity())

    # QueryAliasInfo/SetAliasInfo

    for i in [1, 2, 3]:
        info = handle.QueryAliasInfo(i)
        try:
            handle.SetAliasInfo(i, info)
        except dcerpc.NTSTATUS, arg:

            # Can't set alias info level 1

            if not (arg[0] == 0xC0000003L and i == 1):
                raise

    # AddAliasMember

    handle.AddAliasMember('S-1-5-21-1606980848-1677128483-854245398-500')

    # AddMultipleMembersToAlias

    handle.AddMultipleMembersToAlias(
        ['S-1-5-21-1606980848-1677128483-854245398-501',
         'S-1-5-21-1606980848-1677128483-854245398-502'])

    # DeleteDomAlias

    handle.DeleteDomAlias()

def test_DeleteGroup_byname(pipe, domain_handle, group_name):
    
    rid = test_LookupNames(pipe, domain_handle, group_name)

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

    print 'testing samr.TestPrivateFunctionsDomain'

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

    print 'testing OpenDomain'

    domain_handle = connect_handle.OpenDomain(domain_sid)

    test_QuerySecurity(pipe, domain_handle)

    test_RemoveMemberFromForeignDomain(pipe, domain_handle)

    test_CreateUser2(pipe, domain_handle)

    test_CreateUser(pipe, domain_handle)

    test_Aliases(pipe, domain_handle, domain_sid)

    sys.exit(0)

    test_CreateDomainGroup(pipe, domain_handle)

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

    print 'testing LookupDomain'

    sid = connect_handle.LookupDomain(domain)

    try:
        connect_handle.LookupDomain('xxNODOMAINxx')
    except dcerpc.NTSTATUS, arg:
        if arg[0] != 0xC00000DFL:          # NT_STATUS_NO_SUCH_DOMAIN
            raise
            
    test_GetDomPwInfo(pipe, connect_handle, domain)
    test_OpenDomain(pipe, connect_handle, sid)
    
def test_EnumDomains(pipe, connect_handle):

    print 'testing EnumDomains'

    for domain in connect_handle.EnumDomains():
        test_LookupDomain(pipe, connect_handle, domain)

def runtests(binding, creds):

    print 'Testing SAMR pipe'

    pipe = dcerpc.pipe_connect(binding,
            dcerpc.DCERPC_SAMR_UUID, int(dcerpc.DCERPC_SAMR_VERSION), creds)

    handle = test_Connect(pipe)

    test_QuerySecurity(pipe, handle)

    test_EnumDomains(pipe, handle)

#!/usr/bin/python

import dcerpc
from optparse import OptionParser

def test_Connect(handle):

    print 'testing samr_Connect'

    r = {}
    r['system_name'] = 0;
    r['access_mask'] = 0x02000000

    result = dcerpc.samr_Connect(pipe, r)
    dcerpc.samr_Close(pipe, result)

    print 'testing samr_Connect2'

    r = {}
    r['system_name'] = None
    r['access_mask'] = 0x02000000

    result = dcerpc.samr_Connect2(pipe, r)
    dcerpc.samr_Close(pipe, result)
    
    print 'testing samr_Connect3'

    r = {}
    r['system_name'] = None
    r['unknown'] = 0
    r['access_mask'] = 0x02000000

    result = dcerpc.samr_Connect3(pipe, r)
    dcerpc.samr_Close(pipe, result)

    print 'testing samr_Connect4'

    r = {}
    r['system_name'] = None
    r['unknown'] = 0
    r['access_mask'] = 0x02000000

    result = dcerpc.samr_Connect4(pipe, r)
    dcerpc.samr_Close(pipe, result)

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

    return result['handle']
    
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

    result = dcerpc.samr_SetSecurity(pipe, s)

    result = dcerpc.samr_QuerySecurity(pipe, r)

def test_GetDomPwInfo(pipe, domain):

    print 'testing samr_GetDomPwInfo'

    r = {}
    r['handle'] = handle
    r['name'] = {}
    r['name']['name_len'] = 0
    r['name']['name_size'] = 0
    r['name']['name'] = domain

    result = dcerpc.samr_GetDomPwInfo(pipe, r)

    r['name']['name'] = '\\\\%s' % domain

    result = dcerpc.samr_GetDomPwInfo(pipe, r)

    r['name']['name'] = '\\\\__NONAME__'

    result = dcerpc.samr_GetDomPwInfo(pipe, r)

    r['name']['name'] = '\\\\Builtin'

    result = dcerpc.samr_GetDomPwInfo(pipe, r)

def test_RemoveMemberFromForeignDomain(pipe, domain_handle):

    r = {}
    r['handle'] = domain_handle
    r['sid'] = {}
    r['sid']['sid_rev_num'] = 1
    r['sid']['id_auth'] = [1, 2, 3, 4, 5, 6]
    r['sid']['num_auths'] = 4
    r['sid']['sub_auths'] = [7, 8, 9, 10]

    result = dcerpc.samr_RemoveMemberFromForeignDomain(pipe, r)

def test_CreateUser2(pipe, domain_handle):
    pass

def test_LookupName(pipe, domain_handle, name):

    r = {}
    r['handle'] = domain_handle
    r['num_names'] = 1
    r['names'] = []
    r['names'].append({'name_len': 0, 'name_size': 0, 'name': name})

    result = dcerpc.samr_LookupNames(pipe, r)

    rid = result['rids']['ids'][0]

    r['num_names'] = 2
    r['names'].append({'name_len': 0, 'name_size': 0, 'name': 'xxNONAMExx'})


    try:
        result = dcerpc.samr_LookupNames(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] != 0x00000107:
            raise dcerpc.NTSTATUS(arg)

    r['num_names'] = 0

    result = dcerpc.samr_LookupNames(pipe, r)

    return rid

def test_OpenUser_byname(pipe, domain_handle, name):

    rid = test_LookupName(pipe, domain_handle, name)

    r = {}
    r['handle'] = domain_handle
    r['access_mask'] = 0x02000000
    r['rid'] = rid

    result = dcerpc.samr_OpenUser(pipe, r)

    return result['acct_handle']

def test_DeleteUser_byname(pipe, domain_handle, name):

    user_handle = test_OpenUser_byname(pipe, domain_handle, name)
    
    r = {}
    r['handle'] = user_handle

    dcerpc.samr_DeleteUser(pipe, r)

def test_CreateUser(pipe, domain_handle):

    r = {}
    r['handle'] = domain_handle
    r['account_name'] = {}
    r['account_name']['name_len'] = 0
    r['account_name']['name_size'] = 0
    r['account_name']['name'] = 'samrtorturetest'
    r['access_mask'] = 0x02000000

    try:
        result = dcerpc.samr_CreateUser(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] == 0xc0000022:
            return
        elif arg[0] == 0xc0000063:
            test_DeleteUser_byname(pipe, domain_handle, 'samrtorturetest')
            result = dcerpc.samr_CreateUser(pipe, r)
        else:
            raise dcerpc.NTSTATUS(arg)

    user_handle = result['acct_handle']

    # samr_QueryUserInfo(), etc

def test_OpenDomain(pipe, handle, domain_sid):

    print 'testing samr_OpenDomain'

    r = {}
    r['handle'] = handle
    r['access_mask'] = 0x02000000
    r['sid'] = domain_sid

    result = dcerpc.samr_OpenDomain(pipe, r)

    domain_handle = result['domain_handle']

    test_QuerySecurity(pipe, domain_handle)

    test_RemoveMemberFromForeignDomain(pipe, domain_handle)

    test_CreateUser2(pipe, domain_handle)

    test_CreateUser(pipe, domain_handle)
    
def test_LookupDomain(pipe, handle, domain):

    print 'testing samr_LookupDomain'

    r = {}
    r['handle'] = handle
    r['domain'] = {}
    r['domain']['name_len'] = 0
    r['domain']['name_size'] = 0
    r['domain']['name'] = None

    try:
        result = dcerpc.samr_LookupDomain(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] != 0xc000000d:
            raise dcerpc.NTSTATUS(arg)

    r['domain']['name'] = 'xxNODOMAINxx'

    try:
        result = dcerpc.samr_LookupDomain(pipe, r)
    except dcerpc.NTSTATUS, arg:
        if arg[0] != 0xc00000df:
            raise dcerpc.NTSTATUS(arg)

    r['domain']['name'] = domain

    result = dcerpc.samr_LookupDomain(pipe, r)

    test_GetDomPwInfo(pipe, domain)

    test_OpenDomain(pipe, handle, result['sid'])
    
def test_EnumDomains(pipe, handle):

    print 'testing samr_EnumDomains'

    r = {}
    r['handle'] = handle
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

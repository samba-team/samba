#!/usr/bin/python

import sys, dcerpc

def test_OpenHKLM(pipe):

    r = {}
    r['unknown'] = {}
    r['unknown']['unknown0'] = 0x9038
    r['unknown']['unknown1'] = 0x0000
    r['access_required'] = 0x02000000

    result = dcerpc.winreg_OpenHKLM(pipe, r)

    return result['handle']

def test_QueryInfoKey(pipe, handle):

    r = {}
    r['handle'] = handle
    r['class'] = {}
    r['class']['name'] = None

    return dcerpc.winreg_QueryInfoKey(pipe, r)

def test_CloseKey(pipe, handle):

    r = {}
    r['handle'] = handle

    dcerpc.winreg_CloseKey(pipe, r)

def test_Enum(pipe, handle, depth = 0):

    if depth > 2:
        return

    keyinfo = test_QueryInfoKey(pipe, handle)

    # Enumerate keys

    r = {}
    r['handle'] = handle
    r['key_name_len'] = 0
    r['unknown'] = 0x0414
    r['in_name'] = {}
    r['in_name']['unknown'] = 0x20a
    r['in_name']['key_name'] = {}
    r['in_name']['key_name']['name'] = None
    r['class'] = {}
    r['class']['name'] = None
    r['last_changed_time'] = {}
    r['last_changed_time']['low'] = 0
    r['last_changed_time']['high'] = 0

    for i in range(0, keyinfo['num_subkeys']):

        r['enum_index'] = i

        subkey = dcerpc.winreg_EnumKey(pipe, r)

        s = {}
        s['handle'] = handle
        s['keyname'] = {}
        s['keyname']['name'] = subkey['out_name']['name']
        s['unknown'] = 0
        s['access_mask'] = 0x02000000

        result = dcerpc.winreg_OpenKey(pipe, s)

        test_Enum(pipe, result['handle'], depth + 1)

        test_CloseKey(pipe, result['handle'])

    # Enumerate values

    r = {}
    r['handle'] = handle

    keyinfo['max_valnamelen'] = 18
    keyinfo['max_valbufsize'] = 0x31f5

    r['foo'] = {}
    r['foo']['len'] = 0
    r['foo']['max_len'] = keyinfo['max_valnamelen'] * 2
    r['foo']['buffer'] = {}
    r['foo']['buffer']['max_len'] = keyinfo['max_valnamelen']
    r['foo']['buffer']['offset'] = 0
    r['foo']['buffer']['len'] = 0
    r['foo']['buffer']['buffer'] = ''
    r['type'] = 0
    r['value'] = {}
    r['value']['max_len'] = keyinfo['max_valbufsize']
    r['value']['offset'] = 0
    r['value']['len'] = 0
    r['value']['buffer'] = []
    r['returned_len'] = 0
    r['foo2'] = {}
    r['foo2']['max_len'] = keyinfo['max_valbufsize']
    r['foo2']['offset'] = 0
    r['foo2']['len'] = 0
    r['foo2']['buffer'] = ''
    r['value1'] = keyinfo['max_valbufsize']
    r['value2'] = 0
    
    for i in range(0, keyinfo['num_values']):

        r['enum_index'] = i

        print keyinfo
        print dcerpc.winreg_EnumValue(pipe, r)

        sys.exit(1)        

def test_Key(pipe, handle):

    test_Enum(pipe, handle)        

def runtests(binding, domain, username, password):
    
    print 'Testing WINREG pipe'

    pipe = dcerpc.pipe_connect(binding,
            dcerpc.DCERPC_WINREG_UUID, dcerpc.DCERPC_WINREG_VERSION,
            domain, username, password)

    handle = test_OpenHKLM(pipe)

    test_Key(pipe, handle)
    

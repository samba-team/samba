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

    return

    r = {}
    r['handle'] = handle
    r['name'] = {}
    r['name']['len'] = 0
    r['name']['max_len'] = 0
    r['name']['name'] = {}
    r['name']['name']['max_len'] = 0
    r['name']['name']['offset'] = 0
    r['name']['name']['len'] = 0
    r['name']['name']['buffer'] = None
    r['type'] = 0
    r['value'] = {}
    r['value']['max_len'] = 0
    r['value']['offset'] = 0
    r['value']['len'] = 0
    r['value']['buffer'] = []
    r['returned_len'] = 0
    
    for i in range(0, keyinfo['num_values']):

        r['enum_index'] = i
        
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
    

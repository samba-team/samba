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

def test_Enum(pipe, handle, name, depth = 0):

    if depth > 2:
        return

    try:
        keyinfo = test_QueryInfoKey(pipe, handle)
    except dcerpc.WERROR, arg:
        if arg[0] == dcerpc.WERR_ACCESS_DENIED:
            return

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

        test_Enum(pipe, result['handle'], name + '/' + s['keyname']['name'],
                  depth + 1)

        test_CloseKey(pipe, result['handle'])

    # Enumerate values

    r = {}
    r['handle'] = handle

    r['name_in'] = {}
    r['name_in']['len'] = 0
    r['name_in']['max_len'] = (keyinfo['max_valnamelen'] + 1) * 2
    r['name_in']['buffer'] = {}
    r['name_in']['buffer']['max_len'] = keyinfo['max_valnamelen']  + 1
    r['name_in']['buffer']['offset'] = 0
    r['name_in']['buffer']['len'] = 0
    r['type'] = 0
    r['value_in'] = {}
    r['value_in']['max_len'] = keyinfo['max_valbufsize']
    r['value_in']['offset'] = 0
    r['value_in']['len'] = 0
    r['value_len1'] = keyinfo['max_valbufsize']
    r['value_len2'] = 0
    
    for i in range(0, keyinfo['num_values']):

        r['enum_index'] = i

        dcerpc.winreg_EnumValue(pipe, r)

def test_Key(pipe, handle, name):

    test_Enum(pipe, handle, name)

def runtests(binding, domain, username, password):
    
    print 'Testing WINREG pipe'

    pipe = dcerpc.pipe_connect(binding,
            dcerpc.DCERPC_WINREG_UUID, dcerpc.DCERPC_WINREG_VERSION,
            domain, username, password)

    handle = test_OpenHKLM(pipe)

    test_Key(pipe, handle, 'HKLM')

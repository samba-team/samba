#!/usr/bin/python

import dcerpc

def test_Connect(handle):

    print 'testing samr_Connect'

    r = {}
    r['system_name'] = '\0\0'
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
    
# Connect to server

pipe = dcerpc.pipe_connect('ncacn_np:win2k3dc',
	dcerpc.DCERPC_SAMR_UUID, dcerpc.DCERPC_SAMR_VERSION,
	'win2k3dom', 'administrator', 'penguin')

test_Connect(pipe)

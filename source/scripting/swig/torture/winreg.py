#!/usr/bin/python

import dcerpc

def test_OpenHKLM(pipe):

    r = {}
    r['unknown'] = {}
    r['unknown']['unknown0'] = 0x84e0
    r['unknown']['unknown1'] = 0
    r['access_required'] = 0x02000000

    dcerpc.winreg_OpenHKLM(pipe, r)

def runtests(binding, domain, username, password):
    
    print 'Testing WINREG pipe'

    pipe = dcerpc.pipe_connect(binding,
            dcerpc.DCERPC_WINREG_UUID, dcerpc.DCERPC_WINREG_VERSION,
            domain, username, password)

    test_OpenHKLM(pipe)

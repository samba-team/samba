#!/usr/bin/python

import dcerpc
from optparse import OptionParser

def test_Connect(handle):

    print 'testing samr_Connect'

    r = {}
    r['system_name'] = [0]
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

    r = {}
    r['handle'] = handle
    r['sec_info'] = 7
    r['sdbuf'] = result['sdbuf']

    result = dcerpc.samr_SetSecurity(pipe, r)

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

print 'Done'

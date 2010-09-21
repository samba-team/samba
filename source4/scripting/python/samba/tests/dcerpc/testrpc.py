#!/usr/bin/env python
#
# test generated python code from pidl
# Andrew Tridgell August 2010
#
import sys

sys.path.insert(0, "bin/python")

import samba
import samba.tests
from samba.dcerpc import drsuapi

samba.talloc_enable_null_tracking()

class RpcTests(samba.tests.TestCase):
    '''test type behaviour of pidl generated python RPC code'''

    def check_blocks(self, object, num_expected):
        '''check that the number of allocated blocks is correct'''
        nblocks = samba.talloc_total_blocks(object)
        if object is None:
            nblocks -= self.initial_blocks
        #print nblocks, num_expected)

    def check_type(self, interface, typename, type):
        print "Checking type %s" % typename
        v = type()
        for n in dir(v):
            if n[0] == '_':
                continue
            try:
                value = getattr(v, n)
            except TypeError, errstr:
                if str(errstr) == "unknown union level":
                    print "ERROR: Unknown union level in %s.%s" % (typename, n)
                    self.errcount += 1
                    continue
                print str(errstr)[1:21]
                if str(errstr)[0:21] == "Can not convert C Type":
                    print "ERROR: Unknown C type for %s.%s" % (typename, n)
                    self.errcount += 1
                    continue
                else:
                    print "ERROR: Failed to instantiate %s.%s" % (typename, n)
                    raise
            except:
                print "ERROR: Failed to instantiate %s.%s" % (typename, n)
                raise

            # now try setting the value back
            try:
                print "Setting %s.%s" % (typename, n)
                setattr(v, n, value)
            except:
                print "ERROR: Failed to set %s.%s" % (typename, n)
                raise

            # and try a comparison
            try:
                if value != getattr(v, n):
                    print "ERROR: Comparison failed for %s.%s" % (typename, n)
                    raise
            except:
                print "ERROR: compare exception for %s.%s" % (typename, n)
                raise


    def check_interface(self, interface, iname):
        errcount = self.errcount
        for n in dir(interface):
            if n[0] == '_' or n == iname:
                # skip the special ones
                continue
            value = getattr(interface, n)
            if isinstance(value, str):
                #print "%s=\"%s\"" % (n, value)
                pass
            elif isinstance(value, int):
                #print "%s=%d" % (n, value)
                pass
            elif isinstance(value, type):
                try:
                    initial_blocks = samba.talloc_total_blocks(None)
                    self.check_type(interface, n, value)
                    self.check_blocks(None, initial_blocks)
                except:
                    print "ERROR: Failed to check_type %s.%s" % (iname, n)
                    self.errcount += 1
                    pass
            else:
                print "UNKNOWN: %s=%s" % (n, value)
        if self.errcount - errcount != 0:
            print "Found %d errors in %s" % (self.errcount - errcount, iname)


    def check_all_interfaces(self):
        for iname in dir(samba.dcerpc):
            if iname[0] == '_':
                continue
            if iname == 'ClientConnection' or iname == 'base':
                continue
            print "Checking interface %s" % iname
            iface = getattr(samba.dcerpc, iname)
            initial_blocks = samba.talloc_total_blocks(None)
            self.check_interface(iface, iname)
            self.check_blocks(None, initial_blocks)

    def test_run(self):
        self.initial_blocks = samba.talloc_total_blocks(None)
        self.errcount = 0
        self.check_all_interfaces()
        self.assertEquals(self.errcount, 0)

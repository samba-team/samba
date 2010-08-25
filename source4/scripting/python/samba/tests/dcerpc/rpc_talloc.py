#!/usr/bin/env python
# test generated python code from pidl

import sys

sys.path.insert(0, "bin/python")

import samba
from samba.dcerpc import drsuapi

samba.talloc_enable_null_tracking()
initial_blocks = samba.talloc_total_blocks(None)

def check_blocks(object, num_expected):
    nblocks = samba.talloc_total_blocks(object)
    if object is None:
        nblocks -= initial_blocks
    if nblocks != num_expected:
        raise Exception("Expected %u blocks in %s - got %u" % (num_expected, str(object), nblocks))

check_blocks(None, 0)

def get_rodc_partial_attribute_set():
    '''get a list of attributes for RODC replication'''
    partial_attribute_set = drsuapi.DsPartialAttributeSet()

    # we expect one block for the object, and one for the structure
    check_blocks(partial_attribute_set, 2)

    attids = [ 1, 2, 3]
    partial_attribute_set.version = 1
    partial_attribute_set.attids     = attids
    partial_attribute_set.num_attids = len(attids)

    # we expect one block object, a structure, an ARRAY, and a reference to the array
    check_blocks(partial_attribute_set, 4)

    return partial_attribute_set

def test_fun():
    pas = get_rodc_partial_attribute_set()
    check_blocks(pas, 4)
    req8 = drsuapi.DsGetNCChangesRequest8()
    check_blocks(req8, 2)
    check_blocks(None, 6)
    req8.partial_attribute_set = pas
    if req8.partial_attribute_set.attids[1] != 2:
        raise Exception("Wrong value in attids[2]")
    # we now get an additional reference
    samba.talloc_report_full(None)
    check_blocks(None, 7)

test_fun()
check_blocks(None, 0)
print "All OK"
sys.exit(0)

#!/usr/bin/env python

# work out what python external libraries we need to install
external_libs = {
    "dns.resolver": "dnspython/dns", 
    "subunit": "subunit/python/subunit",
    "testtools": "testtools/testtools"}

list = []

for module, package in external_libs.iteritems():
    try:
        __import__(module)
    except ImportError:
        list.append(package)

print ' '.join(list)

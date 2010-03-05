#!/usr/bin/python

# work out what python external libraries we need to install

list = []

try:
    import dns.resolver
except:
    list.append("dnspython")

print ' '.join(list)

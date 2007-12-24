#!/usr/bin/python
#
#  tool to manipulate a remote registry
#  Copyright Andrew Tridgell 2005
#  Copyright Jelmer Vernooij 2007
#  Released under the GNU GPL v3 or later
#

import sys

options = GetOptions(ARGV,
			 "POPT_AUTOHELP",
			 "POPT_COMMON_SAMBA",
			 "POPT_COMMON_CREDENTIALS",
			 "createkey=s")
if (options == undefined) {
	print "Failed to parse options"
	sys.exit(-1)

if len(sys.argv < 2:
	print "Usage: %s <BINDING> [path]" % sys.argv[0]
	sys.exit(-1)

binding = options.ARGV[0]
reg = winregObj()

print "Connecting to " + binding
status = reg.connect(binding)
if (status.is_ok != true) {
	print("Failed to connect to " + binding + " - " + status.errstr + "\n")
	return -1
}

def list_values(path):
	list = reg.enum_values(path)
	if (list == undefined) {
		return
	}
	for (i=0;i<list.length;i++) {
		v = list[i]
		printf("\ttype=%-30s size=%4d  '%s'\n", reg.typestring(v.type), v.size, v.name)
		if (v.type == reg.REG_SZ || v.type == reg.REG_EXPAND_SZ) {
			printf("\t\t'%s'\n", v.value)
		}
		if (v.type == reg.REG_MULTI_SZ) {
			for (j in v.value) {
				printf("\t\t'%s'\n", v.value[j])
			}
		}
		if (v.type == reg.REG_DWORD || v.type == reg.REG_DWORD_BIG_ENDIAN) {
			printf("\t\t0x%08x (%d)\n", v.value, v.value)
		}
		if (v.type == reg.REG_QWORD) {
			printf("\t\t0x%llx (%lld)\n", v.value, v.value)
		}
	}

def list_path(path):
	count = 0
	list = reg.enum_path(path)
	if (list == undefined) {
		println("Unable to list " + path)
		return 0
	}
	list_values(path)
	count = count + list.length
	for (i=0;i<list.length;i++) {
		if (path) {
			npath = path + "\\" + list[i]
		} else {
			npath = list[i]
		}
		println(npath)
		count = count + list_path(npath)
	}
	return count

if len(sys.argv) > 2:
	root = sys.argv[2]
else:
	root = ''

if options.createkey:
    try:
	    reg.create_key("HKLM\\SOFTWARE", options.createkey)
    except:
		print "Failed to create key"
else:
	printf("Listing registry tree '%s'\n", root)
	count = list_path(root)
    if count == 0:
		println("No entries found")
		sys.exit(1)

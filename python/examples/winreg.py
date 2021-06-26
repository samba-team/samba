#!/usr/bin/env python3
#
#  tool to manipulate a remote registry
#  Copyright Andrew Tridgell 2005
#  Copyright Jelmer Vernooij 2007
#  Released under the GNU GPL v3 or later
#

import sys

# Find right directory when running from source tree
sys.path.insert(0, "bin/python")

from samba.dcerpc import winreg,misc
import optparse
import samba.getopt as options

parser = optparse.OptionParser("%s <BINDING> [path]" % sys.argv[0])
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option("--createkey", type="string", metavar="KEYNAME",
                  help="create a key")

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(-1)

binding = args[0]

print("Connecting to " + binding)
conn = winreg.winreg(binding, sambaopts.get_loadparm())

def list_values(key):
    (num_values, max_valnamelen, max_valbufsize) = conn.QueryInfoKey(key, winreg.String())[4:7]
    for i in range(num_values):
        name = winreg.ValNameBuf()
        name.size = max_valnamelen
        (name, type, data, _, data_len) = conn.EnumValue(key, i, name, 0, [], max_valbufsize, 0)
        print("\ttype=%-30s size=%4d  '%s'" % (type, name.size, name))
        if type in (misc.REG_SZ, misc.REG_EXPAND_SZ):
            print("\t\t'%s'" % data)


def list_path(key, path):
    count = 0
    (num_subkeys, max_subkeylen, max_classlen) = conn.QueryInfoKey(key, winreg.String())[1:4]
    for i in range(num_subkeys):
        name = winreg.StringBuf()
        name.size = max_subkeylen+2 # utf16 0-terminator
        keyclass = winreg.StringBuf()
        keyclass.size = max_classlen+2 # utf16 0-terminator
        (name, _, _) = conn.EnumKey(key, i, name, keyclass=keyclass, last_changed_time=None)
        name2 = winreg.String()
        name2.name = name.name
        subkey = conn.OpenKey(key, name2, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_ENUMERATE_SUB_KEYS)
        count += list_path(subkey, "%s\\%s" % (path, name))
        list_values(subkey)
    return count


if len(args) > 1:
    root = args[1]
else:
    root = "HKLM"

if opts.createkey:
    name = winreg.String()
    name.name = "SOFTWARE"

    # Just sample code, "HKLM\SOFTWARE" should already exist

    root = conn.OpenHKLM(
        None, winreg.KEY_QUERY_VALUE | winreg.KEY_ENUMERATE_SUB_KEYS)
    conn.CreateKey(
        root,
        name,
        keyclass=winreg.String(),
        options=0,
        access_mask=0,
        secdesc=None,
        action_taken=0)
else:
    print("Listing registry tree '%s'" % root)
    try:
        root_key = getattr(conn, "Open%s" % root)(None, winreg.KEY_QUERY_VALUE | winreg.KEY_ENUMERATE_SUB_KEYS)
    except AttributeError:
        print("Unknown root key name %s" % root)
        sys.exit(1)
    count = list_path(root_key, root)
    if count == 0:
        print("No entries found")
        sys.exit(1)

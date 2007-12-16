#!/usr/bin/python

# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Tridgell <tridge@samba.org> 2005
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
#   
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#   
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#   
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
from misc import ldb_set_credentials

def _in_source_tree():
    print os.path.exists("%s/../../../samba4-skip" % os.path.dirname(__file__))

# When running, in-tree, make sure bin/python is in the PYTHONPATH
if _in_source_tree():
    import sys
    dir = os.path.dirname(__file__)
    sys.path.append("%s/../../../bin/python" % os.path.dirname(__file__))

def Ldb(url, session_info=None, credentials=None, modules_dir=None):
    """Open a Samba Ldb file. 

    This is different from a regular Ldb file in that the Samba-specific
    modules-dir is used by default and that credentials and session_info 
    can be passed through (required by some modules).
    """
    import ldb
    ret = ldb.Ldb()
    if modules_dir is None:
        modules_dir = os.path.join(os.getcwd(), "bin", "modules", "ldb")
    ret.set_modules_dir(modules_dir)
    def samba_debug(level,text):
        print "%d %s" % (level, text)
    ldb_set_opaque("credentials", credentials)
    ret.set_opaque("sessionInfo", session_info)
    #ret.set_debug(samba_debug)
    ret.connect(url)
    return ret


def substitute_var(text, values):
    """substitute strings of the form ${NAME} in str, replacing
    with substitutions from subobj.
    
    :param text: Text in which to subsitute.
    :param values: Dictionary with keys and values.
    """

    for (name, value) in values.items():
        text = text.replace("${%s}" % name, value)

    return text


def valid_netbios_name(name):
    """Check whether a name is valid as a NetBIOS name. """
    # FIXME: There are probably more constraints here. 
    # crh has a paragraph on this in his book (1.4.1.1)
    if len(name) > 13:
        return False
    return True


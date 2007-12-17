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

def _in_source_tree():
    """Check whether the script is being run from the source dir. """
    return os.path.exists("%s/../../../samba4-skip" % os.path.dirname(__file__))


# When running, in-tree, make sure bin/python is in the PYTHONPATH
if _in_source_tree():
    import sys
    srcdir = "%s/../../.." % os.path.dirname(__file__)
    sys.path.append("%s/bin/python" % srcdir)
    default_ldb_modules_dir = "%s/bin/modules/ldb" % srcdir


import misc
import ldb
ldb.Ldb.set_credentials = misc.ldb_set_credentials
ldb.Ldb.set_session_info = misc.ldb_set_session_info
ldb.Ldb.set_loadparm = misc.ldb_set_loadparm

class Ldb(ldb.Ldb):
    """Simple Samba-specific LDB subclass that takes care 
    of setting up the modules dir, credentials pointers, etc.
    
    Please note that this is intended to be for all Samba LDB files, 
    not necessarily the Sam database. For Sam-specific helper 
    functions see samdb.py.
    """
    def __init__(url, session_info=None, credentials=None, modules_dir=None, 
            lp=None):
        """Open a Samba Ldb file. 

        :param url: LDB Url to open
        :param session_info: Optional session information
        :param credentials: Optional credentials, defaults to anonymous.
        :param modules_dir: Modules directory, automatically set if not specified.
        :param lp: Loadparm object, optional.

        This is different from a regular Ldb file in that the Samba-specific
        modules-dir is used by default and that credentials and session_info 
        can be passed through (required by some modules).
        """
        super(self, Ldb).__init__()
        import ldb
        ret = ldb.Ldb()
        if modules_dir is None:
            modules_dir = default_ldb_modules_dir
        if modules_dir is not None:
            ret.set_modules_dir(modules_dir)
        def samba_debug(level,text):
            print "%d %s" % (level, text)
        if credentials is not None:
            ldb.set_credentials(credentials)
        if session_info is not None:
            ldb.set_session_info(session_info)
        if lp is not None:
            ldb.set_loadparm(lp)
        #ret.set_debug(samba_debug)
        ret.connect(url)
        return ret

    def searchone(self, basedn, expression, attribute):
        """Search for one attribute as a string."""
        res = self.search(basedn, SCOPE_SUBTREE, expression, [attribute])
        if len(res) != 1 or res[0][attribute] is None:
            return None
        return res[0][attribute]

    def erase(self):
        """Erase an ldb, removing all records."""
        # delete the specials
        for attr in ["@INDEXLIST", "@ATTRIBUTES", "@SUBCLASSES", "@MODULES", 
                     "@OPTIONS", "@PARTITION", "@KLUDGEACL"]:
            try:
                self.delete(Dn(self, attr))
            except LdbError, (LDB_ERR_NO_SUCH_OBJECT, _):
                # Ignore missing dn errors
                pass

        basedn = Dn(self, "")
        # and the rest
        for msg in self.search(basedn, SCOPE_SUBTREE, 
                "(&(|(objectclass=*)(dn=*))(!(dn=@BASEINFO)))", 
                ["dn"]):
            self.delete(msg.dn)

        res = self.search(basedn, SCOPE_SUBTREE, "(&(|(objectclass=*)(dn=*))(!(dn=@BASEINFO)))", ["dn"])
        assert len(res) == 0


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



# Unix SMB/CIFS implementation.
# utility functions for provisioning a Samba4 server

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2010
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008-2009
# Copyright (C) Oliver Liebel <oliver@itc.li> 2008-2009
#
# Based on the original in EJS:
# Copyright (C) Andrew Tridgell <tridge@samba.org> 2005
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

"""Functions for setting up a Samba configuration."""

__docformat__ = "restructuredText"

import os
from samba import read_and_sub_file
from samba.param import setup_dir

FILL_FULL = "FULL"
FILL_SUBDOMAIN = "SUBDOMAIN"
FILL_NT4SYNC = "NT4SYNC"
FILL_DRS = "DRS"


def setup_path(file):
    """Return an absolute path to the provision tempate file specified by file"""
    return os.path.join(setup_dir(), file)


def setup_add_ldif(ldb, ldif_path, subst_vars=None, controls=["relax:0"]):
    """Setup a ldb in the private dir.

    :param ldb: LDB file to import data into
    :param ldif_path: Path of the LDIF file to load
    :param subst_vars: Optional variables to subsitute in LDIF.
    :param nocontrols: Optional list of controls, can be None for no controls
    """
    assert isinstance(ldif_path, str)
    data = read_and_sub_file(ldif_path, subst_vars)
    ldb.add_ldif(data, controls)


def setup_modify_ldif(ldb, ldif_path, subst_vars=None, controls=["relax:0"]):
    """Modify a ldb in the private dir.

    :param ldb: LDB object.
    :param ldif_path: LDIF file path.
    :param subst_vars: Optional dictionary with substitution variables.
    """
    data = read_and_sub_file(ldif_path, subst_vars)
    ldb.modify_ldif(data, controls)


def setup_ldb(ldb, ldif_path, subst_vars):
    """Import a LDIF a file into a LDB handle, optionally substituting
    variables.

    :note: Either all LDIF data will be added or none (using transactions).

    :param ldb: LDB file to import into.
    :param ldif_path: Path to the LDIF file.
    :param subst_vars: Dictionary with substitution variables.
    """
    assert ldb is not None
    ldb.transaction_start()
    try:
        setup_add_ldif(ldb, ldif_path, subst_vars)
    except:
        ldb.transaction_cancel()
        raise
    else:
        ldb.transaction_commit()

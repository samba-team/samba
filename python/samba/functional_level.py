# domain management - common code
#
# Copyright Catlayst .Net Ltd 2017-2023
# Copyright Jelmer Vernooij 2007-2012
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

from samba.dsdb import (
    DS_DOMAIN_FUNCTION_2000,
    DS_DOMAIN_FUNCTION_2003,
    DS_DOMAIN_FUNCTION_2008,
    DS_DOMAIN_FUNCTION_2008_R2,
    DS_DOMAIN_FUNCTION_2012,
    DS_DOMAIN_FUNCTION_2012_R2,
    DS_DOMAIN_FUNCTION_2003_MIXED,
    DS_DOMAIN_FUNCTION_2016
)

string_version_to_constant = {
    "2000": DS_DOMAIN_FUNCTION_2000,
    "2003": DS_DOMAIN_FUNCTION_2003,
    "2008": DS_DOMAIN_FUNCTION_2008,
    "2008_R2": DS_DOMAIN_FUNCTION_2008_R2,
    "2012": DS_DOMAIN_FUNCTION_2012,
    "2012_R2": DS_DOMAIN_FUNCTION_2012_R2,
    "2016": DS_DOMAIN_FUNCTION_2016,
}


def string_to_level(string):
    """Interpret a string indicating a functional level."""
    return string_version_to_constant[string]


def level_to_string(level):
    """turn the level enum number into a printable string."""
    if level < DS_DOMAIN_FUNCTION_2000:
        return "invalid"
    strings = {
        DS_DOMAIN_FUNCTION_2000: "2000",
        DS_DOMAIN_FUNCTION_2003_MIXED: \
            "2003 with mixed domains/interim (NT4 DC support)",
        DS_DOMAIN_FUNCTION_2003: "2003",
        DS_DOMAIN_FUNCTION_2008: "2008",
        DS_DOMAIN_FUNCTION_2008_R2: "2008 R2",
        DS_DOMAIN_FUNCTION_2012: "2012",
        DS_DOMAIN_FUNCTION_2012_R2: "2012 R2",
        DS_DOMAIN_FUNCTION_2016: "2016",
    }
    return strings.get(level, "higher than 2016")

def dc_level_from_lp(lp):
    """Return the ad dc functional level as an integer from a LoadParm"""

    # I don't like the RuntimeError here, but these "can't happen"
    # except by a developer stuffup.

    smb_conf_dc_functional_level = lp.get('ad dc functional level')
    if smb_conf_dc_functional_level is None:
        # This shouldn't be possible, except if the default option
        # value is not in the loadparm enum table
        raise RuntimeError(f"'ad dc functional level' in smb.conf unrecognised!")

    try:
        return string_to_level(smb_conf_dc_functional_level)
    except KeyError:
        # This shouldn't be possible at all, unless the table in
        # python/samba/functional_level.py is not a superset of that
        # in lib/param/param_table.c
        raise RuntimeError(f"'ad dc functional level = {smb_conf_dc_functional_level}'"
                           " in smb.conf is not valid!")

#!/usr/bin/python

# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Tridgell 2010
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

import os, sys

def dns_resolver():
    '''try and import the dns.resolver library, and if it fails
    then use a local copy from the external directory'''

    try:
        import dns.resolver as dns
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../../lib/dnspython"))
        import dns.resolver as dns
    return dns

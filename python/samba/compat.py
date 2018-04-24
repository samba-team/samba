# module which helps with porting to Python 3
#
# Copyright (C) Lumir Balhar <lbalhar@redhat.com> 2017
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

"""module which helps with porting to Python 3"""

import sys

PY3 = sys.version_info[0] == 3

if PY3:
    # compat functions
    from  urllib.parse import quote as urllib_quote
    from urllib.request import urlopen as urllib_urlopen

    # compat types
    integer_types = int,
    string_types = str
    text_type = str
    binary_type = bytes

    # alias
    import io
    StringIO = io.StringIO
else:
    # compat functions
    from urllib import quote as urllib_quote
    from urllib import urlopen as urllib_urlopen

    # compat types
    integer_types = (int, long)
    string_types = basestring
    text_type = unicode
    binary_type = str

    # alias
    import StringIO
    StringIO = StringIO.StringIO

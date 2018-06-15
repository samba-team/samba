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
    def cmp_fn(x, y):
        """
        Replacement for built-in function cmp that was removed in Python 3

        Compare the two objects x and y and return an integer according to
        the outcome. The return value is negative if x < y, zero if x == y
        and strictly positive if x > y.
        """

        return (x > y) - (x < y)
    # compat functions
    from  urllib.parse import quote as urllib_quote
    from urllib.request import urlopen as urllib_urlopen
    from functools import cmp_to_key as cmp_to_key_fn

    # compat types
    integer_types = int,
    string_types = str
    text_type = str
    binary_type = bytes

    # alias
    import io
    StringIO = io.StringIO
else:

    if sys.version_info < (2, 7):
        def cmp_to_key_fn(mycmp):

            """Convert a cmp= function into a key= function"""
            class K(object):
                __slots__ = ['obj']

                def __init__(self, obj, *args):
                    self.obj = obj

                def __lt__(self, other):
                    return mycmp(self.obj, other.obj) < 0

                def __gt__(self, other):
                    return mycmp(self.obj, other.obj) > 0

                def __eq__(self, other):
                    return mycmp(self.obj, other.obj) == 0

                def __le__(self, other):
                    return mycmp(self.obj, other.obj) <= 0

                def __ge__(self, other):
                    return mycmp(self.obj, other.obj) >= 0

                def __ne__(self, other):
                    return mycmp(self.obj, other.obj) != 0

                def __hash__(self):
                    raise TypeError('hash not implemented')
            return K
    else:
        from functools import cmp_to_key as cmp_to_key_fn
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
    cmp_fn = cmp

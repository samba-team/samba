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
    # Sometimes in PY3 we have variables whose content can be 'bytes' or
    # 'str' and we can't be sure which. Generally this is because the
    # code variable can be initialised (or reassigned) a value from different
    # api(s) or functions depending on complex conditions or logic. Or another
    # common case is in PY2 the variable is 'type <str>' and in PY3 it is
    # 'class <str>' and the function to use e.g. b64encode requires 'bytes'
    # in PY3. In such cases it would be nice to avoid excessive testing in
    # the client code. Calling such a helper function should be avoided
    # if possible but sometimes this just isn't possible.
    # If a 'str' object is passed in it is encoded using 'utf8' or if 'bytes'
    # is passed in it is returned unchanged.
    # Using this function is PY2/PY3 code should ensure in most cases
    # the PY2 code runs unchanged in PY2 whereas the code in PY3 possibly
    # encodes the variable (see PY2 implementation of this function below)
    def get_bytes(bytesorstring):
        tmp = bytesorstring
        if isinstance(bytesorstring, str):
            tmp = bytesorstring.encode('utf8')
        elif not isinstance(bytesorstring, bytes):
            raise ValueError('Expected byte or string for %s:%s' % (type(bytesorstring), bytesorstring))
        return tmp

    # helper function to get a string from a variable that maybe 'str' or
    # 'bytes' if 'bytes' then it is decoded using 'utf8'. If 'str' is passed
    # it is returned unchanged
    # Using this function is PY2/PY3 code should ensure in most cases
    # the PY2 code runs unchanged in PY2 whereas the code in PY3 possibly
    # decodes the variable (see PY2 implementation of this function below)
    def get_string(bytesorstring):
        tmp = bytesorstring
        if isinstance(bytesorstring, bytes):
            tmp = bytesorstring.decode('utf8')
        elif not isinstance(bytesorstring, str):
            raise ValueError('Expected byte of string for %s:%s' % (type(bytesorstring), bytesorstring))
        return tmp

    def cmp_fn(x, y):
        """
        Replacement for built-in function cmp that was removed in Python 3

        Compare the two objects x and y and return an integer according to
        the outcome. The return value is negative if x < y, zero if x == y
        and strictly positive if x > y.
        """

        return (x > y) - (x < y)
    # compat functions
    from functools import cmp_to_key as cmp_to_key_fn


else:
    raise NotImplementedError("Samba versions >= 4.11 do not support Python 2.x")

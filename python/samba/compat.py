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

    # compat types
    integer_types = int,
    string_types = str
    text_type = str
    binary_type = bytes

    # alias
    import io
    StringIO = io.StringIO
    def ConfigParser(defaults=None, dict_type=dict, allow_no_value=False):
        from configparser import ConfigParser
        return ConfigParser(defaults, dict_type, allow_no_value, interpolation=None)
else:
    # Helper function to return bytes.
    # if 'unicode' is passed in then it is decoded using 'utf8' and
    # the result returned. If 'str' is passed then it is returned unchanged.
    # Using this function is PY2/PY3 code should ensure in most cases
    # the PY2 code runs unchanged in PY2 whereas the code in PY3 possibly
    # encodes the variable (see PY3 implementation of this function above)
    def get_bytes(bytesorstring):
        tmp = bytesorstring
        if isinstance(bytesorstring, unicode):
            tmp = bytesorstring.encode('utf8')
        elif not isinstance(bytesorstring, str):
            raise ValueError('Expected string for %s:%s' % (type(bytesorstring), bytesorstring))
        return tmp

    # Helper function to return string.
    # if 'str' or 'unicode' passed in they are returned unchanged
    # otherwise an exception is generated
    # Using this function is PY2/PY3 code should ensure in most cases
    # the PY2 code runs unchanged in PY2 whereas the code in PY3 possibly
    # decodes the variable (see PY3 implementation of this function above)
    def get_string(bytesorstring):
        tmp = bytesorstring
        if not(isinstance(bytesorstring, str) or isinstance(bytesorstring, unicode)):
            raise ValueError('Expected str or unicode for %s:%s' % (type(bytesorstring), bytesorstring))
        return tmp


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

    # compat types
    integer_types = (int, long)
    string_types = basestring
    text_type = unicode
    binary_type = str

    # alias
    import cStringIO
    StringIO = cStringIO.StringIO
    from ConfigParser import ConfigParser
    cmp_fn = cmp

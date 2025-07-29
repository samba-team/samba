# Samba common functions
#
# Copyright (C) Matthieu Patou <mat@matws.net>
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
#


def cmp(x, y):
    """
    Replacement for built-in function cmp that was removed in Python 3

    Compare the two objects x and y and return an integer according to
    the outcome. The return value is negative if x < y, zero if x == y
    and strictly positive if x > y.
    """

    return (x > y) - (x < y)


def confirm(msg, forced=False, allow_all=False):
    """confirm an action with the user

    :param msg: A string to print to the user
    :param forced: Are the answer forced
    """
    if forced:
        print("%s [YES]" % msg)
        return True

    mapping = {
        'Y': True,
        'YES': True,
        '': False,
        'N': False,
        'NO': False,
    }

    prompt = '[y/N]'

    if allow_all:
        mapping['ALL'] = 'ALL'
        mapping['NONE'] = 'NONE'
        prompt = '[y/N/all/none]'

    while True:
        v = input(msg + ' %s ' % prompt)
        v = v.upper()
        if v in mapping:
            return mapping[v]
        print("Unknown response '%s'" % v)


def normalise_int32(ivalue):
    """normalise a ldap integer to signed 32 bit"""
    ivalue = int(ivalue)
    if ivalue > 0xffffffff or ivalue < -0x80000000:
        raise ValueError(f"{ivalue} (0x{ivalue:x}) does not fit in 32 bits.")
    if ivalue >= 0x80000000:
        return str(int(ivalue) - 0x100000000)
    return str(ivalue)


# Sometimes we have variables whose content can be 'bytes' or
# 'str' and we can't be sure which. Generally this is because the
# code variable can be initialised (or reassigned) a value from different
# api(s) or functions depending on complex conditions or logic.
# If a 'str' object is passed in it is encoded using 'utf8' or if 'bytes'
# is passed in it is returned unchanged.
def get_bytes(bytesorstring):
    tmp = bytesorstring
    if isinstance(bytesorstring, str):
        tmp = bytesorstring.encode('utf8')
    elif not isinstance(bytesorstring, bytes):
        raise ValueError('Expected bytes or string for %s:%s' % (type(bytesorstring), bytesorstring))
    return tmp

# helper function to get a string from a variable that maybe 'str' or
# 'bytes' if 'bytes' then it is decoded using 'utf8'. If 'str' is passed
# it is returned unchanged
def get_string(bytesorstring):
    tmp = bytesorstring
    if isinstance(bytesorstring, bytes):
        tmp = bytesorstring.decode('utf8')
    elif not isinstance(bytesorstring, str):
        raise ValueError('Expected bytes or string for %s:%s' % (type(bytesorstring), bytesorstring))
    return tmp

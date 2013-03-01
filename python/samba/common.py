# Samba common functions
#
# Copyright (C) Matthieu Patou <mat@matws.net>
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


import ldb
import dsdb


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
        v = raw_input(msg + ' %s ' % prompt)
        v = v.upper()
        if v in mapping:
            return mapping[v]
        print("Unknown response '%s'" % v)


def normalise_int32(ivalue):
    '''normalise a ldap integer to signed 32 bit'''
    if int(ivalue) & 0x80000000 and int(ivalue) > 0:
        return str(int(ivalue) - 0x100000000)
    return str(ivalue)


class dsdb_Dn(object):
    '''a class for binary DN'''

    def __init__(self, samdb, dnstring, syntax_oid=None):
        '''create a dsdb_Dn'''
        if syntax_oid is None:
            # auto-detect based on string
            if dnstring.startswith("B:"):
                syntax_oid = dsdb.DSDB_SYNTAX_BINARY_DN
            elif dnstring.startswith("S:"):
                syntax_oid = dsdb.DSDB_SYNTAX_STRING_DN
            else:
                syntax_oid = dsdb.DSDB_SYNTAX_OR_NAME
        if syntax_oid in [dsdb.DSDB_SYNTAX_BINARY_DN, dsdb.DSDB_SYNTAX_STRING_DN]:
            # it is a binary DN
            colons = dnstring.split(':')
            if len(colons) < 4:
                raise RuntimeError("Invalid DN %s" % dnstring)
            prefix_len = 4 + len(colons[1]) + int(colons[1])
            self.prefix = dnstring[0:prefix_len]
            self.binary = self.prefix[3+len(colons[1]):-1]
            self.dnstring = dnstring[prefix_len:]
        else:
            self.dnstring = dnstring
            self.prefix = ''
            self.binary = ''
        self.dn = ldb.Dn(samdb, self.dnstring)

    def __str__(self):
        return self.prefix + str(self.dn.extended_str(mode=1))

    def get_binary_integer(self):
        '''return binary part of a dsdb_Dn as an integer, or None'''
        if self.prefix == '':
            return None
        return int(self.binary, 16)

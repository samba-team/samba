# GPO Parser for generic extensions
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
# Written by Garming Sam <garming@catalyst.net.nz>
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

from xml.dom import minidom
from io import BytesIO
from xml.etree.ElementTree import ElementTree

class GPNoParserException(Exception):
    pass

# [MS-GPIPSEC] (LDAP)
# [MS-GPDPC] Deployed Printer Connections (LDAP)
# [MS-GPPREF] Preferences Extension (XML)
# [MS-GPWL] Wireless/Wired Protocol Extension (LDAP)
class GPParser(object):
    encoding = 'utf-16'
    output_encoding = 'utf-8'

    def parse(self, contents):
        pass

    def write_xml(self, filename):
        with file(filename, 'w') as f:
            f.write('<?xml version="1.0" encoding="utf-8"?><UnknownFile/>')

    def load_xml(self, filename):
        pass

    def write_binary(self, filename):
        raise GPNoParserException("This file has no parser available.")

    def write_pretty_xml(self, xml_element, handle):
        # Add the xml header as well as format it nicely.
        # ElementTree doesn't have a pretty-print, so use minidom.

        et = ElementTree(xml_element)
        temporary_bytes = BytesIO()
        et.write(temporary_bytes, encoding=self.output_encoding,
                 xml_declaration=True)
        minidom_parsed = minidom.parseString(temporary_bytes.getvalue())
        handle.write(minidom_parsed.toprettyxml(encoding=self.output_encoding))

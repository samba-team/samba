# GPO Parser for registry extension
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

import base64

from xml.etree.ElementTree import Element, SubElement

from samba.dcerpc import preg
from samba.dcerpc import misc
from samba.ndr import ndr_pack, ndr_unpack

from samba.gp_parse import GPParser

# [MS-GPREG]
# [MS-GPFAS] Firewall and Advanced Security
# [MS-GPEF] Encrypting File System
# [MS-GPNRPT] Name Resolution Table
class GPPolParser(GPParser):
    pol_file = None

    reg_type = {
        misc.REG_NONE: "REG_NONE",
        misc.REG_SZ: "REG_SZ",
        misc.REG_DWORD: "REG_DWORD",
        misc.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
        misc.REG_QWORD: "REG_QWORD",
        misc.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        misc.REG_MULTI_SZ: "REG_MULTI_SZ",
        misc.REG_BINARY: "REG_BINARY"
    }

    def map_reg_type(self, val):
        ret = self.reg_type.get(val)
        if ret is None:
            return "REG_UNKNOWN"
        return ret

    def parse(self, contents):
        self.pol_file = ndr_unpack(preg.file, contents)

    def load_xml(self, root):
        self.pol_file = preg.file()
        self.pol_file.header.signature = root.attrib['signature']
        self.pol_file.header.version = int(root.attrib['version'])
        self.pol_file.num_entries = int(root.attrib['num_entries'])

        entries = []
        for e in root.findall('Entry'):
            entry = preg.entry()
            entry_type = int(e.attrib['type'])

            entry.type = entry_type

            entry.keyname = e.find('Key').text
            value_name = e.find('ValueName').text
            if value_name is None:
                value_name = ''

            entry.valuename = value_name
            # entry.size = int(e.attrib['size'])

            if misc.REG_MULTI_SZ == entry_type:
                values = [x.text for x in e.findall('Value')]
                entry.data = (u'\x00'.join(values) + u'\x00\x00').encode('utf-16le')
            elif (misc.REG_NONE == entry_type):
                pass
            elif (misc.REG_SZ == entry_type or
                  misc.REG_EXPAND_SZ == entry_type):
                string_val = e.find('Value').text
                if string_val is None:
                    string_val = ''
                entry.data = string_val
            elif (misc.REG_DWORD == entry_type or
                  misc.REG_DWORD_BIG_ENDIAN == entry_type or
                  misc.REG_QWORD == entry_type):
                entry.data = int(e.find('Value').text)
            else: # REG UNKNOWN or REG_BINARY
                entry.data = base64.b64decode(e.find('Value').text)

            entries.append(entry)

        self.pol_file.entries = entries
        # print self.pol_file.__ndr_print__()

    def write_xml(self, filename):
        with open(filename, 'wb') as f:
            root = Element('PolFile')
            root.attrib['num_entries'] = str(self.pol_file.num_entries)
            root.attrib['signature'] = self.pol_file.header.signature
            root.attrib['version'] = str(self.pol_file.header.version)
            for entry in self.pol_file.entries:
                child = SubElement(root, 'Entry')
                # child.attrib['size'] = str(entry.size)
                child.attrib['type'] = str(entry.type)
                child.attrib['type_name'] = self.map_reg_type(entry.type)
                key = SubElement(child, 'Key')
                key.text = entry.keyname
                valuename = SubElement(child, 'ValueName')
                valuename.text = entry.valuename
                if misc.REG_MULTI_SZ == entry.type:
                    multi = entry.data.decode('utf-16').rstrip(u'\x00').split(u'\x00')
                    # print repr(multi)
                    for m in multi:
                        value = SubElement(child, 'Value')
                        value.text = m
                    # print tostring(value)
                elif (misc.REG_NONE == entry.type or
                      misc.REG_SZ == entry.type or
                      misc.REG_DWORD == entry.type or
                      misc.REG_DWORD_BIG_ENDIAN == entry.type or
                      misc.REG_QWORD == entry.type or
                      misc.REG_EXPAND_SZ == entry.type):
                    value = SubElement(child, 'Value')
                    value.text = str(entry.data)
                    # print tostring(value)
                else: # REG UNKNOWN or REG_BINARY
                    value = SubElement(child, 'Value')
                    value.text = base64.b64encode(entry.data).decode('utf8')
                    # print tostring(value)

            # print tostring(root)

            self.write_pretty_xml(root, f)

        # contents = codecs.open(filename, encoding='utf-8').read()
        # self.load_xml(fromstring(contents))

    def write_binary(self, filename):
        with open(filename, 'wb') as f:
            binary_data = ndr_pack(self.pol_file)
            f.write(binary_data)

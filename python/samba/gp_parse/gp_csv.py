# GPO Parser for audit extensions
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

import codecs
import csv
import io

from io import BytesIO
from xml.etree.ElementTree import Element, SubElement
from samba.compat import PY3
from samba.gp_parse import GPParser
from samba.compat import text_type
# [MS-GPAC] Group Policy Audit Configuration
class GPAuditCsvParser(GPParser):
    encoding = 'utf-8'
    header = None
    lines = []

    def parse(self, contents):
        self.lines = []
        reader = csv.reader(codecs.getreader(self.encoding)(BytesIO(contents)))

        self.header = next(reader)
        for row in reader:
            line = {}
            for i, x in enumerate(row):
                line[self.header[i]] = x

            self.lines.append(line)
            # print line

    def write_xml(self, filename):
        with open(filename, 'wb') as f:
            root = Element('CsvFile')
            child = SubElement(root, 'Row')
            for e in self.header:
                value = SubElement(child, 'Value')
                value.text = e

            for line in self.lines:
                child = SubElement(root, 'Row')
                for e, title in [(line[x], x) for x in self.header]:
                    value = SubElement(child, 'Value')
                    value.text = e

                    # Metadata for generalization
                    if title == 'Policy Target' and e != '':
                        value.attrib['user_id'] = 'TRUE'
                    if (title == 'Setting Value' and e != '' and
                        (line['Subcategory'] == 'RegistryGlobalSacl' or
                         line['Subcategory'] == 'FileGlobalSacl')):
                        value.attrib['acl'] = 'TRUE'

            self.write_pretty_xml(root, f)


        # contents = codecs.open(filename, encoding='utf-8').read()
        # self.load_xml(fromstring(contents))

    def load_xml(self, root):
        header = True
        self.lines = []

        for r in root.findall('Row'):
            if header:
                header = False
                self.header = []
                for v in r.findall('Value'):
                    if not isinstance(v.text, text_type):
                        v.text = v.text.decode(self.output_encoding)
                    self.header.append(v.text)
            else:
                line = {}
                for i, v in enumerate(r.findall('Value')):
                    line[self.header[i]] = v.text if v.text is not None else ''
                    if not isinstance(self.header[i], text_type):
                        line[self.header[i]] = line[self.header[i]].decode(self.output_encoding)

                self.lines.append(line)

    def write_binary(self, filename):
        from io import open
        with open(filename, 'w', encoding=self.encoding) as f:
            # In this case "binary" means "utf-8", so we let Python do that.
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(self.header)
            for line in self.lines:
                writer.writerow([line[x] for x in self.header])

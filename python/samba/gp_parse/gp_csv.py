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

from samba.gp_parse import GPParser

# [MS-GPAC] Group Policy Audit Configuration
class GPAuditCsvParser(GPParser):
    encoding = 'utf-8'
    header = None
    lines = []

    def parse(self, contents):
        self.lines = []
        reader = UnicodeReader(BytesIO(contents),
                               encoding=self.encoding)

        self.header = reader.next()
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
                    self.header.append(v.text.decode(self.output_encoding))
            else:
                line = {}
                for i, v in enumerate(r.findall('Value')):
                    line[self.header[i]] = v.text if v.text is not None else ''
                    line[self.header[i]] = line[self.header[i]].decode(self.output_encoding)

                self.lines.append(line)

    def write_binary(self, filename):
        with open(filename, 'wb') as f:
            # This should be using a unicode writer, but it seems to be in the
            # right encoding at least by default.
            #
            # writer = UnicodeWriter(f, quoting=csv.QUOTE_MINIMAL)
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(self.header)
            for line in self.lines:
                writer.writerow([line[x] for x in self.header])


# The following classes come from the Python documentation
# https://docs.python.org/3.0/library/csv.html


class UTF8Recoder:
    """
    Iterator that reads an encoded stream and reencodes the input to UTF-8
    """
    def __init__(self, f, encoding):
        self.reader = codecs.getreader(encoding)(f)

    def __iter__(self):
        return self

    def next(self):
        return next(self.reader).encode("utf-8")

    __next__ = next

class UnicodeReader:
    """
    A CSV reader which will iterate over lines in the CSV file "f",
    which is encoded in the given encoding.
    """

    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        f = UTF8Recoder(f, encoding)
        self.reader = csv.reader(f, dialect=dialect, **kwds)

    def next(self):
        row = next(self.reader)
        return [unicode(s, "utf-8") for s in row]

    def __iter__(self):
        return self

    __next__ = next

class UnicodeWriter:
    """
    A CSV writer which will write rows to CSV file "f",
    which is encoded in the given encoding.
    """

    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        # Redirect output to a queue
        self.queue = io.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwds)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()

    def writerow(self, row):
        self.writer.writerow([s.encode("utf-8") for s in row])
        # Fetch UTF-8 output from the queue ...
        data = self.queue.getvalue()
        data = data.decode("utf-8")
        # ... and reencode it into the target encoding
        data = self.encoder.encode(data)
        # write to the target stream
        self.stream.write(data)
        # empty queue
        self.queue.truncate(0)

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)

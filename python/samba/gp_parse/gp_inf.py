# GPO Parser for security extensions
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
import collections
import re

from abc import ABCMeta, abstractmethod
from xml.etree.ElementTree import Element, SubElement

from samba.gp_parse import GPParser

# [MS-GPSB] Security Protocol Extension
class GptTmplInfParser(GPParser):
    sections = None
    encoding = 'utf-16'
    output_encoding = 'utf-16le'

    class AbstractParam:
        __metaclass__ = ABCMeta

        def __init__(self):
            self.param_list = []

        @abstractmethod
        def parse(self, line):
            pass

        @abstractmethod
        def write_section(self, header, fp):
            pass

        @abstractmethod
        def build_xml(self, xml_parent):
            pass

        @abstractmethod
        def from_xml(self, section):
            pass

    class IniParam(AbstractParam):
        # param_list = [(Key, Value),]

        def parse(self, line):
            key, val = line.split('=')

            self.param_list.append((key.strip(),
                                    val.strip()))

            # print key.strip(), val.strip()

        def write_section(self, header, fp):
            if len(self.param_list) ==  0:
                return
            fp.write(u'[%s]\r\n' % header)
            for key_out, val_out in self.param_list:
                fp.write(u'%s = %s\r\n' % (key_out,
                                           val_out))

        def build_xml(self, xml_parent):
            for key_ini, val_ini in self.param_list:
                child = SubElement(xml_parent, 'Parameter')
                key = SubElement(child, 'Key')
                value = SubElement(child, 'Value')
                key.text = key_ini
                value.text = val_ini

        def from_xml(self, section):
            for param in section.findall('Parameter'):
                key = param.find('Key').text
                value = param.find('Value').text
                if value is None:
                    value = ''

                self.param_list.append((key, value))

    class RegParam(AbstractParam):
        # param_list = [Value, Value, ...]
        def parse(self, line):
            # = can occur in a registry key, so don't parse these
            self.param_list.append(line)
            # print line

        def write_section(self, header, fp):
            if len(self.param_list) ==  0:
                return
            fp.write(u'[%s]\r\n' % header)
            for param in self.param_list:
                fp.write(u'%s\r\n' % param)

        def build_xml(self, xml_parent):
            for val_ini in self.param_list:
                child = SubElement(xml_parent, 'Parameter')
                value = SubElement(child, 'Value')
                value.text = val_ini

        def from_xml(self, section):
            for param in section.findall('Parameter'):
                value = param.find('Value').text
                if value is None:
                    value = ''

                self.param_list.append(value)

    class PrivSIDListParam(AbstractParam):
        # param_list = [(Key, [SID, SID,..]),
        def parse(self, line):
            key, val = line.split('=')

            self.param_list.append((key.strip(),
                                    [x.strip() for x in val.split(',')]))
            # print line

        def write_section(self, header, fp):
            if len(self.param_list) ==  0:
                return
            fp.write(u'[%s]\r\n' % header)
            for key_out, val in self.param_list:
                val_out = u','.join(val)
                fp.write(u'%s = %s\r\n' % (key_out, val_out))

        def build_xml(self, xml_parent):
            for key_ini, sid_list in self.param_list:
                child = SubElement(xml_parent, 'Parameter')
                key = SubElement(child, 'Key')
                key.text = key_ini
                for val_ini in sid_list:
                    value = SubElement(child, 'Value')
                    value.attrib['user_id'] = 'TRUE'
                    value.text = val_ini

        def from_xml(self, section):
            for param in section.findall('Parameter'):
                key = param.find('Key').text

                sid_list = []
                for val in param.findall('Value'):
                    value = val.text
                    if value is None:
                        value = ''

                    sid_list.append(value)

                self.param_list.append((key, sid_list))

    class NameModeACLParam(AbstractParam):
        # param_list = [[Name, Mode, ACL],]
        def parse(self, line):
            parameters = [None, None, None]
            current_arg = 0

            while line != '':
                # Read quoted string
                if line[:1] == '"':
                    line = line[1:]
                    findex = line.find('"')
                    parameters[current_arg] = line[:findex]
                    line = line[findex + 1:]
                # Skip past delimeter
                elif line[:1] == ',':
                    line = line[1:]
                    current_arg += 1
                # Read unquoted string
                else:
                    findex = line.find(',')
                    parameters[current_arg] = line[:findex]
                    line = line[findex:]

            # print parameters
            # print line
            self.param_list.append(parameters)

        def write_section(self, header, fp):
            if len(self.param_list) ==  0:
                return
            fp.write(u'[%s]\r\n' % header)
            for param in self.param_list:
                fp.write(u'"%s",%s,"%s"\r\n' % tuple(param))

        def build_xml(self, xml_parent):
            for name_mode_acl in self.param_list:
                child = SubElement(xml_parent, 'Parameter')

                value = SubElement(child, 'Value')
                value.text = name_mode_acl[0]

                value = SubElement(child, 'Value')
                value.text = name_mode_acl[1]

                value = SubElement(child, 'Value')
                value.attrib['acl'] = 'TRUE'
                value.text = name_mode_acl[2]

        def from_xml(self, section):
            for param in section.findall('Parameter'):
                name_mode_acl = [x.text if x.text else '' for x in param.findall('Value')]
                self.param_list.append(name_mode_acl)

    class MemberSIDListParam(AbstractParam):
        # param_list = [([XXXX, Memberof|Members], [SID, SID...]),...]
        def parse(self, line):
            key, val = line.split('=')

            key = key.strip()

            self.param_list.append((key.split('__'),
                                    [x.strip() for x in val.split(',')]))
            # print line

        def write_section(self, header, fp):
            if len(self.param_list) ==  0:
                return
            fp.write(u'[%s]\r\n' % header)

            for key, val in self.param_list:
                key_out = u'__'.join(key)
                val_out = u','.join(val)
                fp.write(u'%s = %s\r\n' % (key_out, val_out))

        def build_xml(self, xml_parent):
            for key_ini, sid_list in self.param_list:
                child = SubElement(xml_parent, 'Parameter')
                key = SubElement(child, 'Key')
                key.text = key_ini[0]
                key.attrib['member_type'] = key_ini[1]
                key.attrib['user_id'] = 'TRUE'

                for val_ini in sid_list:
                    value = SubElement(child, 'Value')
                    value.attrib['user_id'] = 'TRUE'
                    value.text = val_ini

        def from_xml(self, section):
            for param in section.findall('Parameter'):
                key = param.find('Key')
                member_type = key.attrib['member_type']

                sid_list = []
                for val in param.findall('Value'):
                    value = val.text
                    if value is None:
                        value = ''

                    sid_list.append(value)

                self.param_list.append(([key.text, member_type], sid_list))

    class UnicodeParam(AbstractParam):
        def parse(self, line):
            # print line
            pass

        def write_section(self, header, fp):
            fp.write(u'[Unicode]\r\nUnicode=yes\r\n')

        def build_xml(self, xml_parent):
            # We do not bother storing this field
            pass

        def from_xml(self, section):
            # We do not bother storing this field
            pass

    class VersionParam(AbstractParam):
        def parse(self, line):
            # print line
            pass

        def write_section(self, header, fp):
            out = u'[Version]\r\nsignature="$CHICAGO$"\r\nRevision=1\r\n'
            fp.write(out)

        def build_xml(self, xml_parent):
            # We do not bother storing this field
            pass

        def from_xml(self, section):
            # We do not bother storing this field
            pass

    def parse(self, contents):
        inf_file = contents.decode(self.encoding)

        self.sections = collections.OrderedDict([
            (u'Unicode', self.UnicodeParam()),
            (u'Version', self.VersionParam()),

            (u'System Access', self.IniParam()),
            (u'Kerberos Policy', self.IniParam()),
            (u'System Log', self.IniParam()),
            (u'Security Log', self.IniParam()),
            (u'Application Log', self.IniParam()),
            (u'Event Audit', self.IniParam()),
            (u'Registry Values', self.RegParam()),
            (u'Privilege Rights', self.PrivSIDListParam()),
            (u'Service General Setting', self.NameModeACLParam()),
            (u'Registry Keys', self.NameModeACLParam()),
            (u'File Security', self.NameModeACLParam()),
            (u'Group Membership', self.MemberSIDListParam()),
        ])

        current_param_parser = None
        current_header_name = None

        for line in inf_file.splitlines():
            match = re.match(r'\[(.*)\]', line)
            if match:
                header_name = match.group(1)
                if header_name in self.sections:
                    current_param_parser = self.sections[header_name]
                    # print current_param_parser
                    continue

            # print 'using', current_param_parser
            current_param_parser.parse(line)


    def write_binary(self, filename):
        with codecs.open(filename, 'wb+',
                         self.output_encoding) as f:
            # Write the byte-order mark
            f.write(u'\ufeff')

            for s in self.sections:
                self.sections[s].write_section(s, f)

    def write_xml(self, filename):
        with open(filename, 'wb') as f:
            root = Element('GptTmplInfFile')

            for sec_inf in self.sections:
                section = SubElement(root, 'Section')
                section.attrib['name'] = sec_inf

                self.sections[sec_inf].build_xml(section)

            self.write_pretty_xml(root, f)

        # contents = codecs.open(filename, encoding='utf-8').read()
        # self.load_xml(fromstring(contents))

    def load_xml(self, root):
        self.sections = collections.OrderedDict([
            (u'Unicode', self.UnicodeParam()),
            (u'Version', self.VersionParam()),

            (u'System Access', self.IniParam()),
            (u'Kerberos Policy', self.IniParam()),
            (u'System Log', self.IniParam()),
            (u'Security Log', self.IniParam()),
            (u'Application Log', self.IniParam()),
            (u'Event Audit', self.IniParam()),
            (u'Registry Values', self.RegParam()),
            (u'Privilege Rights', self.PrivSIDListParam()),
            (u'Service General Setting', self.NameModeACLParam()),
            (u'Registry Keys', self.NameModeACLParam()),
            (u'File Security', self.NameModeACLParam()),
            (u'Group Membership', self.MemberSIDListParam()),
        ])

        for s in root.findall('Section'):
            self.sections[s.attrib['name']].from_xml(s)

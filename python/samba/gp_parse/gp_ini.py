# GPO Parser for extensions with ini files
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

from xml.etree.ElementTree import Element, SubElement
from samba.compat import ConfigParser
from samba.compat import StringIO

from samba.gp_parse import GPParser, ENTITY_USER_ID

# [MS-GPFR] Group Policy Folder Redirection
# [MS-GPSCR] Scripts Extension
class GPIniParser(GPParser):
    ini_conf = None

    def parse(self, contents):
        # Required dict_type in Python 2.7
        self.ini_conf = ConfigParser(dict_type=collections.OrderedDict)
        self.ini_conf.optionxform = str

        self.ini_conf.readfp(StringIO(contents.decode(self.encoding)))

    def build_xml_parameter(self, section_xml, section, key_ini, val_ini):
        child = SubElement(section_xml, 'Parameter')
        key = SubElement(child, 'Key')
        value = SubElement(child, 'Value')
        key.text = key_ini
        value.text = val_ini

        return child

    def load_xml_parameter(self, param_xml, section):
        key = param_xml.find('Key').text
        value = param_xml.find('Value').text
        if value is None:
            value = ''
        self.ini_conf.set(section, key, value)

        return (key, value)

    def build_xml_section(self, root_xml, sec_ini):
        section = SubElement(root_xml, 'Section')
        section.attrib['name'] = sec_ini

        return section

    def load_xml_section(self, section_xml):
        section_name = section_xml.attrib['name']
        self.ini_conf.add_section(section_name)

        return section_name

    def write_xml(self, filename):
        with open(filename, 'wb') as f:
            root = Element('IniFile')

            for sec_ini in self.ini_conf.sections():
                section = self.build_xml_section(root, sec_ini)

                for key_ini, val_ini in self.ini_conf.items(sec_ini, raw=True):
                    self.build_xml_parameter(section, sec_ini, key_ini,
                                             val_ini)

            self.write_pretty_xml(root, f)

        # from xml.etree.ElementTree import fromstring
        # contents = codecs.open(filename, encoding='utf-8').read()
        # self.load_xml(fromstring(contents))

    def load_xml(self, root):
        # Required dict_type in Python 2.7
        self.ini_conf = ConfigParser(dict_type=collections.OrderedDict)
        self.ini_conf.optionxform = str

        for s in root.findall('Section'):
            section_name = self.load_xml_section(s)

            for param in s.findall('Parameter'):
                self.load_xml_parameter(param, section_name)

    def write_binary(self, filename):
        with codecs.open(filename, 'wb+', self.encoding) as f:
            self.ini_conf.write(f)


class GPTIniParser(GPIniParser):
    encoding = 'utf-8'

    def parse(self, contents):
        try:
            super(GPTIniParser, self).parse(contents)
        except UnicodeDecodeError:
            # Required dict_type in Python 2.7
            self.ini_conf = ConfigParser(dict_type=collections.OrderedDict)
            self.ini_conf.optionxform = str

            # Fallback to Latin-1 which RSAT appears to use
            self.ini_conf.readfp(StringIO(contents.decode('iso-8859-1')))


class GPScriptsIniParser(GPIniParser):
    def build_xml_parameter(self, section_xml, section, key_ini, val_ini):
        parent_return = super(GPScriptsIniParser,
                              self).build_xml_parameter(section_xml, section,
                                                        key_ini, val_ini)

        cmdline = re.match('\\d+CmdLine$', key_ini)
        if cmdline is not None:
            value = parent_return.find('Value')
            value.attrib['network_path'] = 'TRUE'

        return parent_return


class GPFDeploy1IniParser(GPIniParser):
    def build_xml_parameter(self, section_xml, section, key_ini, val_ini):
        parent_return = super(GPFDeploy1IniParser,
                              self).build_xml_parameter(section_xml, section,
                                                        key_ini, val_ini)
        # Add generalization metadata and parse out SID list
        if section.lower() == 'folder_redirection':
            # Process the header section
            # {GUID} = S-1-1-0;S-1-1-0

            # Remove the un-split SID values
            key = parent_return.find('Value')
            parent_return.remove(key)

            sid_list = val_ini.strip().strip(';').split(';')

            for sid in sid_list:
                value = SubElement(parent_return, 'Value')
                value.text = sid
                value.attrib['user_id'] = 'TRUE'

        else:
            # Process redirection sections
            # Only FullPath should be a network path
            if key_ini == 'FullPath':
                key = parent_return.find('Value')
                key.attrib['network_path'] = 'TRUE'

        return parent_return

    def load_xml_parameter(self, param_xml, section):
        # Re-join the SID list before entering ConfigParser
        if section.lower() == 'folder_redirection':
            key = param_xml.find('Key').text
            values = param_xml.findall('Value')

            if len(values) == 1:
                # There appears to be a convention of a trailing semi-colon
                # with only one value in the SID list.
                value = values[0].text + ';'
            else:
                value = ';'.join([x.text for x in values])

            self.ini_conf.set(section, key, value)

            return (key, value)

        # Do the normal ini code for other sections
        return super(GPFDeploy1IniParser,
                     self).load_xml_parameter(param_xml, section)

    def build_xml_section(self, root_xml, sec_ini):
        section = SubElement(root_xml, 'Section')

        if (sec_ini.lower() != 'folder_redirection' and
            sec_ini.lower() != 'version'):
            guid, sid = sec_ini.split('_')
            section.attrib['fdeploy_GUID'] = guid
            section.attrib['fdeploy_SID'] = sid
        else:
            section.attrib['name'] = sec_ini

        return section

    def load_xml_section(self, section_xml):
        # Construct the name from GUID + SID if no name exists
        if 'name' in section_xml.attrib:
            section_name = section_xml.attrib['name']
        else:
            guid = section_xml.attrib['fdeploy_GUID']
            sid = section_xml.attrib['fdeploy_SID']
            section_name = guid + '_' + sid

        self.ini_conf.add_section(section_name)
        return section_name

    def custom_entities(self, root, global_entities):
        entities = []
        fdeploy_sids = root.findall('.//Section[@fdeploy_SID]')
        fdeploy_sids.sort(key = lambda x: x.tag)

        for sid in fdeploy_sids:
            old_attrib = sid.attrib['fdeploy_SID']

            if old_attrib in global_entities:
                new_attrib = global_entities[old_attrib]
            else:
                new_attrib = self.new_xml_entity(old_attrib, ENTITY_USER_ID)
                entities.append((new_attrib, old_attrib))

                global_entities.update([(old_attrib, new_attrib)])

            sid.attrib['fdeploy_SID'] = new_attrib

        return entities

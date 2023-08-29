# vgp_motd_ext samba gpo policy
# Copyright (C) David Mulder <dmulder@suse.com> 2020
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

import os
from samba.gp.gpclass import gp_xml_ext, gp_misc_applier

class vgp_motd_ext(gp_xml_ext, gp_misc_applier):
    def unapply(self, guid, motd, attribute, value):
        if attribute != 'motd':
            raise ValueError('"%s" is not a message attribute' % attribute)
        msg = value
        data = self.parse_value(value)
        if os.path.exists(motd):
            with open(motd, 'r') as f:
                current = f.read()
        else:
            current = ''
        # Only overwrite the msg if it hasn't been modified. It may have been
        # modified by another GPO.
        if 'new_val' not in data or current.strip() == data['new_val'].strip():
            msg = data['old_val']
            with open(motd, 'w') as w:
                if msg:
                    w.write(msg)
                else:
                    w.truncate()
        self.cache_remove_attribute(guid, attribute)

    def apply(self, guid, motd, text):
        if os.path.exists(motd):
            with open(motd, 'r') as f:
                current = f.read()
        else:
            current = ''
        if current != text.text:
            with open(motd, 'w') as w:
                w.write(text.text)
            data = self.generate_value(old_val=current, new_val=text.text)
            self.cache_add_attribute(guid, 'motd', data)

    def __str__(self):
        return 'Unix Settings/Message of the Day'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             motd='/etc/motd'):
        for guid, settings in deleted_gpo_list:
            if str(self) in settings:
                for attribute, msg in settings[str(self)].items():
                    self.unapply(guid, motd, attribute, msg)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                xml = 'MACHINE/VGP/VTLA/Unix/MOTD/manifest.xml'
                path = os.path.join(gpo.file_sys_path, xml)
                xml_conf = self.parse(path)
                if not xml_conf:
                    continue
                policy = xml_conf.find('policysetting')
                data = policy.find('data')
                text = data.find('text')
                self.apply(gpo.name, motd, text)

    def rsop(self, gpo):
        output = {}
        if gpo.file_sys_path:
            xml = 'MACHINE/VGP/VTLA/Unix/MOTD/manifest.xml'
            path = os.path.join(gpo.file_sys_path, xml)
            xml_conf = self.parse(path)
            if not xml_conf:
                return output
            policy = xml_conf.find('policysetting')
            data = policy.find('data')
            filename = data.find('filename')
            text = data.find('text')
            mfile = os.path.join('/etc', filename.text)
            output[mfile] = text.text
        return output

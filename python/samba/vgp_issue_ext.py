# vgp_issue_ext samba gpo policy
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
from samba.gpclass import gp_xml_ext

class vgp_issue_ext(gp_xml_ext):
    def __str__(self):
        return 'Unix Settings/Issue'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             issue='/etc/issue'):
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for attribute, msg in settings[str(self)].items():
                    if attribute == 'issue':
                        with open(issue, 'w') as w:
                            if msg:
                                w.write(msg)
                            else:
                                w.truncate()
                    self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                self.gp_db.set_guid(gpo.name)
                xml = 'MACHINE/VGP/VTLA/Unix/Issue/manifest.xml'
                path = os.path.join(gpo.file_sys_path, xml)
                xml_conf = self.parse(path)
                if not xml_conf:
                    continue
                policy = xml_conf.find('policysetting')
                data = policy.find('data')
                text = data.find('text')
                current = open(issue, 'r').read() if os.path.exists(issue) else ''
                if current != text.text:
                    with open(issue, 'w') as w:
                        w.write(text.text)
                        self.gp_db.store(str(self), 'issue', current)
                    self.gp_db.commit()

    def rsop(self, gpo):
        output = {}
        if gpo.file_sys_path:
            xml = 'MACHINE/VGP/VTLA/Unix/Issue/manifest.xml'
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

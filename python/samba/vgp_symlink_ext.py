# vgp_symlink_ext samba gpo policy
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
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE

class vgp_symlink_ext(gp_xml_ext):
    def __str__(self):
        return 'VGP/Unix Settings/Symbolic Links'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for attribute, symlink in settings[str(self)].items():
                    if os.path.exists(symlink):
                        os.unlink(symlink)
                    self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                self.gp_db.set_guid(gpo.name)
                xml = 'MACHINE/VGP/VTLA/Unix/Symlink/manifest.xml'
                path = os.path.join(gpo.file_sys_path, xml)
                xml_conf = self.parse(path)
                if not xml_conf:
                    continue
                policy = xml_conf.find('policysetting')
                data = policy.find('data')
                for entry in data.findall('file_properties'):
                    source = entry.find('source').text
                    target = entry.find('target').text
                    attribute = '%s:%s' % (source, target)
                    old_val = self.gp_db.retrieve(str(self), attribute)
                    if not old_val:
                        if not os.path.exists(target):
                            os.symlink(source, target)
                            self.gp_db.store(str(self), attribute, target)
                        else:
                            self.logger.warn('Symlink destination "%s" exists'
                                             % target)
                    self.gp_db.commit()

    def rsop(self, gpo):
        output = {}
        xml = 'MACHINE/VGP/VTLA/Unix/Symlink/manifest.xml'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, xml)
            xml_conf = self.parse(path)
            if not xml_conf:
                return output
            policy = xml_conf.find('policysetting')
            data = policy.find('data')
            for entry in data.findall('file_properties'):
                source = entry.find('source').text
                target = entry.find('target').text
                if str(self) not in output.keys():
                    output[str(self)] = []
                output[str(self)].append('ln -s %s %s' % (source, target))
        return output

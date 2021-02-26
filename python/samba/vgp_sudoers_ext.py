# vgp_sudoers_ext samba gpo policy
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
from base64 import b64encode
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
from samba.gp_sudoers_ext import visudo, intro

class vgp_sudoers_ext(gp_xml_ext):
    def __str__(self):
        return 'VGP/Unix Settings/Sudo Rights'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
            sdir='/etc/sudoers.d'):
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for attribute, sudoers in settings[str(self)].items():
                    if os.path.exists(sudoers):
                        os.unlink(sudoers)
                    self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                self.gp_db.set_guid(gpo.name)
                xml = 'MACHINE/VGP/VTLA/Sudo/SudoersConfiguration/manifest.xml'
                path = os.path.join(gpo.file_sys_path, xml)
                xml_conf = self.parse(path)
                if not xml_conf:
                    continue
                policy = xml_conf.find('policysetting')
                data = policy.find('data')
                for entry in data.findall('sudoers_entry'):
                    command = entry.find('command').text
                    user = entry.find('user').text
                    listelements = entry.findall('listelement')
                    principals = []
                    for listelement in listelements:
                        principals.extend(listelement.findall('principal'))
                    if len(principals) > 0:
                        uname = ','.join([u.text if u.attrib['type'] == 'user' \
                            else '%s%%' % u.text for u in principals])
                    else:
                        uname = 'ALL'
                    nopassword = entry.find('password') == None
                    np_entry = ' NOPASSWD:' if nopassword else ''
                    p = '%s ALL=(%s)%s %s' % (uname, user, np_entry, command)
                    attribute = b64encode(p.encode()).decode()
                    old_val = self.gp_db.retrieve(str(self), attribute)
                    if not old_val:
                        contents = intro
                        contents += '%s\n' % p
                        with NamedTemporaryFile() as f:
                            with open(f.name, 'w') as w:
                                w.write(contents)
                            sudo_validation = \
                                    Popen([visudo, '-c', '-f', f.name],
                                        stdout=PIPE, stderr=PIPE).wait()
                        if sudo_validation == 0:
                            with NamedTemporaryFile(prefix='gp_',
                                                    delete=False,
                                                    dir=sdir) as f:
                                with open(f.name, 'w') as w:
                                    w.write(contents)
                                self.gp_db.store(str(self),
                                                 attribute,
                                                 f.name)
                        else:
                            self.logger.warn('Sudoers apply "%s" failed'
                                    % p)
                    self.gp_db.commit()

    def rsop(self, gpo):
        output = {}
        xml = 'MACHINE/VGP/VTLA/Sudo/SudoersConfiguration/manifest.xml'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, xml)
            xml_conf = self.parse(path)
            if not xml_conf:
                return output
            policy = xml_conf.find('policysetting')
            data = policy.find('data')
            for entry in data.findall('sudoers_entry'):
                command = entry.find('command').text
                user = entry.find('user').text
                listelements = entry.findall('listelement')
                principals = []
                for listelement in listelements:
                    principals.extend(listelement.findall('principal'))
                if len(principals) > 0:
                    uname = ','.join([u.text if u.attrib['type'] == 'user' \
                        else '%s%%' % u.text for u in principals])
                else:
                    uname = 'ALL'
                nopassword = entry.find('password') == None
                np_entry = ' NOPASSWD:' if nopassword else ''
                p = '%s ALL=(%s)%s %s' % (uname, user, np_entry, command)
                if str(self) not in output.keys():
                    output[str(self)] = []
                output[str(self)].append(p)
        return output

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
from samba.gp.gpclass import gp_xml_ext, gp_file_applier
from samba.gp.gp_sudoers_ext import sudo_applier_func

class vgp_sudoers_ext(gp_xml_ext, gp_file_applier):
    def __str__(self):
        return 'VGP/Unix Settings/Sudo Rights'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
            sdir='/etc/sudoers.d'):
        for guid, settings in deleted_gpo_list:
            if str(self) in settings:
                for attribute, sudoers in settings[str(self)].items():
                    self.unapply(guid, attribute, sudoers)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                xml = 'MACHINE/VGP/VTLA/Sudo/SudoersConfiguration/manifest.xml'
                path = os.path.join(gpo.file_sys_path, xml)
                xml_conf = self.parse(path)
                if not xml_conf:
                    continue
                policy = xml_conf.find('policysetting')
                data = policy.find('data')
                sudo_entries = []
                for entry in data.findall('sudoers_entry'):
                    command = entry.find('command').text
                    user = entry.find('user').text
                    listelements = entry.findall('listelement')
                    principals = []
                    for listelement in listelements:
                        principals.extend(listelement.findall('principal'))
                    if len(principals) > 0:
                        uname = ','.join([u.text if u.attrib['type'] == 'user'
                            else '%s%%' % u.text for u in principals])
                    else:
                        uname = 'ALL'
                    nopassword = entry.find('password') is None
                    np_entry = ' NOPASSWD:' if nopassword else ''
                    p = '%s ALL=(%s)%s %s' % (uname, user, np_entry, command)
                    sudo_entries.append(p)
                # Each GPO applies only one set of sudoers, in a
                # set of files, so the attribute does not need uniqueness.
                attribute = self.generate_attribute(gpo.name)
                # The value hash is generated from the sudo_entries, ensuring
                # any changes to this GPO will cause the files to be rewritten.
                value_hash = self.generate_value_hash(*sudo_entries)
                self.apply(gpo.name, attribute, value_hash, sudo_applier_func,
                           sdir, sudo_entries)
                # Cleanup any old entries that are no longer part of the policy
                self.clean(gpo.name, keep=[attribute])

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
                    uname = ','.join([u.text if u.attrib['type'] == 'user'
                        else '%s%%' % u.text for u in principals])
                else:
                    uname = 'ALL'
                nopassword = entry.find('password') is None
                np_entry = ' NOPASSWD:' if nopassword else ''
                p = '%s ALL=(%s)%s %s' % (uname, user, np_entry, command)
                if str(self) not in output.keys():
                    output[str(self)] = []
                output[str(self)].append(p)
        return output

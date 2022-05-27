# gp_firefox_ext samba gpo policy
# Copyright (C) David Mulder <dmulder@suse.com> 2021
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
import json
from samba.gp.gpclass import gp_pol_ext
from samba.dcerpc import misc
from samba.common import get_string
from samba.gp.util.logging import log

def parse_entry_data(e):
    if e.type == misc.REG_MULTI_SZ:
        data = get_string(e.data).replace('\x00', '')
        return json.loads(data)
    elif e.type == misc.REG_DWORD and e.data in [0, 1]:
        return e.data == 1
    return e.data

def convert_pol_to_json(policies, section, entries):
    result = policies['policies']
    index_map = {}
    for e in entries:
        if not e.keyname.startswith(section):
            continue
        if '**delvals.' in e.valuename:
            continue
        sub_keys = e.keyname.replace(section, '').strip('\\')
        if sub_keys:
            sub_keys = sub_keys.split('\\')
            current = result
            index = -1
            if sub_keys[-1].isnumeric():
                name = '\\'.join(sub_keys[:-1])
            elif e.valuename.isnumeric():
                name = e.keyname
            else:
                name = '\\'.join([e.keyname, e.valuename])
            for i in range(len(sub_keys)):
                if sub_keys[i] == 'PDFjs':
                    sub_keys[i] = 'PSFjs'
                ctype = dict
                if i == len(sub_keys)-1 and e.valuename.isnumeric():
                    ctype = list
                    index = int(e.valuename)
                if i < len(sub_keys)-1 and sub_keys[i+1].isnumeric():
                    ctype = list
                    index = int(sub_keys[i+1])
                if type(current) == dict:
                    if sub_keys[i] not in current:
                        if ctype == dict:
                            current[sub_keys[i]] = {}
                        else:
                            current[sub_keys[i]] = []
                    current = current[sub_keys[i]]
                else:
                    if name not in index_map:
                        index_map[name] = {}
                    if index not in index_map[name].keys():
                        if ctype == dict:
                            current.append({})
                        else:
                            current.append([])
                        index_map[name][index] = len(current)-1
                    current = current[index_map[name][index]]
            if type(current) == list:
                current.append(parse_entry_data(e))
            else:
                current[e.valuename] = parse_entry_data(e)
        else:
            result[e.valuename] = parse_entry_data(e)
    return {'policies': result}

class gp_firefox_ext(gp_pol_ext):
    __firefox_installdir1 = '/usr/lib64/firefox/distribution'
    __firefox_installdir2 = '/etc/firefox/policies'
    __destfile1 = os.path.join(__firefox_installdir1, 'policies.json')
    __destfile2 = os.path.join(__firefox_installdir2, 'policies.json')

    def __str__(self):
        return 'Mozilla/Firefox'

    def set_machine_policy(self, policies):
        try:
            os.makedirs(self.__firefox_installdir1, exist_ok=True)
            with open(self.__destfile1, 'w') as f:
                json.dump(policies, f)
                log.debug('Wrote Firefox preferences', self.__destfile1)
        except PermissionError:
            log.debug('Failed to write Firefox preferences',
                              self.__destfile1)

        try:
            os.makedirs(self.__firefox_installdir2, exist_ok=True)
            with open(self.__destfile2, 'w') as f:
                json.dump(policies, f)
                log.debug('Wrote Firefox preferences', self.__destfile2)
        except PermissionError:
            log.debug('Failed to write Firefox preferences',
                              self.__destfile2)

    def get_machine_policy(self):
        if os.path.exists(self.__destfile2):
            with open(self.__destfile2, 'r') as r:
                policies = json.load(r)
                log.debug('Read Firefox preferences', self.__destfile2)
        elif os.path.exists(self.__destfile1):
            with open(self.__destfile1, 'r') as r:
                policies = json.load(r)
                log.debug('Read Firefox preferences', self.__destfile1)
        else:
            policies = {'policies': {}}
        return policies

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             policy_dir=None):
        if policy_dir is not None:
            self.__firefox_installdir2 = policy_dir
            self.__destfile2 = os.path.join(policy_dir, 'policies.json')
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for attribute, policies in settings[str(self)].items():
                    self.set_machine_policy(json.loads(policies))
                    self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section = 'Software\\Policies\\Mozilla\\Firefox'
                self.gp_db.set_guid(gpo.name)
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue

                policies = self.get_machine_policy()
                self.gp_db.store(str(self), 'policies.json',
                                 json.dumps(policies))
                policies = convert_pol_to_json(policies, section,
                                               pol_conf.entries)
                self.set_machine_policy(policies)
                self.gp_db.commit()

    def rsop(self, gpo):
        output = {}
        pol_file = 'MACHINE/Registry.pol'
        section = 'Software\\Policies\\Mozilla\\Firefox'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if e.keyname.startswith(section):
                    output['%s\\%s' % (e.keyname, e.valuename)] = e.data
        return output

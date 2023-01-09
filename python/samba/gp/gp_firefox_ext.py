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
from samba.gp.gpclass import gp_pol_ext, gp_misc_applier
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

def convert_pol_to_json(section, entries):
    result = {}
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
    return result

class gp_firefox_ext(gp_pol_ext, gp_misc_applier):
    firefox_installdir = '/etc/firefox/policies'
    destfile = os.path.join(firefox_installdir, 'policies.json')

    def __str__(self):
        return 'Mozilla/Firefox'

    def set_machine_policy(self, policies):
        try:
            os.makedirs(self.firefox_installdir, exist_ok=True)
            with open(self.destfile, 'w') as f:
                json.dump(policies, f)
                log.debug('Wrote Firefox preferences', self.destfile)
        except PermissionError:
            log.debug('Failed to write Firefox preferences',
                              self.destfile)

    def get_machine_policy(self):
        if os.path.exists(self.destfile):
            with open(self.destfile, 'r') as r:
                policies = json.load(r)
                log.debug('Read Firefox preferences', self.destfile)
        else:
            policies = {'policies': {}}
        return policies

    def parse_value(self, value):
        data = super().parse_value(value)
        for k, v in data.items():
            try:
                data[k] = json.loads(v)
            except json.decoder.JSONDecodeError:
                pass
        return data

    def unapply_policy(self, guid, policy, applied_val, val):
        def set_val(policies, policy, val):
            if val is None:
                del policies[policy]
            else:
                policies[policy] = val
        current = self.get_machine_policy()
        if policy in current['policies'].keys():
            if applied_val is not None:
                # Only restore policy if unmodified
                if current['policies'][policy] == applied_val:
                    set_val(current['policies'], policy, val)
            else:
                set_val(current['policies'], policy, val)
            self.set_machine_policy(current)

    def unapply(self, guid, policy, val):
        cache = self.parse_value(val)
        if policy == 'policies.json':
            current = self.get_machine_policy()
            for attr in current['policies'].keys():
                val = cache['old_val']['policies'][attr] \
                        if attr in cache['old_val']['policies'] else None
                self.unapply_policy(guid, attr, None, val)
        else:
            self.unapply_policy(guid, policy,
                                cache['new_val'] if 'new_val' in cache else None,
                                cache['old_val'])
        self.cache_remove_attribute(guid, policy)

    def apply(self, guid, policy, val):
        # If the policy has changed, unapply, then apply new policy
        data = self.cache_get_attribute_value(guid, policy)
        if data is not None:
            self.unapply(guid, policy, data)

        current = self.get_machine_policy()
        before = None
        if policy in current['policies'].keys():
            before = current['policies'][policy]

        # Apply the policy and log the changes
        new_value = self.generate_value(old_val=json.dumps(before),
                                        new_val=json.dumps(val))
        current['policies'][policy] = val
        self.set_machine_policy(current)
        self.cache_add_attribute(guid, policy, get_string(new_value))

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             policy_dir=None):
        if policy_dir is not None:
            self.firefox_installdir = policy_dir
            self.destfile = os.path.join(policy_dir, 'policies.json')
        for guid, settings in deleted_gpo_list:
            if str(self) in settings:
                for policy, val in settings[str(self)].items():
                    self.unapply(guid, policy, val)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                pol_file = 'MACHINE/Registry.pol'
                section = 'Software\\Policies\\Mozilla\\Firefox'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue

                # Unapply the old cache entry, if present
                data = self.cache_get_attribute_value(gpo.name, 'policies.json')
                if data is not None:
                    self.unapply(gpo.name, 'policies.json', data)

                policies = convert_pol_to_json(section, pol_conf.entries)
                for policy, val in policies.items():
                    self.apply(gpo.name, policy, val)

                # cleanup removed policies
                self.clean(gpo.name, keep=policies.keys())

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

class gp_firefox_old_ext(gp_firefox_ext):
    firefox_installdir = '/usr/lib64/firefox/distribution'
    destfile = os.path.join(firefox_installdir, 'policies.json')

    def __str__(self):
        return 'Mozilla/Firefox (old profile directory)'

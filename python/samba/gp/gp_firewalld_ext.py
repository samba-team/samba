# gp_firewalld_ext samba gpo policy
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
from subprocess import Popen, PIPE
from hashlib import blake2b
from shutil import which
import json
from samba.gp.gpclass import gp_pol_ext
from samba.gp.util.logging import log

def firewall_cmd(*args):
    fw_cmd = which('firewall-cmd')
    if fw_cmd is not None:
        cmd = [fw_cmd]
        cmd.extend(list(args))

        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdoutdata, _ = p.communicate()
        return p.returncode, stdoutdata
    else:
        return -1, 'firewall-cmd not found'

def rule_segment_parse(name, rule_segment):
    if isinstance(rule_segment, str):
        return ('%s=%s' % (name, rule_segment)) + ' '
    else:
        return '%s %s ' % (name,
            ' '.join(['%s=%s' % (k, v) for k, v in rule_segment.items()]))

class gp_firewalld_ext(gp_pol_ext):
    def __str__(self):
        return 'Security/Firewalld'

    def apply_zone(self, zone):
        ret = firewall_cmd('--permanent', '--new-zone=%s' % zone)[0]
        if ret != 0:
            log.error('Failed to add new zone', zone)
        else:
            self.gp_db.store(str(self), 'zone:%s' % zone, zone)
        # Default to matching the interface(s) for the default zone
        ret, out = firewall_cmd('--list-interfaces')
        if ret != 0:
            log.error('Failed to set interfaces for zone', zone)
        for interface in out.strip().split():
            ret = firewall_cmd('--permanent', '--zone=%s' % zone,
                               '--add-interface=%s' % interface.decode())
            if ret != 0:
                log.error('Failed to set interfaces for zone', zone)

    def apply_rules(self, rule_dict):
        for zone, rules in rule_dict.items():
            for rule in rules:
                if 'rule' in rule:
                    rule_parsed = rule_segment_parse('rule', rule['rule'])
                else:
                    rule_parsed = 'rule '
                for segment in ['source', 'destination', 'service', 'port',
                                'protocol', 'icmp-block', 'masquerade',
                                'icmp-type', 'forward-port', 'source-port',
                                'log', 'audit']:
                    names = [s for s in rule.keys() if s.startswith(segment)]
                    for name in names:
                        rule_parsed += rule_segment_parse(name, rule[name])
                actions = set(['accept', 'reject', 'drop', 'mark'])
                segments = set(rule.keys())
                action = actions.intersection(segments)
                if len(action) == 1:
                    rule_parsed += rule_segment_parse(list(action)[0],
                                                      rule[list(action)[0]])
                else:
                    log.error('Invalid firewall rule syntax')
                ret = firewall_cmd('--permanent', '--zone=%s' % zone,
                                   '--add-rich-rule', rule_parsed.strip())[0]
                if ret != 0:
                    log.error('Failed to add firewall rule', rule_parsed)
                else:
                    rhash = blake2b(rule_parsed.encode()).hexdigest()
                    self.gp_db.store(str(self), 'rule:%s:%s' % (zone, rhash),
                                     rule_parsed)

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for attribute, value in settings[str(self)].items():
                    if attribute.startswith('zone'):
                        ret = firewall_cmd('--permanent',
                                           '--delete-zone=%s' % value)[0]
                        if ret != 0:
                            log.error('Failed to remove zone', value)
                        else:
                            self.gp_db.delete(str(self), attribute)
                    elif attribute.startswith('rule'):
                        _, zone, _ = attribute.split(':')
                        ret = firewall_cmd('--permanent', '--zone=%s' % zone,
                                           '--remove-rich-rule', value)[0]
                        if ret != 0:
                            log.error('Failed to remove firewall rule', value)
                        else:
                            self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section = 'Software\\Policies\\Samba\\Unix Settings\\Firewalld'
                self.gp_db.set_guid(gpo.name)
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                for e in pol_conf.entries:
                    if e.keyname.startswith(section):
                        if e.keyname.endswith('Rules'):
                            self.apply_rules(json.loads(e.data))
                        elif e.keyname.endswith('Zones'):
                            if e.valuename == '**delvals.':
                                continue
                            self.apply_zone(e.data)
                self.gp_db.commit()

    def rsop(self, gpo):
        output = {}
        pol_file = 'MACHINE/Registry.pol'
        section = 'Software\\Policies\\Samba\\Unix Settings\\Firewalld'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if e.keyname.startswith(section):
                    if e.keyname.endswith('Zones'):
                        if e.valuename == '**delvals.':
                            continue
                        if 'Zones' not in output.keys():
                            output['Zones'] = []
                        output['Zones'].append(e.data)
                    elif e.keyname.endswith('Rules'):
                        if 'Rules' not in output.keys():
                            output['Rules'] = []
                        output['Rules'].append(json.loads(e.data))
        return output

# gp_centrify_sudoers_ext samba gpo policy
# Copyright (C) David Mulder <dmulder@suse.com> 2022
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
from samba.gp.gpclass import gp_pol_ext, gp_file_applier
from samba.gp.gp_sudoers_ext import sudo_applier_func
from samba.gp.util.logging import log

def ext_enabled(entries):
    section = 'Software\\Policies\\Centrify\\UnixSettings'
    for e in entries:
        if e.keyname == section and e.valuename == 'sudo.enabled':
            return e.data == 1
    return False

class gp_centrify_sudoers_ext(gp_pol_ext, gp_file_applier):
    def __str__(self):
        return 'Centrify/Sudo Rights'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
            sdir='/etc/sudoers.d'):
        for guid, settings in deleted_gpo_list:
            if str(self) in settings:
                for attribute, sudoers in settings[str(self)].items():
                    self.unapply(guid, attribute, sudoers)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section = 'Software\\Policies\\Centrify\\UnixSettings\\SuDo'
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf or not ext_enabled(pol_conf.entries):
                    continue
                sudo_entries = []
                for e in pol_conf.entries:
                    if e.keyname == section and e.data.strip():
                        if '**delvals.' in e.valuename:
                            continue
                        sudo_entries.append(e.data)
                # Each GPO applies only one set of sudoers, in a
                # set of files, so the attribute does not need uniqueness.
                attribute = self.generate_attribute(gpo.name, *sudo_entries)
                # The value hash is generated from the sudo_entries, ensuring
                # any changes to this GPO will cause the files to be rewritten.
                value_hash = self.generate_value_hash(*sudo_entries)
                self.apply(gpo.name, attribute, value_hash, sudo_applier_func,
                           sdir, sudo_entries)
                # Cleanup any old entries that are no longer part of the policy
                self.clean(gpo.name, keep=[attribute])

    def rsop(self, gpo):
        output = {}
        section = 'Software\\Policies\\Centrify\\UnixSettings\\SuDo'
        pol_file = 'MACHINE/Registry.pol'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if e.keyname == section and e.data.strip():
                    if '**delvals.' in e.valuename:
                        continue
                    if str(self) not in output.keys():
                        output[str(self)] = []
                    output[str(self)].append(e.data)
        return output

# gp_msgs_ext samba gpo policy
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
from samba.gp.gpclass import gp_pol_ext, gp_misc_applier

class gp_msgs_ext(gp_pol_ext, gp_misc_applier):
    def unapply(self, guid, cdir, attribute, value):
        if attribute not in ['motd', 'issue']:
            raise ValueError('"%s" is not a message attribute' % attribute)
        data = self.parse_value(value)
        mfile = os.path.join(cdir, attribute)
        current = open(mfile, 'r').read() if os.path.exists(mfile) else ''
        # Only overwrite the msg if it hasn't been modified. It may have been
        # modified by another GPO.
        if 'new_val' not in data or current.strip() == data['new_val'].strip():
            msg = data['old_val']
            with open(mfile, 'w') as w:
                if msg:
                    w.write(msg)
                else:
                    w.truncate()
        self.cache_remove_attribute(guid, attribute)

    def apply(self, guid, cdir, entries):
        section_name = 'Software\\Policies\\Samba\\Unix Settings\\Messages'
        for e in entries:
            if e.keyname == section_name and e.data.strip():
                if e.valuename not in ['motd', 'issue']:
                    raise ValueError('"%s" is not a message attribute' % \
                            e.valuename)
                mfile = os.path.join(cdir, e.valuename)
                if os.path.exists(mfile):
                    old_val = open(mfile, 'r').read()
                else:
                    old_val = ''
                # If policy is already applied, skip application
                if old_val.strip() == e.data.strip():
                    return
                with open(mfile, 'w') as w:
                    w.write(e.data)
                data = self.generate_value(old_val=old_val, new_val=e.data)
                self.cache_add_attribute(guid, e.valuename, data)

    def __str__(self):
        return 'Unix Settings/Messages'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             cdir='/etc'):
        for guid, settings in deleted_gpo_list:
            if str(self) in settings:
                for attribute, msg in settings[str(self)].items():
                    self.unapply(guid, cdir, attribute, msg)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section_name = 'Software\\Policies\\Samba\\Unix Settings\\Messages'
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                self.apply(gpo.name, cdir, pol_conf.entries)

    def rsop(self, gpo):
        output = {}
        if gpo.file_sys_path:
            section_name = 'Software\\Policies\\Samba\\Unix Settings\\Messages'
            pol_file = 'MACHINE/Registry.pol'
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if e.keyname == section_name and e.data.strip():
                    mfile = os.path.join('/etc', e.valuename)
                    output[mfile] = e.data
        return output

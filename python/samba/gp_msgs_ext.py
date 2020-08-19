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
from samba.gpclass import gp_pol_ext

class gp_msgs_ext(gp_pol_ext):
    def __str__(self):
        return 'Unix Settings/Messages'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             cdir='/etc'):
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for attribute, msg in settings[str(self)].items():
                    if attribute == 'motd':
                        mfile = os.path.join(cdir, 'motd')
                    elif attribute == 'issue':
                        mfile = os.path.join(cdir, 'issue')
                    else:
                        continue
                    with open(mfile, 'w') as w:
                        if msg:
                            w.write(msg)
                        else:
                            w.truncate()
                    self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section_name = 'Software\\Policies\\Samba\\Unix Settings\\Messages'
                self.gp_db.set_guid(gpo.name)
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                for e in pol_conf.entries:
                    if e.keyname == section_name and e.data.strip():
                        if e.valuename == 'motd':
                            mfile = os.path.join(cdir, 'motd')
                        elif e.valuename == 'issue':
                            mfile = os.path.join(cdir, 'issue')
                        else:
                            continue
                        if os.path.exists(mfile):
                            old_val = open(mfile, 'r').read()
                        else:
                            old_val = ''
                        with open(mfile, 'w') as w:
                            w.write(e.data)
                            self.gp_db.store(str(self), e.valuename, old_val)
                        self.gp_db.commit()

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

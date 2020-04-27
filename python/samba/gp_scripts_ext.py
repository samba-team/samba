# gp_scripts_ext samba gpo policy
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

import os, re
from samba.gpclass import gp_pol_ext
from base64 import b64encode
from tempfile import NamedTemporaryFile

class gp_scripts_ext(gp_pol_ext):
    def __str__(self):
        return 'Unix Settings/Daily Scripts'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list, cdir='/etc/cron.daily'):
        for gpo in deleted_gpo_list:
            self.gp_db.set_guid(gpo[0])
            if str(self) in gpo[1]:
                for attribute, script in gpo[1][str(self)].items():
                    os.unlink(script)
                    self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section_name = 'Software\\Policies\\Samba\\Unix Settings\\Daily Scripts'
                self.gp_db.set_guid(gpo.name)
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                for e in pol_conf.entries:
                    if e.keyname == section_name and e.data.strip():
                        attribute = b64encode(e.data.encode()).decode()
                        old_val = self.gp_db.retrieve(str(self), attribute)
                        if not old_val:
                            with NamedTemporaryFile(mode="w+", delete=False, dir=cdir) as f:
                                f.write('#!/bin/sh\n%s' % e.data)
                                os.chmod(f.name, 0o700)
                                self.gp_db.store(str(self), attribute, f.name)
                        self.gp_db.commit()

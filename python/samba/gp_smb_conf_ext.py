# gp_smb_conf_ext smb.conf gpo policy
# Copyright (C) David Mulder <dmulder@suse.com> 2018
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

import os, re, numbers
from samba.gpclass import gp_pol_ext
from tempfile import NamedTemporaryFile

def is_number(x):
    return isinstance(x, numbers.Number) and \
           type(x) != bool

class gp_smb_conf_ext(gp_pol_ext):
    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):

        pol_file = 'MACHINE/Registry.pol'
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            smb_conf = settings.get('smb.conf')
            if smb_conf is None:
                continue
            for key, value in smb_conf.items():
                self.set_smb_conf(key, value)
                self.gp_db.delete('smb.conf', key)
                self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section_name = 'Software\\Policies\\Samba\\smb_conf'
                self.gp_db.set_guid(gpo.name)
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                for e in pol_conf.entries:
                    if not e.keyname.startswith(section_name):
                        continue
                    self.set_smb_conf(e.valuename, e.data)
                    self.gp_db.commit()

    def set_smb_conf(self, attribute, val):
        old_val = self.lp.get(attribute)

        if type(val) == bytes:
            val = val.decode()
        if is_number(val) and is_number(old_val):
            val = str(val)
        elif is_number(val) and type(old_val) == bool:
            val = bool(val)
        if type(val) == bool:
            val = 'yes' if val else 'no'

        self.lp.set(attribute, val)
        with NamedTemporaryFile(delete=False,
                                dir=os.path.dirname(self.lp.configfile)) as f:
            self.lp.dump(False, f.name)
            mode = os.stat(self.lp.configfile).st_mode
            os.chmod(f.name, mode)
            os.rename(f.name, self.lp.configfile)

        self.logger.info('smb.conf [global] %s was changed from %s to %s' % \
                         (attribute, old_val, str(val)))

        if is_number(old_val):
            old_val = str(old_val)
        elif type(old_val) == bool:
            old_val = 'yes' if old_val else 'no'
        elif type(old_val) == list:
            old_val = ' '.join(old_val)
        self.gp_db.store(str(self), attribute, old_val)

    def __str__(self):
        return "smb.conf"

    def rsop(self, gpo):
        output = {}
        if gpo.file_sys_path:
            section_name = 'Software\\Policies\\Samba\\smb_conf'
            pol_file = 'MACHINE/Registry.pol'
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if not e.keyname.startswith(section_name):
                    continue
                if 'smb.conf' not in output.keys():
                    output['smb.conf'] = {}
                output['smb.conf'][e.valuename] = e.data
        return output

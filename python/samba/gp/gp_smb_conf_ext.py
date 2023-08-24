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

import os, numbers
from samba.gp.gpclass import gp_pol_ext, gp_misc_applier
from tempfile import NamedTemporaryFile
from samba.gp.util.logging import log

def is_number(x):
    return isinstance(x, numbers.Number) and \
           type(x) != bool

class gp_smb_conf_ext(gp_pol_ext, gp_misc_applier):
    def unapply(self, guid, attribute, val):
        current = self.lp.get(attribute)
        data = self.parse_value(val)

        # Only overwrite the smb.conf setting if it hasn't been modified. It
        # may have been modified by another GPO.
        if 'new_val' not in data or \
                self.lptype_to_string(current) == data['new_val']:
            self.lp.set(attribute, self.regtype_to_lptype(data['old_val'],
                                                          current))
            self.store_lp_smb_conf(self.lp)
            log.info('smb.conf [global] was changed',
                     { attribute : str(data['old_val']) })

        self.cache_remove_attribute(guid, attribute)

    def apply(self, guid, attribute, val):
        old_val = self.lp.get(attribute)
        val = self.regtype_to_lptype(val, old_val)

        self.lp.set(attribute, val)
        self.store_lp_smb_conf(self.lp)
        log.info('smb.conf [global] was changed', { attribute : str(val) })

        data = self.generate_value(old_val=self.lptype_to_string(old_val),
                                   new_val=self.lptype_to_string(val))
        self.cache_add_attribute(guid, attribute, data)

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        pol_file = 'MACHINE/Registry.pol'
        for guid, settings in deleted_gpo_list:
            smb_conf = settings.get('smb.conf')
            if smb_conf is None:
                continue
            for key, value in smb_conf.items():
                self.unapply(guid, key, value)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section_name = 'Software\\Policies\\Samba\\smb_conf'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                attrs = []
                for e in pol_conf.entries:
                    if not e.keyname.startswith(section_name):
                        continue
                    attrs.append(e.valuename)
                    self.apply(gpo.name, e.valuename, e.data)

                # Cleanup settings which were removed from the policy
                self.clean(gpo.name, keep=attrs)

    def regtype_to_lptype(self, val, old_val):
        if type(val) == bytes:
            val = val.decode()
        if is_number(val) and is_number(old_val):
            val = str(val)
        elif is_number(val) and type(old_val) == bool:
            val = bool(val)
        if type(val) == bool:
            val = 'yes' if val else 'no'
        return val

    def store_lp_smb_conf(self, lp):
        with NamedTemporaryFile(delete=False,
                                dir=os.path.dirname(lp.configfile)) as f:
            lp.dump(False, f.name)
            mode = os.stat(lp.configfile).st_mode
            os.chmod(f.name, mode)
            os.rename(f.name, lp.configfile)

    def lptype_to_string(self, val):
        if is_number(val):
            val = str(val)
        elif type(val) == bool:
            val = 'yes' if val else 'no'
        elif type(val) == list:
            val = ' '.join(val)
        return val

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

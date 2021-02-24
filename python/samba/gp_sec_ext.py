# gp_sec_ext kdc gpo policy
# Copyright (C) Luke Morrison <luc785@.hotmail.com> 2013
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

import os.path
from samba.gpclass import gp_inf_ext
from samba.auth import system_session
from samba.common import get_string
try:
    from ldb import LdbError
    from samba.samdb import SamDB
except ImportError:
    pass

def mins_to_hours(val):
    return '%d' % (int(val) / 60)

def days_to_hours(val):
    return '%d' % (int(val) * 24)

def days2rel_nttime(val):
    seconds = 60
    minutes = 60
    hours = 24
    sam_add = 10000000
    val = int(val)
    return str(-(val * seconds * minutes * hours * sam_add))

class gp_krb_ext(gp_inf_ext):
    apply_map = { 'MaxTicketAge':  'kdc:user_ticket_lifetime',
                  'MaxServiceAge': 'kdc:service_ticket_lifetime',
                  'MaxRenewAge':   'kdc:renewal_lifetime' }
    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        if self.lp.get('server role') != 'active directory domain controller':
            return
        inf_file = 'MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            for section in settings.keys():
                if section == str(self):
                    for att, value in settings[section].items():
                        self.set_kdc_tdb(att, value)
                        self.gp_db.delete(section, att)
                        self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                self.gp_db.set_guid(gpo.name)
                path = os.path.join(gpo.file_sys_path, inf_file)
                inf_conf = self.parse(path)
                if not inf_conf:
                    continue
                for section in inf_conf.sections():
                    if section == str(self):
                        for key, value in inf_conf.items(section):
                            att = gp_krb_ext.apply_map[key]
                            value_func = self.mapper().get(att)
                            self.set_kdc_tdb(att, value_func(value))
                            self.gp_db.commit()

    def set_kdc_tdb(self, attribute, val):
        old_val = self.gp_db.gpostore.get(attribute)
        self.logger.info('%s was changed from %s to %s' % (attribute,
                                                           old_val, val))
        if val is not None:
            self.gp_db.gpostore.store(attribute, get_string(val))
            self.gp_db.store(str(self), attribute, get_string(old_val) \
                    if old_val else None)
        else:
            self.gp_db.gpostore.delete(attribute)
            self.gp_db.delete(str(self), attribute)

    def mapper(self):
        return {'kdc:user_ticket_lifetime': lambda val: val,
                'kdc:service_ticket_lifetime': mins_to_hours,
                'kdc:renewal_lifetime': days_to_hours,
                }

    def __str__(self):
        return 'Kerberos Policy'

    def rsop(self, gpo):
        output = {}
        if self.lp.get('server role') != 'active directory domain controller':
            return output
        inf_file = 'MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, inf_file)
            inf_conf = self.parse(path)
            if not inf_conf:
                return output
            if str(self) in inf_conf.sections():
                section = str(self)
                output[section] = {k: v for k, v in inf_conf.items(section) \
                                      if gp_krb_ext.apply_map.get(k)}
        return output


class gp_access_ext(gp_inf_ext):
    '''This class takes the .inf file parameter (essentially a GPO file mapped
    to a GUID), hashmaps it to the Samba parameter, which then uses an ldb
    object to update the parameter to Samba4. Not registry oriented whatsoever.
    '''

    def load_ldb(self):
        try:
            self.ldb = SamDB(self.lp.samdb_url(),
                             session_info=system_session(),
                             credentials=self.creds,
                             lp=self.lp)
        except (NameError, LdbError):
            raise Exception('Failed to load SamDB for assigning Group Policy')

    apply_map = { 'MinimumPasswordAge':     'minPwdAge',
                  'MaximumPasswordAge':     'maxPwdAge',
                  'MinimumPasswordLength':  'minPwdLength',
                  'PasswordComplexity':     'pwdProperties' }
    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        if self.lp.get('server role') != 'active directory domain controller':
            return
        self.load_ldb()
        inf_file = 'MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            for section in settings.keys():
                if section == str(self):
                    for att, value in settings[section].items():
                        update_samba, _ = self.mapper().get(att)
                        update_samba(att, value)
                        self.gp_db.delete(section, att)
                        self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                self.gp_db.set_guid(gpo.name)
                path = os.path.join(gpo.file_sys_path, inf_file)
                inf_conf = self.parse(path)
                if not inf_conf:
                    continue
                for section in inf_conf.sections():
                    if section == str(self):
                        for key, value in inf_conf.items(section):
                            att = gp_access_ext.apply_map[key]
                            (update_samba, value_func) = self.mapper().get(att)
                            update_samba(att, value_func(value))
                            self.gp_db.commit()

    def ch_minPwdAge(self, attribute, val):
        old_val = self.ldb.get_minPwdAge()
        self.logger.info('KDC Minimum Password age was changed from %s to %s'
                         % (old_val, val))
        self.gp_db.store(str(self), attribute, str(old_val))
        self.ldb.set_minPwdAge(val)

    def ch_maxPwdAge(self, attribute, val):
        old_val = self.ldb.get_maxPwdAge()
        self.logger.info('KDC Maximum Password age was changed from %s to %s'
                         % (old_val, val))
        self.gp_db.store(str(self), attribute, str(old_val))
        self.ldb.set_maxPwdAge(val)

    def ch_minPwdLength(self, attribute, val):
        old_val = self.ldb.get_minPwdLength()
        self.logger.info(
            'KDC Minimum Password length was changed from %s to %s'
            % (old_val, val))
        self.gp_db.store(str(self), attribute, str(old_val))
        self.ldb.set_minPwdLength(val)

    def ch_pwdProperties(self, attribute, val):
        old_val = self.ldb.get_pwdProperties()
        self.logger.info('KDC Password Properties were changed from %s to %s'
                         % (old_val, val))
        self.gp_db.store(str(self), attribute, str(old_val))
        self.ldb.set_pwdProperties(val)

    def mapper(self):
        '''ldap value : samba setter'''
        return {"minPwdAge": (self.ch_minPwdAge, days2rel_nttime),
                "maxPwdAge": (self.ch_maxPwdAge, days2rel_nttime),
                # Could be none, but I like the method assignment in
                # update_samba
                "minPwdLength": (self.ch_minPwdLength, lambda val: val),
                "pwdProperties": (self.ch_pwdProperties, lambda val: val),

                }

    def __str__(self):
        return 'System Access'

    def rsop(self, gpo):
        output = {}
        if self.lp.get('server role') != 'active directory domain controller':
            return output
        inf_file = 'MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, inf_file)
            inf_conf = self.parse(path)
            if not inf_conf:
                return output
            if str(self) in inf_conf.sections():
                section = str(self)
                output[section] = {k: v for k, v in inf_conf.items(section) \
                                      if gp_access_ext.apply_map.get(k)}
        return output

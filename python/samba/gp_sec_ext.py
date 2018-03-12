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
from gpclass import gp_ext_setter, gp_inf_ext

class inf_to_kdc_tdb(gp_ext_setter):
    def mins_to_hours(self):
        return '%d' % (int(self.val)/60)

    def days_to_hours(self):
        return '%d' % (int(self.val)*24)

    def set_kdc_tdb(self, val):
        old_val = self.gp_db.gpostore.get(self.attribute)
        self.logger.info('%s was changed from %s to %s' % (self.attribute,
                                                           old_val, val))
        if val is not None:
            self.gp_db.gpostore.store(self.attribute, val)
            self.gp_db.store(str(self), self.attribute, old_val)
        else:
            self.gp_db.gpostore.delete(self.attribute)
            self.gp_db.delete(str(self), self.attribute)

    def mapper(self):
        return { 'kdc:user_ticket_lifetime': (self.set_kdc_tdb, self.explicit),
                 'kdc:service_ticket_lifetime': (self.set_kdc_tdb,
                                                 self.mins_to_hours),
                 'kdc:renewal_lifetime': (self.set_kdc_tdb,
                                          self.days_to_hours),
               }

    def __str__(self):
        return 'Kerberos Policy'

class inf_to_ldb(gp_ext_setter):
    '''This class takes the .inf file parameter (essentially a GPO file mapped
    to a GUID), hashmaps it to the Samba parameter, which then uses an ldb
    object to update the parameter to Samba4. Not registry oriented whatsoever.
    '''

    def ch_minPwdAge(self, val):
        old_val = self.ldb.get_minPwdAge()
        self.logger.info('KDC Minimum Password age was changed from %s to %s' \
                         % (old_val, val))
        self.gp_db.store(str(self), self.attribute, old_val)
        self.ldb.set_minPwdAge(val)

    def ch_maxPwdAge(self, val):
        old_val = self.ldb.get_maxPwdAge()
        self.logger.info('KDC Maximum Password age was changed from %s to %s' \
                         % (old_val, val))
        self.gp_db.store(str(self), self.attribute, old_val)
        self.ldb.set_maxPwdAge(val)

    def ch_minPwdLength(self, val):
        old_val = self.ldb.get_minPwdLength()
        self.logger.info(
            'KDC Minimum Password length was changed from %s to %s' \
             % (old_val, val))
        self.gp_db.store(str(self), self.attribute, old_val)
        self.ldb.set_minPwdLength(val)

    def ch_pwdProperties(self, val):
        old_val = self.ldb.get_pwdProperties()
        self.logger.info('KDC Password Properties were changed from %s to %s' \
                         % (old_val, val))
        self.gp_db.store(str(self), self.attribute, old_val)
        self.ldb.set_pwdProperties(val)

    def days2rel_nttime(self):
        seconds = 60
        minutes = 60
        hours = 24
        sam_add = 10000000
        val = (self.val)
        val = int(val)
        return  str(-(val * seconds * minutes * hours * sam_add))

    def mapper(self):
        '''ldap value : samba setter'''
        return { "minPwdAge" : (self.ch_minPwdAge, self.days2rel_nttime),
                 "maxPwdAge" : (self.ch_maxPwdAge, self.days2rel_nttime),
                 # Could be none, but I like the method assignment in
                 # update_samba
                 "minPwdLength" : (self.ch_minPwdLength, self.explicit),
                 "pwdProperties" : (self.ch_pwdProperties, self.explicit),

               }

    def __str__(self):
        return 'System Access'

class gp_sec_ext(gp_inf_ext):
    '''This class does the following two things:
        1) Identifies the GPO if it has a certain kind of filepath,
        2) Finally parses it.
    '''

    count = 0

    def __str__(self):
        return "Security GPO extension"

    def list(self, rootpath):
        return os.path.join(rootpath,
            "MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf")

    def listmachpol(self, rootpath):
        return os.path.join(rootpath, "Machine/Registry.pol")

    def listuserpol(self, rootpath):
        return os.path.join(rootpath, "User/Registry.pol")

    def apply_map(self):
        return {"System Access": {"MinimumPasswordAge": ("minPwdAge",
                                                         inf_to_ldb),
                                  "MaximumPasswordAge": ("maxPwdAge",
                                                         inf_to_ldb),
                                  "MinimumPasswordLength": ("minPwdLength",
                                                            inf_to_ldb),
                                  "PasswordComplexity": ("pwdProperties",
                                                         inf_to_ldb),
                                 },
                "Kerberos Policy": {"MaxTicketAge": (
                                        "kdc:user_ticket_lifetime",
                                        inf_to_kdc_tdb
                                    ),
                                    "MaxServiceAge": (
                                        "kdc:service_ticket_lifetime",
                                        inf_to_kdc_tdb
                                    ),
                                    "MaxRenewAge": (
                                        "kdc:renewal_lifetime",
                                        inf_to_kdc_tdb
                                    ),
                                   }
               }


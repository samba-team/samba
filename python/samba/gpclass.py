# Reads important GPO parameters and updates Samba
# Copyright (C) Luke Morrison <luc785@.hotmail.com> 2013
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


import sys
import os
import tdb
sys.path.insert(0, "bin/python")
import samba.gpo as gpo
import optparse
import ldb
from samba.auth import system_session
import samba.getopt as options
from samba.samdb import SamDB
from samba.netcmd import gpo as gpo_user
import codecs
from samba import NTSTATUSError
from ConfigParser import ConfigParser
from StringIO import StringIO
from abc import ABCMeta, abstractmethod

class Backlog:
    def __init__(self, sysvol_log):
        if os.path.isfile(sysvol_log):
            self.backlog = tdb.open(sysvol_log)
        else:
            self.backlog = tdb.Tdb(sysvol_log, 0, tdb.DEFAULT, os.O_CREAT|os.O_RDWR)
        self.backlog.transaction_start()

    def version(self, guid):
        try:
            old_version = int(self.backlog.get(guid))
        except TypeError:
            old_version = -1
        return old_version

    def store(self, guid, version):
        self.backlog.store(guid, '%i' % version)

    def commit(self):
        self.backlog.transaction_commit()

    def __del__(self):
        self.backlog.close()

class gp_ext(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def list(self, rootpath):
        pass

    @abstractmethod
    def parse(self, afile, ldb, conn, lp):
        pass

    @abstractmethod
    def __str__(self):
        pass


class inf_to():
    __metaclass__ = ABCMeta

    def __init__(self, logger, ldb, lp, attribute, val):
        self.logger = logger
        self.ldb = ldb
        self.attribute = attribute
        self.val = val
        self.lp = lp

    def explicit(self):
        return self.val

    def update_samba(self):
        (upd_sam, value) = self.mapper().get(self.attribute)
        upd_sam(value())

    @abstractmethod
    def mapper(self):
        pass

class inf_to_ldb(inf_to):
    '''This class takes the .inf file parameter (essentially a GPO file mapped to a GUID),
    hashmaps it to the Samba parameter, which then uses an ldb object to update the
    parameter to Samba4. Not registry oriented whatsoever.
    '''

    def ch_minPwdAge(self, val):
        self.logger.info('KDC Minimum Password age was changed from %s to %s' % (self.ldb.get_minPwdAge(), val))
        self.ldb.set_minPwdAge(val)

    def ch_maxPwdAge(self, val):
        self.logger.info('KDC Maximum Password age was changed from %s to %s' % (self.ldb.get_maxPwdAge(), val))
        self.ldb.set_maxPwdAge(val)

    def ch_minPwdLength(self, val):
        self.logger.info('KDC Minimum Password length was changed from %s to %s' % (self.ldb.get_minPwdLength(), val))
        self.ldb.set_minPwdLength(val)

    def ch_pwdProperties(self, val):
        self.logger.info('KDC Password Properties were changed from %s to %s' % (self.ldb.get_pwdProperties(), val))
        self.ldb.set_pwdProperties(val)

    def nttime2unix(self):
        seconds = 60
        minutes = 60
        hours = 24
        sam_add = 10000000
        val = (self.val)
        val = int(val)
        return  str(-(val * seconds * minutes * hours * sam_add))

    def mapper(self):
        '''ldap value : samba setter'''
        return { "minPwdAge" : (self.ch_minPwdAge, self.nttime2unix),
                 "maxPwdAge" : (self.ch_maxPwdAge, self.nttime2unix),
                 # Could be none, but I like the method assignment in update_samba
                 "minPwdLength" : (self.ch_minPwdLength, self.explicit),
                 "pwdProperties" : (self.ch_pwdProperties, self.explicit),

               }


class gp_sec_ext(gp_ext):
    '''This class does the following two things:
        1) Identifies the GPO if it has a certain kind of filepath,
        2) Finally parses it.
    '''

    count = 0

    def __init__(self, logger):
        self.logger = logger

    def __str__(self):
        return "Security GPO extension"

    def list(self, rootpath):
        return os.path.join(rootpath, "MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf")

    def listmachpol(self, rootpath):
        return os.path.join(rootpath, "Machine/Registry.pol")

    def listuserpol(self, rootpath):
        return os.path.join(rootpath, "User/Registry.pol")

    def populate_inf(self):
        return {"System Access": {"MinimumPasswordAge": ("minPwdAge", inf_to_ldb),
                                  "MaximumPasswordAge": ("maxPwdAge", inf_to_ldb),
                                  "MinimumPasswordLength": ("minPwdLength", inf_to_ldb),
                                  "PasswordComplexity": ("pwdProperties", inf_to_ldb),
                                 }
               }

    def read_inf(self, path, conn):
        ret = False
        inftable = self.populate_inf()

        policy = conn.loadfile(path.replace('/', '\\'))
        current_section = None

        # So here we would declare a boolean,
        # that would get changed to TRUE.
        #
        # If at any point in time a GPO was applied,
        # then we return that boolean at the end.

        inf_conf = ConfigParser()
        inf_conf.optionxform=str
        try:
            inf_conf.readfp(StringIO(policy))
        except:
            inf_conf.readfp(StringIO(policy.decode('utf-16')))

        for section in inf_conf.sections():
            current_section = inftable.get(section)
            if not current_section:
                continue
            for key, value in inf_conf.items(section):
                if current_section.get(key):
                    (att, setter) = current_section.get(key)
                    value = value.encode('ascii', 'ignore')
                    ret = True
                    setter(self.logger, self.ldb, self.lp, att, value).update_samba()
        return ret

    def parse(self, afile, ldb, conn, lp):
        self.ldb = ldb
        self.lp = lp

        # Fixing the bug where only some Linux Boxes capitalize MACHINE
        if afile.endswith('inf'):
            try:
                blist = afile.split('/')
                idx = afile.lower().split('/').index('machine')
                for case in [blist[idx].upper(), blist[idx].capitalize(), blist[idx].lower()]:
                    bfile = '/'.join(blist[:idx]) + '/' + case + '/' + '/'.join(blist[idx+1:])
                    try:
                        return self.read_inf(bfile, conn)
                    except NTSTATUSError:
                        continue
            except ValueError:
                try:
                    return self.read_inf(afile, conn)
                except:
                    return None


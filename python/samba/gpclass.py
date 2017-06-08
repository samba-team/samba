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
import xml.etree.ElementTree as etree

class gp_log:
    ''' Log settings overwritten by gpo apply
    The gp_log is an xml file that stores a history of gpo changes (and the original setting value).

    The log is organized like so:

<gp>
    <user name="KDC-1$">
        <applylog>
            <guid count="0" value="{31B2F340-016D-11D2-945F-00C04FB984F9}" />
        </applylog>
        <guid value="{31B2F340-016D-11D2-945F-00C04FB984F9}">
            <gp_ext name="System Access">
                <attribute name="minPwdAge">-864000000000</attribute>
                <attribute name="maxPwdAge">-36288000000000</attribute>
                <attribute name="minPwdLength">7</attribute>
                <attribute name="pwdProperties">1</attribute>
            </gp_ext>
            <gp_ext name="Kerberos Policy">
                <attribute name="ticket_lifetime">1d</attribute>
                <attribute name="renew_lifetime" />
                <attribute name="clockskew">300</attribute>
            </gp_ext>
        </guid>
    </user>
</gp>

    Each guid value contains a list of extensions, which contain a list of attributes. The guid value
    represents a GPO. The attributes are the values of those settings prior to the application of
    the GPO.
    The list of guids is enclosed within a user name, which represents the user the settings were
    applied to. This user may be the samaccountname of the local computer, which implies that these
    are machine policies.
    The applylog keeps track of the order in which the GPOs were applied, so that they can be rolled
    back in reverse, returning the machine to the state prior to policy application.
    '''
    def __init__(self, user, gpostore, db_log=None):
        ''' Initialize the gp_log
        param user          - the username (or machine name) that policies are being applied to
        param gpostore      - the GPOStorage obj which references the tdb which contains gp_logs
        param db_log        - (optional) a string to initialize the gp_log
        '''
        self.gpostore = gpostore
        self.username = user
        if db_log:
            self.gpdb = etree.fromstring(db_log)
        else:
            self.gpdb = etree.Element('gp')
        self.user = self.gpdb.find('user[@name="%s"]' % user)
        if self.user is None:
            self.user = etree.SubElement(self.gpdb, 'user')
            self.user.attrib['name'] = user

    def set_guid(self, guid):
        ''' Log to a different GPO guid
        param guid          - guid value of the GPO from which we're applying policy
        '''
        self.guid = self.user.find('guid[@value="%s"]' % guid)
        if self.guid is None:
            self.guid = etree.SubElement(self.user, 'guid')
            self.guid.attrib['value'] = guid
        apply_log = self.user.find('applylog')
        if apply_log is None:
            apply_log = etree.SubElement(self.user, 'applylog')
        item = etree.SubElement(apply_log, 'guid')
        item.attrib['count'] = '%d' % (len(apply_log)-1)
        item.attrib['value'] = guid

    def apply_log_pop(self):
        ''' Pop a GPO guid from the applylog
        return              - last applied GPO guid

        Removes the GPO guid last added to the list, which is the most recently applied GPO.
        '''
        apply_log = self.user.find('applylog')
        if apply_log is not None:
            ret = apply_log.find('guid[@count="%d"]' % (len(apply_log)-1))
            if ret is not None:
                apply_log.remove(ret)
                return ret.attrib['value']
            if len(apply_log) == 0 and apply_log in self.user:
                self.user.remove(apply_log)
        return None

    def store(self, gp_ext_name, attribute, old_val):
        ''' Store an attribute in the gp_log
        param gp_ext_name   - Name of the extension applying policy
        param attribute     - The attribute being modified
        param old_val       - The value of the attribute prior to policy application
        '''
        assert self.guid is not None, "gpo guid was not set"
        ext = self.guid.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is None:
            ext = etree.SubElement(self.guid, 'gp_ext')
            ext.attrib['name'] = gp_ext_name
        attr = ext.find('attribute[@name="%s"]' % attribute)
        if attr is None:
            attr = etree.SubElement(ext, 'attribute')
            attr.attrib['name'] = attribute
        attr.text = old_val

    def retrieve(self, gp_ext_name, attribute):
        ''' Retrieve a stored attribute from the gp_log
        param gp_ext_name   - Name of the extension which applied policy
        param attribute     - The attribute being retrieved
        return              - The value of the attribute prior to policy application
        '''
        assert self.guid is not None, "gpo guid was not set"
        ext = self.guid.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is not None:
            attr = ext.find('attribute[@name="%s"]' % attribute)
            if attr is not None:
                return attr.text
        return None

    def list(self, gp_extensions):
        ''' Return a list of attributes, their previous values, and functions to set them
        param gp_extensions - list of extension objects, for retrieving attr to func mappings
        return              - list of (attr, value, apply_func) tuples for unapplying policy
        '''
        assert self.guid is not None, "gpo guid was not set"
        ret = []
        data_maps = {}
        for gp_ext in gp_extensions:
            data_maps.update(gp_ext.apply_map())
        exts = self.guid.findall('gp_ext')
        if exts is not None:
            for ext in exts:
                ext_map = {val[0]: val[1] for (key, val) in data_maps[ext.attrib['name']].items()}
                attrs = ext.findall('attribute')
                for attr in attrs:
                    ret.append((attr.attrib['name'], attr.text, ext_map[attr.attrib['name']]))
        return ret

    def delete(self, gp_ext_name, attribute):
        ''' Remove an attribute from the gp_log
        param gp_ext_name   - name of extension from which to remove the attribute
        param attribute     - attribute to remove
        '''
        assert self.guid is not None, "gpo guid was not set"
        ext = self.guid.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is not None:
            attr = ext.find('attribute[@name="%s"]' % attribute)
            if attr is not None:
                ext.remove(attr)
                if len(ext) == 0:
                    self.guid.remove(ext)

    def commit(self):
        ''' Write gp_log changes to disk '''
        if len(self.guid) == 0 and self.guid in self.user:
            self.user.remove(self.guid)
        if len(self.user) == 0 and self.user in self.gpdb:
            self.gpdb.remove(self.user)
        self.gpostore.store(self.username, etree.tostring(self.gpdb, 'utf-8'))

class GPOStorage:
    def __init__(self, log_file):
        if os.path.isfile(log_file):
            self.log = tdb.open(log_file)
        else:
            self.log = tdb.Tdb(log_file, 0, tdb.DEFAULT, os.O_CREAT|os.O_RDWR)

    def start(self):
        self.log.transaction_start()

    def get_int(self, key):
        try:
            return int(self.log.get(key))
        except TypeError:
            return None

    def get(self, key):
        return self.log.get(key)

    def get_gplog(self, user):
        return gp_log(user, self, self.log.get(user))

    def store(self, key, val):
        self.log.store(key, val)

    def cancel(self):
        self.log.transaction_cancel()

    def delete(self, key):
        self.log.delete(key)

    def commit(self):
        self.log.transaction_commit()

    def __del__(self):
        self.log.close()

class gp_ext(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def list(self, rootpath):
        pass

    @abstractmethod
    def apply_map(self):
        pass

    @abstractmethod
    def parse(self, afile, ldb, conn, gp_db, lp):
        pass

    @abstractmethod
    def __str__(self):
        pass

class inf_to():
    __metaclass__ = ABCMeta

    def __init__(self, logger, ldb, gp_db, lp, attribute, val):
        self.logger = logger
        self.ldb = ldb
        self.attribute = attribute
        self.val = val
        self.lp = lp
        self.gp_db = gp_db

    def explicit(self):
        return self.val

    def update_samba(self):
        (upd_sam, value) = self.mapper().get(self.attribute)
        upd_sam(value())

    @abstractmethod
    def mapper(self):
        pass

    @abstractmethod
    def __str__(self):
        pass

class inf_to_ldb(inf_to):
    '''This class takes the .inf file parameter (essentially a GPO file mapped to a GUID),
    hashmaps it to the Samba parameter, which then uses an ldb object to update the
    parameter to Samba4. Not registry oriented whatsoever.
    '''

    def ch_minPwdAge(self, val):
        old_val = self.ldb.get_minPwdAge()
        self.logger.info('KDC Minimum Password age was changed from %s to %s' % (old_val, val))
        self.gp_db.store(str(self), self.attribute, old_val)
        self.ldb.set_minPwdAge(val)

    def ch_maxPwdAge(self, val):
        old_val = self.ldb.get_maxPwdAge()
        self.logger.info('KDC Maximum Password age was changed from %s to %s' % (old_val, val))
        self.gp_db.store(str(self), self.attribute, old_val)
        self.ldb.set_maxPwdAge(val)

    def ch_minPwdLength(self, val):
        old_val = self.ldb.get_minPwdLength()
        self.logger.info('KDC Minimum Password length was changed from %s to %s' % (old_val, val))
        self.gp_db.store(str(self), self.attribute, old_val)
        self.ldb.set_minPwdLength(val)

    def ch_pwdProperties(self, val):
        old_val = self.ldb.get_pwdProperties()
        self.logger.info('KDC Password Properties were changed from %s to %s' % (old_val, val))
        self.gp_db.store(str(self), self.attribute, old_val)
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

    def __str__(self):
        return 'System Access'


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

    def apply_map(self):
        return {"System Access": {"MinimumPasswordAge": ("minPwdAge", inf_to_ldb),
                                  "MaximumPasswordAge": ("maxPwdAge", inf_to_ldb),
                                  "MinimumPasswordLength": ("minPwdLength", inf_to_ldb),
                                  "PasswordComplexity": ("pwdProperties", inf_to_ldb),
                                 }
               }

    def read_inf(self, path, conn):
        ret = False
        inftable = self.apply_map()

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
                    setter(self.logger, self.ldb, self.gp_db, self.lp, att, value).update_samba()
                    self.gp_db.commit()
        return ret

    def parse(self, afile, ldb, conn, gp_db, lp):
        self.ldb = ldb
        self.gp_db = gp_db
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


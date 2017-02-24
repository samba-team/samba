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

class gp_ext(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def list(self, rootpath):
        pass

    @abstractmethod
    def parse(self, afile, ldb, conn, attr_log, lp):
        pass

    @abstractmethod
    def __str__(self):
        pass


class inf_to():
    __metaclass__ = ABCMeta

    def __init__(self, logger, ldb, dn, lp, attribute, val):
        self.logger = logger
        self.ldb = ldb
        self.dn = dn
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
        path = "%s%s" % (rootpath, "MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf")
        return path

    def listmachpol(self, rootpath):
        path = "%s%s" % (rootpath, "Machine/Registry.pol")
        return path

    def listuserpol(self, rootpath):
        path = "%s%s" % (rootpath, "User/Registry.pol")
        return path

    def populate_inf(self):
        return {"System Access": {"MinimumPasswordAge": ("minPwdAge", inf_to_ldb),
                                  "MaximumPasswordAge": ("maxPwdAge", inf_to_ldb),
                                  "MinimumPasswordLength": ("minPwdLength", inf_to_ldb),
                                  "PasswordComplexity": ("pwdProperties", inf_to_ldb),
                                 }
               }

    def read_inf(self, path, conn, attr_log):
        ret = False
        inftable = self.populate_inf()

        policy = conn.loadfile(path.replace('/', '\\')).decode('utf-16')
        current_section = None
        LOG = open(attr_log, "a")
        LOG.write(str(path.split('/')[2]) + '\n')

        # So here we would declare a boolean,
        # that would get changed to TRUE.
        #
        # If at any point in time a GPO was applied,
        # then we return that boolean at the end.

        inf_conf = ConfigParser()
        inf_conf.optionxform=str
        inf_conf.readfp(StringIO(policy))

        for section in inf_conf.sections():
            current_section = inftable.get(section)
            if not current_section:
                continue
            for key, value in inf_conf.items(section):
                if current_section.get(key):
                    (att, setter) = current_section.get(key)
                    value = value.encode('ascii', 'ignore')
                    ret = True
                    setter(self.logger, self.ldb, self.dn, self.lp, att, value).update_samba()
        return ret

    def parse(self, afile, ldb, conn, attr_log, lp):
        self.ldb = ldb
        self.lp = lp
        self.dn = ldb.get_default_basedn()

        # Fixing the bug where only some Linux Boxes capitalize MACHINE
        if afile.endswith('inf'):
            try:
                blist = afile.split('/')
                idx = afile.lower().split('/').index('machine')
                for case in [blist[idx].upper(), blist[idx].capitalize(), blist[idx].lower()]:
                    bfile = '/'.join(blist[:idx]) + '/' + case + '/' + '/'.join(blist[idx+1:])
                    try:
                        return self.read_inf(bfile, conn, attr_log)
                    except NTSTATUSError:
                        continue
            except ValueError:
                try:
                    return self.read_inf(afile, conn, attr_log)
                except:
                    return None


def scan_log(sysvol_tdb):
    data = {}
    for key in sysvol_tdb.iterkeys():
        data[key] = sysvol_tdb.get(key)
    return data


def Reset_Defaults(test_ldb):
    test_ldb.set_minPwdAge(str(-25920000000000))
    test_ldb.set_maxPwdAge(str(-38016000000000))
    test_ldb.set_minPwdLength(str(7))
    test_ldb.set_pwdProperties(str(1))


def check_deleted(guid_list, backloggpo):
    if backloggpo is None:
        return False
    for guid in backloggpo:
        if guid not in guid_list:
            return True
    return False


# The hierarchy is as per MS http://msdn.microsoft.com/en-us/library/windows/desktop/aa374155%28v=vs.85%29.aspx
#
# It does not care about local GPO, because GPO and snap-ins are not made in Linux yet.
# It follows the linking order and children GPO are last written format.
#
# Also, couple further testing with call scripts entitled informant and informant2.
# They explicitly show the returned hierarchically sorted list.


def container_indexes(GUID_LIST):
    '''So the original list will need to be seperated into containers.
    Returns indexed list of when the container changes after hierarchy
    '''
    count = 0
    container_indexes = []
    while count < (len(GUID_LIST)-1):
        if GUID_LIST[count][2] != GUID_LIST[count+1][2]:
            container_indexes.append(count+1)
        count += 1
    container_indexes.append(len(GUID_LIST))
    return container_indexes


def sort_linked(SAMDB, guid_list, start, end):
    '''So GPO in same level need to have link level.
    This takes a container and sorts it.

    TODO:  Small small problem, it is backwards
    '''
    containers = gpo_user.get_gpo_containers(SAMDB, guid_list[start][0])
    for right_container in containers:
        if right_container.get('dn') == guid_list[start][2]:
            break
    gplink = str(right_container.get('gPLink'))
    gplink_split = gplink.split('[')
    linked_order = []
    ret_list = []
    for ldap_guid in gplink_split:
        linked_order.append(str(ldap_guid[10:48]))
    count = len(linked_order) - 1
    while count > 0:
        ret_list.append([linked_order[count], guid_list[start][1], guid_list[start][2]])
        count -= 1
    return ret_list


def establish_hierarchy(SamDB, GUID_LIST, DC_OU, global_dn):
    '''Takes a list of GUID from gpo, and sorts them based on OU, and realm.
    See http://msdn.microsoft.com/en-us/library/windows/desktop/aa374155%28v=vs.85%29.aspx
    '''
    final_list = []
    count_unapplied_GPO = 0
    for GUID in GUID_LIST:

        container_iteration = 0
        # Assume first it is not applied
        applied = False
        # Realm only written on last call, if the GPO is linked to multiple places
        gpo_realm = False

        # A very important call. This gets all of the linked information.
        GPO_CONTAINERS = gpo_user.get_gpo_containers(SamDB, GUID)
        for GPO_CONTAINER in GPO_CONTAINERS:

            container_iteration += 1

            if DC_OU == str(GPO_CONTAINER.get('dn')):
                applied = True
                insert_gpo = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                final_list.append(insert_gpo)
                break

            if global_dn == str(GPO_CONTAINER.get('dn')) and (len(GPO_CONTAINERS) == 1):
                gpo_realm = True
                applied = True


            if global_dn == str(GPO_CONTAINER.get('dn')) and (len(GPO_CONTAINERS) > 1):
                gpo_realm = True
                applied = True


            if container_iteration == len(GPO_CONTAINERS):
                if gpo_realm == False:
                    insert_dud = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                    final_list.insert(0, insert_dud)
                    count_unapplied_GPO += 1
                else:
                    REALM_GPO = [GUID, applied, str(GPO_CONTAINER.get('dn'))]
                    final_list.insert(count_unapplied_GPO, REALM_GPO)

    # After GPO are sorted into containers, let's sort the containers themselves.
    # But first we can get the GPO that we don't care about, out of the way.
    indexed_places = container_indexes(final_list)
    count = 0
    unapplied_gpo = []
    # Sorted by container
    sorted_gpo_list = []

    # Unapplied GPO live at start of list, append them to final list
    while final_list[0][1] == False:
        unapplied_gpo.append(final_list[count])
        count += 1
    count = 0
    sorted_gpo_list += unapplied_gpo

    # A single container call gets the linked order for all GPO in container.
    # So we need one call per container - > index of the Original list
    indexed_places.insert(0, 0)
    while count < (len(indexed_places)-1):
        sorted_gpo_list += (sort_linked(SamDB, final_list, indexed_places[count], indexed_places[count+1]))
        count += 1
    return sorted_gpo_list

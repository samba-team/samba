# Utilities for working with policies in SYSVOL Registry.pol files
#
# Copyright (C) David Mulder <dmulder@samba.org> 2022
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

import json
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import preg
from samba.netcmd.common import netcmd_finddc
from samba.netcmd.gpcommon import create_directory_hier, smb_connection
from samba import NTSTATUSError
from numbers import Number
from samba.registry import str_regtype
from samba.ntstatus import (
    NT_STATUS_OBJECT_NAME_INVALID,
    NT_STATUS_OBJECT_NAME_NOT_FOUND,
    NT_STATUS_OBJECT_PATH_NOT_FOUND
)

class RegistryGroupPolicies(object):
    def __init__(self, gpo, lp, creds, host=None):
        self.gpo = gpo
        self.lp = lp
        self.creds = creds
        realm = self.lp.get('realm')
        self.pol_dir = '\\'.join([realm.lower(), 'Policies', gpo, '%s'])
        self.pol_file = '\\'.join([self.pol_dir, 'Registry.pol'])


        if host and host.startswith('ldap://'):
            dc_hostname = host[7:]
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)

        self.conn = smb_connection(dc_hostname,
                                   'sysvol',
                                   lp=self.lp,
                                   creds=self.creds)

    def __load_registry_pol(self, pol_file):
        try:
            pol_data = ndr_unpack(preg.file, self.conn.loadfile(pol_file))
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                pol_data = preg.file() # The file doesn't exist
            else:
                raise
        return pol_data

    def __save_registry_pol(self, pol_dir, pol_file, pol_data):
        create_directory_hier(self.conn, pol_dir)
        self.conn.savefile(pol_file, ndr_pack(pol_data))

    def __validate_json(self, json_input, remove=False):
        if type(json_input) != list:
            raise SyntaxError('JSON not formatted correctly')
        for entry in json_input:
            if type(entry) != dict:
                raise SyntaxError('JSON not formatted correctly')
            keys = ['keyname', 'valuename', 'class']
            if not remove:
                keys.extend(['data', 'type'])
            if not all([k in entry for k in keys]):
                raise SyntaxError('JSON not formatted correctly')

    def __determine_data_type(self, entry):
        if isinstance(entry['type'], Number):
            return entry['type']
        else:
            for i in range(12):
                if str_regtype(i) == entry['type'].upper():
                    return i
        return 0 # REG_NONE

    def __pol_replace(self, pol_data, entry):
        for e in pol_data.entries:
            if e.keyname == entry['keyname'] and \
               e.valuename == entry['valuename']:
                e.data = entry['data']
                break
        else:
            e = preg.entry()
            e.keyname = entry['keyname']
            e.valuename = entry['valuename']
            e.type = self.__determine_data_type(entry)
            e.data = entry['data']
            entries = list(pol_data.entries)
            entries.append(e)
            pol_data.entries = entries
            pol_data.num_entries = len(entries)

    def __pol_remove(self, pol_data, entry):
        entries = []
        for e in pol_data.entries:
            if not (e.keyname == entry['keyname'] and \
                    e.valuename == entry['valuename']):
                entries.append(e)
        pol_data.entries = entries
        pol_data.num_entries = len(entries)

    def remove_s(self, json_input):
        '''remove_s
        json_input: JSON list of entries to remove from GPO

        Example json_input:
        [
            {
                "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
                "valuename": "StartPage",
                "class": "USER",
            },
            {
                "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
                "valuename": "URL",
                "class": "USER",
            },
        ]
        '''
        self.__validate_json(json_input, remove=True)
        user_pol_data = self.__load_registry_pol(self.pol_file % 'User')
        machine_pol_data = self.__load_registry_pol(self.pol_file % 'Machine')

        for entry in json_input:
            cls = entry['class'].lower()
            if cls == 'machine' or cls == 'both':
                self.__pol_remove(machine_pol_data, entry)
            if cls == 'user' or cls == 'both':
                self.__pol_remove(user_pol_data, entry)
        self.__save_registry_pol(self.pol_dir % 'User',
                                 self.pol_file % 'User',
                                 user_pol_data)
        self.__save_registry_pol(self.pol_dir % 'Machine',
                                 self.pol_file % 'Machine',
                                 machine_pol_data)

    def merge_s(self, json_input):
        '''merge_s
        json_input: JSON list of entries to merge into GPO

        Example json_input:
        [
            {
                "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
                "valuename": "StartPage",
                "class": "USER",
                "type": "REG_SZ",
                "data": "homepage"
            },
            {
                "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
                "valuename": "URL",
                "class": "USER",
                "type": "REG_SZ",
                "data": "google.com"
            },
        ]
        '''
        self.__validate_json(json_input)
        user_pol_data = self.__load_registry_pol(self.pol_file % 'User')
        machine_pol_data = self.__load_registry_pol(self.pol_file % 'Machine')

        for entry in json_input:
            cls = entry['class'].lower()
            if cls == 'machine' or cls == 'both':
                self.__pol_replace(machine_pol_data, entry)
            if cls == 'user' or cls == 'both':
                self.__pol_replace(user_pol_data, entry)
        self.__save_registry_pol(self.pol_dir % 'User',
                                 self.pol_file % 'User',
                                 user_pol_data)
        self.__save_registry_pol(self.pol_dir % 'Machine',
                                 self.pol_file % 'Machine',
                                 machine_pol_data)

    def replace_s(self, json_input):
        '''replace_s
        json_input: JSON list of entries to replace entries in GPO

        Example json_input:
        [
            {
                "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
                "valuename": "StartPage",
                "class": "USER",
                "data": "homepage"
            },
            {
                "keyname": "Software\\Policies\\Mozilla\\Firefox\\Homepage",
                "valuename": "URL",
                "class": "USER",
                "data": "google.com"
            },
        ]
        '''
        self.__validate_json(json_input)
        user_pol_data = preg.file()
        machine_pol_data = preg.file()

        for entry in json_input:
            cls = entry['class'].lower()
            if cls == 'machine' or cls == 'both':
                self.__pol_replace(machine_pol_data, entry)
            if cls == 'user' or cls == 'both':
                self.__pol_replace(user_pol_data, entry)
        if user_pol_data.num_entries > 0:
            self.__save_registry_pol(self.pol_dir % 'User',
                                     self.pol_file % 'User',
                                     user_pol_data)
        if machine_pol_data.num_entries > 0:
            self.__save_registry_pol(self.pol_dir % 'Machine',
                                     self.pol_file % 'Machine',
                                     machine_pol_data)

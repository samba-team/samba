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

from io import StringIO
import ldb
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import preg
from samba.netcmd.common import netcmd_finddc
from samba.netcmd.gpcommon import (
    create_directory_hier,
    smb_connection,
    get_gpo_dn
)
from samba import NTSTATUSError
from numbers import Number
from samba.registry import str_regtype
from samba.ntstatus import (
    NT_STATUS_OBJECT_NAME_INVALID,
    NT_STATUS_OBJECT_NAME_NOT_FOUND,
    NT_STATUS_OBJECT_PATH_NOT_FOUND,
    NT_STATUS_INVALID_PARAMETER
)
from samba.gp_parse.gp_ini import GPTIniParser
from samba.common import get_string
from samba.dcerpc import security
from samba.ntacls import dsacl2fsacl
from samba.dcerpc.misc import REG_BINARY, REG_MULTI_SZ, REG_SZ, GUID

GPT_EMPTY = \
"""
[General]
Version=0
"""

class RegistryGroupPolicies(object):
    def __init__(self, gpo, lp, creds, samdb, host=None):
        self.gpo = gpo
        self.lp = lp
        self.creds = creds
        self.samdb = samdb
        realm = self.lp.get('realm')
        self.pol_dir = '\\'.join([realm.lower(), 'Policies', gpo, '%s'])
        self.pol_file = '\\'.join([self.pol_dir, 'Registry.pol'])
        self.policy_dn = get_gpo_dn(self.samdb, self.gpo)

        if host and host.startswith('ldap://'):
            dc_hostname = host[7:]
        else:
            dc_hostname = netcmd_finddc(self.lp, self.creds)

        self.conn = smb_connection(dc_hostname,
                                   'sysvol',
                                   lp=self.lp,
                                   creds=self.creds)

        # Get new security descriptor
        ds_sd_flags = (security.SECINFO_OWNER |
                       security.SECINFO_GROUP |
                       security.SECINFO_DACL)
        msg = self.samdb.search(base=self.policy_dn, scope=ldb.SCOPE_BASE,
                                attrs=['nTSecurityDescriptor'])[0]
        ds_sd_ndr = msg['nTSecurityDescriptor'][0]
        ds_sd = ndr_unpack(security.descriptor, ds_sd_ndr).as_sddl()

        # Create a file system security descriptor
        domain_sid = security.dom_sid(self.samdb.get_domain_sid())
        self.fs_sd = dsacl2fsacl(ds_sd, domain_sid, as_sddl=False)

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

    def __save_file(self, file_dir, file_name, data):
        create_directory_hier(self.conn, file_dir)
        self.conn.savefile(file_name, data)
        self.conn.set_acl(file_name, self.fs_sd)

    def __save_registry_pol(self, pol_dir, pol_file, pol_data):
        self.__save_file(pol_dir, pol_file, ndr_pack(pol_data))

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
        raise TypeError('Unknown type %s' % entry['type'])

    def __set_data(self, rtype, data):
        # JSON can't store bytes, and have to be set via an int array
        if rtype == REG_BINARY and type(data) == list:
            return bytes(data)
        elif rtype == REG_MULTI_SZ and type(data) == list:
            data = ('\x00').join(data) + '\x00\x00'
            return data.encode('utf-16-le')
        elif rtype == REG_SZ and type(data) == str:
            return data.encode('utf-8')
        return data

    def __pol_replace(self, pol_data, entry):
        for e in pol_data.entries:
            if e.keyname == entry['keyname'] and \
               e.valuename == entry['valuename']:
                e.data = self.__set_data(e.type, entry['data'])
                break
        else:
            e = preg.entry()
            e.keyname = entry['keyname']
            e.valuename = entry['valuename']
            e.type = self.__determine_data_type(entry)
            e.data = self.__set_data(e.type, entry['data'])
            entries = list(pol_data.entries)
            entries.append(e)
            pol_data.entries = entries
            pol_data.num_entries = len(entries)

    def __pol_remove(self, pol_data, entry):
        entries = []
        for e in pol_data.entries:
            if not (e.keyname == entry['keyname'] and
                    e.valuename == entry['valuename']):
                entries.append(e)
        pol_data.entries = entries
        pol_data.num_entries = len(entries)

    def increment_gpt_ini(self, machine_changed=False, user_changed=False):
        if not machine_changed and not user_changed:
            return
        GPT_INI = self.pol_dir % 'GPT.INI'
        try:
            data = self.conn.loadfile(GPT_INI)
        except NTSTATUSError as e:
            if e.args[0] in [NT_STATUS_OBJECT_NAME_INVALID,
                             NT_STATUS_OBJECT_NAME_NOT_FOUND,
                             NT_STATUS_OBJECT_PATH_NOT_FOUND]:
                data = GPT_EMPTY
            else:
                raise
        parser = GPTIniParser()
        parser.parse(data)
        version = 0
        machine_version = 0
        user_version = 0
        if parser.ini_conf.has_option('General', 'Version'):
            version = int(parser.ini_conf.get('General',
                                              'Version').encode('utf-8'))
            machine_version = version & 0x0000FFFF
            user_version = version >> 16
        if machine_changed:
            machine_version += 1
        if user_changed:
            user_version += 1
        version = (user_version << 16) + machine_version

        # Set the new version in the GPT.INI
        if not parser.ini_conf.has_section('General'):
            parser.ini_conf.add_section('General')
        parser.ini_conf.set('General', 'Version', str(version))
        with StringIO() as out_data:
            parser.ini_conf.write(out_data)
            out_data.seek(0)
            self.__save_file(self.pol_dir % '', GPT_INI,
                             out_data.read().encode('utf-8'))

        # Set the new versionNumber on the ldap object
        m = ldb.Message()
        m.dn = self.policy_dn
        m['new_value'] = ldb.MessageElement(str(version), ldb.FLAG_MOD_REPLACE,
                                            'versionNumber')
        self.samdb.modify(m)

    def __validate_extension_registration(self, ext_name, ext_attr):
        try:
            ext_name_guid = GUID(ext_name)
        except NTSTATUSError as e:
            if e.args[0] == NT_STATUS_INVALID_PARAMETER:
                raise SyntaxError('Extension name not formatted correctly')
            raise
        if ext_attr not in ['gPCMachineExtensionNames',
                            'gPCUserExtensionNames']:
            raise SyntaxError('Extension attribute incorrect')
        return '{%s}' % ext_name_guid

    def register_extension_name(self, ext_name, ext_attr):
        ext_name = self.__validate_extension_registration(ext_name, ext_attr)
        res = self.samdb.search(base=self.policy_dn, scope=ldb.SCOPE_BASE,
                                attrs=[ext_attr])
        if len(res) == 0 or ext_attr not in res[0]:
            ext_names = '[]'
        else:
            ext_names = get_string(res[0][ext_attr][-1])
        if ext_name not in ext_names:
            ext_names = '[' + ext_names.strip('[]') + ext_name + ']'
        else:
            return

        m = ldb.Message()
        m.dn = self.policy_dn
        m['new_value'] = ldb.MessageElement(ext_names, ldb.FLAG_MOD_REPLACE,
                                            ext_attr)
        self.samdb.modify(m)

    def unregister_extension_name(self, ext_name, ext_attr):
        ext_name = self.__validate_extension_registration(ext_name, ext_attr)
        res = self.samdb.search(base=self.policy_dn, scope=ldb.SCOPE_BASE,
                                attrs=[ext_attr])
        if len(res) == 0 or ext_attr not in res[0]:
            return
        else:
            ext_names = get_string(res[0][ext_attr][-1])
        if ext_name in ext_names:
            ext_names = ext_names.replace(ext_name, '')
        else:
            return

        m = ldb.Message()
        m.dn = self.policy_dn
        m['new_value'] = ldb.MessageElement(ext_names, ldb.FLAG_MOD_REPLACE,
                                            ext_attr)
        self.samdb.modify(m)

    def remove_s(self, json_input):
        """remove_s
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
        """
        self.__validate_json(json_input, remove=True)
        user_pol_data = self.__load_registry_pol(self.pol_file % 'User')
        machine_pol_data = self.__load_registry_pol(self.pol_file % 'Machine')

        machine_changed = False
        user_changed = False
        for entry in json_input:
            cls = entry['class'].lower()
            if cls == 'machine' or cls == 'both':
                machine_changed = True
                self.__pol_remove(machine_pol_data, entry)
            if cls == 'user' or cls == 'both':
                user_changed = True
                self.__pol_remove(user_pol_data, entry)
        if user_changed:
            self.__save_registry_pol(self.pol_dir % 'User',
                                     self.pol_file % 'User',
                                     user_pol_data)
        if machine_changed:
            self.__save_registry_pol(self.pol_dir % 'Machine',
                                     self.pol_file % 'Machine',
                                     machine_pol_data)
        self.increment_gpt_ini(machine_changed, user_changed)

    def merge_s(self, json_input):
        """merge_s
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
        """
        self.__validate_json(json_input)
        user_pol_data = self.__load_registry_pol(self.pol_file % 'User')
        machine_pol_data = self.__load_registry_pol(self.pol_file % 'Machine')

        machine_changed = False
        user_changed = False
        for entry in json_input:
            cls = entry['class'].lower()
            if cls == 'machine' or cls == 'both':
                machine_changed = True
                self.__pol_replace(machine_pol_data, entry)
            if cls == 'user' or cls == 'both':
                user_changed = True
                self.__pol_replace(user_pol_data, entry)
        if user_changed:
            self.__save_registry_pol(self.pol_dir % 'User',
                                     self.pol_file % 'User',
                                     user_pol_data)
        if machine_changed:
            self.__save_registry_pol(self.pol_dir % 'Machine',
                                     self.pol_file % 'Machine',
                                     machine_pol_data)
        self.increment_gpt_ini(machine_changed, user_changed)

    def replace_s(self, json_input):
        """replace_s
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
        """
        self.__validate_json(json_input)
        user_pol_data = preg.file()
        machine_pol_data = preg.file()

        machine_changed = False
        user_changed = False
        for entry in json_input:
            cls = entry['class'].lower()
            if cls == 'machine' or cls == 'both':
                machine_changed = True
                self.__pol_replace(machine_pol_data, entry)
            if cls == 'user' or cls == 'both':
                user_changed = True
                self.__pol_replace(user_pol_data, entry)
        if user_changed:
            self.__save_registry_pol(self.pol_dir % 'User',
                                     self.pol_file % 'User',
                                     user_pol_data)
        if machine_changed:
            self.__save_registry_pol(self.pol_dir % 'Machine',
                                     self.pol_file % 'Machine',
                                     machine_pol_data)
        self.increment_gpt_ini(machine_changed, user_changed)

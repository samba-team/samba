# gp_gnome_settings_ext samba gpo policy
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
from tempfile import NamedTemporaryFile
import shutil
from configparser import ConfigParser
from subprocess import Popen, PIPE
from samba.common import get_bytes, get_string
from glob import glob
import xml.etree.ElementTree as etree

def dconf_update(log, test_dir):
    if test_dir is not None:
        return
    dconf = shutil.which('dconf')
    if dconf is None:
        log.error('Failed to update dconf. Command not found')
        return
    p = Popen([dconf, 'update'], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        log.error('Failed to update dconf: %s' % get_string(err))

def create_locks_dir(test_dir):
    locks_dir = '/etc/dconf/db/local.d/locks'
    if test_dir is not None:
        locks_dir = os.path.join(test_dir, locks_dir[1:])
    os.makedirs(locks_dir, exist_ok=True)
    return locks_dir

def create_user_profile(test_dir):
    user_profile = '/etc/dconf/profile/user'
    if test_dir is not None:
        user_profile = os.path.join(test_dir, user_profile[1:])
    if os.path.exists(user_profile):
        return
    os.makedirs(os.path.dirname(user_profile), exist_ok=True)
    with NamedTemporaryFile('w', dir=os.path.dirname(user_profile),
                            delete=False) as w:
        w.write('user-db:user\nsystem-db:local')
        fname = w.name
    shutil.move(fname, user_profile)

def create_local_db(test_dir):
    local_db = '/etc/dconf/db/local.d'
    if test_dir is not None:
        local_db = os.path.join(test_dir, local_db[1:])
    os.makedirs(local_db, exist_ok=True)
    return local_db

def select_next_conf(directory, fname=''):
    configs = [re.match(r'(\d+)%s' % fname, f) for f in os.listdir(directory)]
    return max([int(m.group(1)) for m in configs if m]+[0])+1

class gp_gnome_settings_ext(gp_pol_ext):
    def __init__(self, *args):
        super().__init__(*args)
        self.keys = ['Compose Key',
                     'Dim Screen when User is Idle',
                     'Lock Down Specific Settings',
                     'Whitelisted Online Accounts',
                     'Enabled Extensions']
        self.lock_down_settings = {}
        self.test_dir = None

    def __str__(self):
        return 'GNOME Settings/Lock Down Settings'

    def __add_lockdown_data(self, k, e):
        if k not in self.lock_down_settings:
            self.lock_down_settings[k] = {}
        self.lock_down_settings[k][e.valuename] = e.data

    def __enable_lockdown_data(self, e):
        if e.valuename not in self.lock_down_settings:
            self.lock_down_settings[e.valuename] = {}
        self.lock_down_settings[e.valuename]['Enabled'] = e.data == 1

    def __apply_compose_key(self, data):
        attribute = self.keys[0]
        old_val = self.gp_db.retrieve(str(self), attribute)
        create_user_profile(self.test_dir)
        local_db_dir = create_local_db(self.test_dir)

        if old_val is not None:
            # Overwrite the old policy if it exists
            local_db, lock = old_val.split(';')
        else:
            conf_id = select_next_conf(local_db_dir, '-input-sources')
            local_db = os.path.join(local_db_dir,
                                    '%010d-input-sources' % conf_id)
        data_map = { 'Right Alt': 'compose:ralt',
                     'Left Win': 'compose:lwin',
                     '3rd level of Left Win': 'compose:lwin-altgr',
                     'Right Win': 'compose:rwin',
                     '3rd level of Right Win': 'compose:rwin-altgr',
                     'Menu': 'compose:menu',
                     '3rd level of Menu': 'compose:menu-altgr',
                     'Left Ctrl': 'compose:lctrl',
                     '3rd level of Left Ctrl': 'compose:lctrl-altgr',
                     'Right Ctrl': 'compose:rctrl',
                     '3rd level of Right Ctrl': 'compose:rctrl-altgr',
                     'Caps Lock': 'compose:caps',
                     '3rd level of Caps Lock': 'compose:caps-altgr',
                     'The "< >" key': 'compose:102',
                     '3rd level of the "< >" key': 'compose:102-altgr',
                     'Pause': 'compose:paus',
                     'PrtSc': 'compose:prsc',
                     'Scroll Lock': 'compose:sclk'
                   }
        if data['Key Name'] not in data_map.keys():
            self.logger.error('Compose Key \'%s\' not recognized' % \
                              data['Key Name'])
            return
        parser = ConfigParser()
        section = 'org/gnome/desktop/input-sources'
        parser.add_section(section)
        parser.set(section, 'xkb-options',
                   "['%s']" % data_map[data['Key Name']])
        with open(local_db, 'w') as w:
            parser.write(w)

        # Lock xkb-options
        locks_dir = create_locks_dir(self.test_dir)
        if old_val is None:
            conf_id = select_next_conf(locks_dir)
            lock = os.path.join(locks_dir, '%010d-input-sources' % conf_id)
        with open(lock, 'w') as w:
            w.write('/org/gnome/desktop/input-sources/xkb-options')

        dconf_update(self.logger, self.test_dir)
        self.gp_db.store(str(self), attribute, ';'.join([local_db, lock]))

    def __apply_dim_idle(self, data):
        attribute = self.keys[1]
        old_val = self.gp_db.retrieve(str(self), attribute)
        create_user_profile(self.test_dir)
        local_db_dir = create_local_db(self.test_dir)
        if old_val is not None:
            # Overwrite the old policy if it exists
            local_power_db, local_session_db, lock = old_val.split(';')
        else:
            conf_id = select_next_conf(local_db_dir, '-power')
            local_power_db = os.path.join(local_db_dir, '%010d-power' % conf_id)
        parser = ConfigParser()
        section = 'org/gnome/settings-daemon/plugins/power'
        parser.add_section(section)
        parser.set(section, 'idle-dim', 'true')
        parser.set(section, 'idle-brightness', str(data['Dim Idle Brightness']))
        with open(local_power_db, 'w') as w:
            parser.write(w)
        if old_val is None:
            conf_id = select_next_conf(local_db_dir, '-session')
            local_session_db = os.path.join(local_db_dir, '%010d-session' % conf_id)
        parser = ConfigParser()
        section = 'org/gnome/desktop/session'
        parser.add_section(section)
        parser.set(section, 'idle-delay', 'uint32 %d' % data['Delay'])
        with open(local_session_db, 'w') as w:
            parser.write(w)

        # Lock power-saving
        locks_dir = create_locks_dir(self.test_dir)
        if old_val is None:
            conf_id = select_next_conf(locks_dir)
            lock = os.path.join(locks_dir, '%010d-power-saving' % conf_id)
        with open(lock, 'w') as w:
            w.write('/org/gnome/settings-daemon/plugins/power/idle-dim\n')
            w.write('/org/gnome/settings-daemon/plugins/power/idle-brightness\n')
            w.write('/org/gnome/desktop/session/idle-delay')

        dconf_update(self.logger, self.test_dir)
        self.gp_db.store(str(self), attribute, ';'.join([local_power_db,
                                                         local_session_db,
                                                         lock]))

    def __apply_specific_settings(self, data):
        attribute = self.keys[2]
        old_val = self.gp_db.retrieve(str(self), attribute)
        create_user_profile(self.test_dir)
        locks_dir = create_locks_dir(self.test_dir)
        if old_val is not None:
            # Overwrite the old policy if it exists
            policy_file = old_val
        else:
            conf_id = select_next_conf(locks_dir, '-group-policy')
            policy_file = os.path.join(locks_dir, '%010d-group-policy' % conf_id)
        with open(policy_file, 'w') as w:
            for key in data.keys():
                w.write('%s\n' % key)
        dconf_update(self.logger, self.test_dir)
        self.gp_db.store(str(self), attribute, policy_file)

    def __apply_whitelisted_account(self, data):
        attribute = self.keys[3]
        old_val = self.gp_db.retrieve(str(self), attribute)
        create_user_profile(self.test_dir)
        local_db_dir = create_local_db(self.test_dir)
        locks_dir = create_locks_dir(self.test_dir)
        val = "['%s']" % "', '".join(data.keys())
        policy_files = self.__lockdown(local_db_dir, locks_dir, 'goa',
                                       'whitelisted-providers', val, old_val,
                                       'org/gnome/online-accounts')
        dconf_update(self.logger, self.test_dir)
        self.gp_db.store(str(self), attribute, ';'.join(policy_files))

    def __apply_enabled_extensions(self, data):
        attribute = self.keys[4]
        old_val = self.gp_db.retrieve(str(self), attribute)
        create_user_profile(self.test_dir)
        local_db_dir = create_local_db(self.test_dir)
        if old_val is not None:
            # Overwrite the old policy if it exists
            policy_file = old_val
        else:
            conf_id = select_next_conf(local_db_dir)
            policy_file = os.path.join(local_db_dir, '%010d-extensions' % conf_id)
        parser = ConfigParser()
        section = 'org/gnome/shell'
        parser.add_section(section)
        exts = data.keys()
        parser.set(section, 'enabled-extensions', "['%s']" % "', '".join(exts))
        parser.set(section, 'development-tools', 'false')
        with open(policy_file, 'w') as w:
            parser.write(w)
        dconf_update(self.logger, self.test_dir)
        self.gp_db.store(str(self), attribute, policy_file)

    def __lockdown(self, local_db_dir, locks_dir, name, key, val,
                   old_val, section='org/gnome/desktop/lockdown'):
        if old_val is None:
            policy_files = []
            conf_id = select_next_conf(local_db_dir)
            policy_file = os.path.join(local_db_dir,
                                       '%010d-%s' % (conf_id, name))
            policy_files.append(policy_file)
            conf_id = select_next_conf(locks_dir)
            lock = os.path.join(locks_dir, '%010d-%s' % (conf_id, name))
            policy_files.append(lock)
        else:
            policy_files = old_val.split(';')
            policy_file, lock = policy_files
        parser = ConfigParser()
        parser.add_section(section)
        parser.set(section, key, val)
        with open(policy_file, 'w') as w:
            parser.write(w)
        with open(lock, 'w') as w:
            w.write('/%s/%s' % (section, key))
        return policy_files

    def __apply_enabled(self, k):
        old_val = self.gp_db.retrieve(str(self), k)
        if old_val is not None:
            # Overwrite the old policy if it exists
            policy_files = old_val.split(';')
        else:
            policy_files = []

        create_user_profile(self.test_dir)
        local_db_dir = create_local_db(self.test_dir)
        locks_dir = create_locks_dir(self.test_dir)

        if k == 'Lock Down Enabled Extensions':
            if old_val is None:
                conf_id = select_next_conf(locks_dir)
                policy_file = os.path.join(locks_dir, '%010d-extensions' % conf_id)
                policy_files.append(policy_file)
            else:
                policy_file, = policy_files
            with open(policy_file, 'w') as w:
                w.write('/org/gnome/shell/enabled-extensions\n')
                w.write('/org/gnome/shell/development-tools')
        elif k == 'Disable Printing':
            policy_files = self.__lockdown(local_db_dir, locks_dir, 'printing',
                                           'disable-printing', 'true', old_val)
        elif k == 'Disable File Saving':
            policy_files = self.__lockdown(local_db_dir, locks_dir,
                                           'filesaving',
                                           'disable-save-to-disk', 'true',
                                           old_val)
        elif k == 'Disable Command-Line Access':
            policy_files = self.__lockdown(local_db_dir, locks_dir, 'cmdline',
                                           'disable-command-line', 'true',
                                           old_val)
        elif k == 'Disallow Login Using a Fingerprint':
            policy_files = self.__lockdown(local_db_dir, locks_dir,
                                           'fingerprintreader',
                                           'enable-fingerprint-authentication',
                                           'false', old_val,
                                           section='org/gnome/login-screen')
        elif k == 'Disable User Logout':
            policy_files = self.__lockdown(local_db_dir, locks_dir, 'logout',
                                           'disable-log-out', 'true', old_val)
        elif k == 'Disable User Switching':
            policy_files = self.__lockdown(local_db_dir, locks_dir, 'logout',
                                           'disable-user-switching', 'true',
                                           old_val)
        elif k == 'Disable Repartitioning':
            actions = '/usr/share/polkit-1/actions'
            udisk2 = glob(os.path.join(actions,
                          'org.freedesktop.[u|U][d|D]isks2.policy'))
            if len(udisk2) == 1:
                udisk2 = udisk2[0]
            else:
                udisk2 = os.path.join(actions,
                                      'org.freedesktop.UDisks2.policy')
            udisk2_etc = os.path.join('/etc/share/polkit-1/actions',
                                      os.path.basename(udisk2))
            if self.test_dir is not None:
                udisk2_etc = os.path.join(self.test_dir, udisk2_etc[1:])
            os.makedirs(os.path.dirname(udisk2_etc), exist_ok=True)
            xml_data = etree.ElementTree(etree.Element('policyconfig'))
            if os.path.exists(udisk2):
                data = open(udisk2, 'rb').read()
                existing_xml = etree.ElementTree(etree.fromstring(data))
                root = xml_data.getroot()
                root.append(existing_xml.find('vendor'))
                root.append(existing_xml.find('vendor_url'))
                root.append(existing_xml.find('icon_name'))
            else:
                vendor = etree.SubElement(xml_data.getroot(), 'vendor')
                vendor.text = 'The Udisks Project'
                vendor_url = etree.SubElement(xml_data.getroot(), 'vendor_url')
                vendor_url.text = 'https://github.com/storaged-project/udisks'
                icon_name = etree.SubElement(xml_data.getroot(), 'icon_name')
                icon_name.text = 'drive-removable-media'
            action = etree.SubElement(xml_data.getroot(), 'action')
            action.attrib['id'] = 'org.freedesktop.udisks2.modify-device'
            description = etree.SubElement(action, 'description')
            description.text = 'Modify the drive settings'
            message = etree.SubElement(action, 'message')
            message.text = 'Authentication is required to modify drive settings'
            defaults = etree.SubElement(action, 'defaults')
            allow_any = etree.SubElement(defaults, 'allow_any')
            allow_any.text = 'no'
            allow_inactive = etree.SubElement(defaults, 'allow_inactive')
            allow_inactive.text = 'no'
            allow_active = etree.SubElement(defaults, 'allow_active')
            allow_active.text = 'yes'
            with open(udisk2_etc, 'wb') as w:
                xml_data.write(w, encoding='UTF-8', xml_declaration=True)
            policy_files.append(udisk2_etc)
        else:
            self.logger.error('Unable to apply %s' % k)
            return
        dconf_update(self.logger, self.test_dir)
        self.gp_db.store(str(self), k, ';'.join(policy_files))

    def __unapply(self, fnames):
        for fname in fnames.split(';'):
            if os.path.exists(fname):
                os.unlink(fname)

    def __clean_data(self, k):
        data = self.lock_down_settings[k]
        return {i: data[i] for i in data.keys() if i != 'Enabled'}

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             test_dir=None):
        if test_dir is not None:
            self.test_dir = test_dir
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for attribute, value in settings[str(self)].items():
                    self.__unapply(value)
                    self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section_name = 'GNOME Settings\\Lock Down Settings'
                self.gp_db.set_guid(gpo.name)
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                for e in pol_conf.entries:
                    if e.keyname.startswith(section_name) and e.data and \
                      '**delvals.' not in e.valuename:
                        for k in self.keys:
                            if e.keyname.endswith(k):
                                self.__add_lockdown_data(k, e)
                                break
                        else:
                            self.__enable_lockdown_data(e)
                for k in self.lock_down_settings.keys():
                    # Ignore disabled preferences
                    if not self.lock_down_settings[k]['Enabled']:
                        continue

                    # Apply using the appropriate applier
                    if k == self.keys[0]:
                        self.__apply_compose_key(self.__clean_data(k))
                    elif k == self.keys[1]:
                        self.__apply_dim_idle(self.__clean_data(k))
                    elif k == self.keys[2]:
                        self.__apply_specific_settings(self.__clean_data(k))
                    elif k == self.keys[3]:
                        self.__apply_whitelisted_account(self.__clean_data(k))
                    elif k == self.keys[4]:
                        self.__apply_enabled_extensions(self.__clean_data(k))
                    else:
                        self.__apply_enabled(k)
                    self.gp_db.commit()

    def rsop(self, gpo):
        output = {}
        if gpo.file_sys_path:
            section_name = 'GNOME Settings\\Lock Down Settings'
            pol_file = 'MACHINE/Registry.pol'
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if e.keyname.startswith(section_name) and e.data and \
                  '**delvals.' not in e.valuename:
                    for k in self.keys:
                        if e.keyname.endswith(k):
                            self.__add_lockdown_data(k, e)
                            break
                    else:
                        self.__enable_lockdown_data(e)
            for k in self.lock_down_settings.keys():
                if self.lock_down_settings[k]['Enabled']:
                    if len(self.lock_down_settings[k]) > 1:
                        data = self.__clean_data(k)
                        if all([i == data[i] for i in data.keys()]):
                            output[k] = list(data.keys())
                        else:
                            output[k] = data
                    else:
                        output[k] = self.lock_down_settings[k]
        return output

# Unix SMB/CIFS implementation. Tests for smb manipulation
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

import os, grp, pwd
import errno
from samba import gpo, tests
from samba.gpclass import register_gp_extension, list_gp_extensions, \
    unregister_gp_extension, GPOStorage
from samba.param import LoadParm
from samba.gpclass import check_refresh_gpo_list, check_safe_path, \
    check_guid, parse_gpext_conf, atomic_write_conf, get_deleted_gpos_list
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile, TemporaryDirectory
from samba.gp_sec_ext import gp_krb_ext, gp_access_ext
from samba.gp_scripts_ext import gp_scripts_ext
from samba.gp_sudoers_ext import gp_sudoers_ext
from samba.vgp_sudoers_ext import vgp_sudoers_ext
from samba.vgp_symlink_ext import vgp_symlink_ext
from samba.gpclass import gp_inf_ext
from samba.gp_smb_conf_ext import gp_smb_conf_ext
from samba.vgp_files_ext import vgp_files_ext
from samba.vgp_openssh_ext import vgp_openssh_ext
from samba.vgp_startup_scripts_ext import vgp_startup_scripts_ext
from samba.vgp_motd_ext import vgp_motd_ext
from samba.vgp_issue_ext import vgp_issue_ext
from samba.vgp_access_ext import vgp_access_ext
from samba.gp_gnome_settings_ext import gp_gnome_settings_ext
import logging
from samba.credentials import Credentials
from samba.gp_msgs_ext import gp_msgs_ext
from samba.common import get_bytes
from samba.dcerpc import preg
from samba.ndr import ndr_pack
import codecs
from shutil import copyfile
import xml.etree.ElementTree as etree
import hashlib
from samba.gp_parse.gp_pol import GPPolParser
from glob import glob
from configparser import ConfigParser

realm = os.environ.get('REALM')
policies = realm + '/POLICIES'
realm = realm.lower()
poldir = r'\\{0}\sysvol\{0}\Policies'.format(realm)
# the first part of the base DN varies by testenv. Work it out from the realm
base_dn = 'DC={0},DC=samba,DC=example,DC=com'.format(realm.split('.')[0])
dspath = 'CN=Policies,CN=System,' + base_dn
gpt_data = '[General]\nVersion=%d'

gnome_test_reg_pol = \
b"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="26" signature="PReg" version="1">
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Lock Down Enabled Extensions</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Lock Down Specific Settings</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Disable Printing</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Disable File Saving</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Disable Command-Line Access</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Disallow Login Using a Fingerprint</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Disable User Logout</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Disable User Switching</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Disable Repartitioning</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Whitelisted Online Accounts</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Compose Key</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Dim Screen when User is Idle</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings</Key>
        <ValueName>Enabled Extensions</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Compose Key</Key>
        <ValueName>Key Name</ValueName>
        <Value>Right Alt</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings\Dim Screen when User is Idle</Key>
        <ValueName>Delay</ValueName>
        <Value>300</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>GNOME Settings\Lock Down Settings\Dim Screen when User is Idle</Key>
        <ValueName>Dim Idle Brightness</ValueName>
        <Value>30</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Enabled Extensions</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Enabled Extensions</Key>
        <ValueName>myextension1@myname.example.com</ValueName>
        <Value>myextension1@myname.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Enabled Extensions</Key>
        <ValueName>myextension2@myname.example.com</ValueName>
        <Value>myextension2@myname.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Lock Down Specific Settings</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Lock Down Specific Settings</Key>
        <ValueName>/org/gnome/desktop/background/picture-uri</ValueName>
        <Value>/org/gnome/desktop/background/picture-uri</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Lock Down Specific Settings</Key>
        <ValueName>/org/gnome/desktop/background/picture-options</ValueName>
        <Value>/org/gnome/desktop/background/picture-options</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Lock Down Specific Settings</Key>
        <ValueName>/org/gnome/desktop/background/primary-color</ValueName>
        <Value>/org/gnome/desktop/background/primary-color</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Lock Down Specific Settings</Key>
        <ValueName>/org/gnome/desktop/background/secondary-color</ValueName>
        <Value>/org/gnome/desktop/background/secondary-color</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Whitelisted Online Accounts</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>GNOME Settings\Lock Down Settings\Whitelisted Online Accounts</Key>
        <ValueName>google</ValueName>
        <Value>google</Value>
    </Entry>
</PolFile>
"""

def days2rel_nttime(val):
    seconds = 60
    minutes = 60
    hours = 24
    sam_add = 10000000
    return -(val * seconds * minutes * hours * sam_add)

def gpupdate(lp, arg):
    gpupdate = lp.get('gpo update command')
    gpupdate.append(arg)

    p = Popen(gpupdate, stdout=PIPE, stderr=PIPE)
    stdoutdata, stderrdata = p.communicate()
    return p.returncode

def gpupdate_force(lp):
    return gpupdate(lp, '--force')

def gpupdate_unapply(lp):
    return gpupdate(lp, '--unapply')

def rsop(lp):
    return gpupdate(lp, '--rsop')

def stage_file(path, data):
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        try:
            os.makedirs(dirname)
        except OSError as e:
            if not (e.errno == errno.EEXIST and os.path.isdir(dirname)):
                return False
    if os.path.exists(path):
        os.rename(path, '%s.bak' % path)
    with NamedTemporaryFile(delete=False, dir=os.path.dirname(path)) as f:
        f.write(get_bytes(data))
        os.rename(f.name, path)
        os.chmod(path, 0o644)
    return True

def unstage_file(path):
    backup = '%s.bak' % path
    if os.path.exists(backup):
        os.rename(backup, path)
    elif os.path.exists(path):
        os.remove(path)

class GPOTests(tests.TestCase):
    def setUp(self):
        super(GPOTests, self).setUp()
        self.server = os.environ["SERVER"]
        self.dc_account = self.server.upper() + '$'
        self.lp = LoadParm()
        self.lp.load_default()
        self.creds = self.insta_creds(template=self.get_credentials())

    def tearDown(self):
        super(GPOTests, self).tearDown()

    def test_gpo_list(self):
        global poldir, dspath
        ads = gpo.ADS_STRUCT(self.server, self.lp, self.creds)
        if ads.connect():
            gpos = ads.get_gpo_list(self.creds.get_username())
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        names = ['Local Policy', guid]
        file_sys_paths = [None, '%s\\%s' % (poldir, guid)]
        ds_paths = [None, 'CN=%s,%s' % (guid, dspath)]
        for i in range(0, len(gpos)):
            self.assertEqual(gpos[i].name, names[i],
                              'The gpo name did not match expected name %s' % gpos[i].name)
            self.assertEqual(gpos[i].file_sys_path, file_sys_paths[i],
                              'file_sys_path did not match expected %s' % gpos[i].file_sys_path)
            self.assertEqual(gpos[i].ds_path, ds_paths[i],
                              'ds_path did not match expected %s' % gpos[i].ds_path)

    def test_gpo_ads_does_not_segfault(self):
        try:
            ads = gpo.ADS_STRUCT(self.server, 42, self.creds)
        except:
            pass

    def test_gpt_version(self):
        global gpt_data
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        gpo_path = os.path.join(local_path, policies, guid)
        old_vers = gpo.gpo_get_sysvol_gpt_version(gpo_path)[1]

        with open(os.path.join(gpo_path, 'GPT.INI'), 'w') as gpt:
            gpt.write(gpt_data % 42)
        self.assertEqual(gpo.gpo_get_sysvol_gpt_version(gpo_path)[1], 42,
                          'gpo_get_sysvol_gpt_version() did not return the expected version')

        with open(os.path.join(gpo_path, 'GPT.INI'), 'w') as gpt:
            gpt.write(gpt_data % old_vers)
        self.assertEqual(gpo.gpo_get_sysvol_gpt_version(gpo_path)[1], old_vers,
                          'gpo_get_sysvol_gpt_version() did not return the expected version')

    def test_check_refresh_gpo_list(self):
        cache = self.lp.cache_path('gpo_cache')
        ads = gpo.ADS_STRUCT(self.server, self.lp, self.creds)
        if ads.connect():
            gpos = ads.get_gpo_list(self.creds.get_username())
        check_refresh_gpo_list(self.server, self.lp, self.creds, gpos)

        self.assertTrue(os.path.exists(cache),
                        'GPO cache %s was not created' % cache)

        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        gpt_ini = os.path.join(cache, policies,
                               guid, 'GPT.INI')
        self.assertTrue(os.path.exists(gpt_ini),
                        'GPT.INI was not cached for %s' % guid)

    def test_check_refresh_gpo_list_malicious_paths(self):
        # the path cannot contain ..
        path = '/usr/local/samba/var/locks/sysvol/../../../../../../root/'
        self.assertRaises(OSError, check_safe_path, path)

        self.assertEqual(check_safe_path('/etc/passwd'), 'etc/passwd')
        self.assertEqual(check_safe_path('\\\\etc/\\passwd'), 'etc/passwd')

        # there should be no backslashes used to delineate paths
        before = 'sysvol/' + realm + '\\Policies/' \
            '{31B2F340-016D-11D2-945F-00C04FB984F9}\\GPT.INI'
        after = realm + '/Policies/' \
            '{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI'
        result = check_safe_path(before)
        self.assertEqual(result, after, 'check_safe_path() didn\'t'
                          ' correctly convert \\ to /')

    def test_check_safe_path_typesafe_name(self):
        path = '\\\\toady.suse.de\\SysVol\\toady.suse.de\\Policies\\' \
               '{31B2F340-016D-11D2-945F-00C04FB984F9}\\GPT.INI'
        expected_path = 'toady.suse.de/Policies/' \
                        '{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI'

        result = check_safe_path(path)
        self.assertEqual(result, expected_path,
            'check_safe_path unable to detect variable case sysvol components')

    def test_gpt_ext_register(self):
        this_path = os.path.dirname(os.path.realpath(__file__))
        samba_path = os.path.realpath(os.path.join(this_path, '../../../'))
        ext_path = os.path.join(samba_path, 'python/samba/gp_sec_ext.py')
        ext_guid = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
        ret = register_gp_extension(ext_guid, 'gp_access_ext', ext_path,
                                    smb_conf=self.lp.configfile,
                                    machine=True, user=False)
        self.assertTrue(ret, 'Failed to register a gp ext')
        gp_exts = list_gp_extensions(self.lp.configfile)
        self.assertTrue(ext_guid in gp_exts.keys(),
                        'Failed to list gp exts')
        self.assertEqual(gp_exts[ext_guid]['DllName'], ext_path,
                          'Failed to list gp exts')

        unregister_gp_extension(ext_guid)
        gp_exts = list_gp_extensions(self.lp.configfile)
        self.assertTrue(ext_guid not in gp_exts.keys(),
                        'Failed to unregister gp exts')

        self.assertTrue(check_guid(ext_guid), 'Failed to parse valid guid')
        self.assertFalse(check_guid('AAAAAABBBBBBBCCC'), 'Parsed invalid guid')

        lp, parser = parse_gpext_conf(self.lp.configfile)
        self.assertTrue(lp and parser, 'parse_gpext_conf() invalid return')
        parser.add_section('test_section')
        parser.set('test_section', 'test_var', ext_guid)
        atomic_write_conf(lp, parser)

        lp, parser = parse_gpext_conf(self.lp.configfile)
        self.assertTrue('test_section' in parser.sections(),
                        'test_section not found in gpext.conf')
        self.assertEqual(parser.get('test_section', 'test_var'), ext_guid,
                          'Failed to find test variable in gpext.conf')
        parser.remove_section('test_section')
        atomic_write_conf(lp, parser)

    def test_gp_log_get_applied(self):
        local_path = self.lp.get('path', 'sysvol')
        guids = ['{31B2F340-016D-11D2-945F-00C04FB984F9}',
                 '{6AC1786C-016F-11D2-945F-00C04FB984F9}']
        gpofile = '%s/' + realm + '/Policies/%s/MACHINE/Microsoft/' \
                  'Windows NT/SecEdit/GptTmpl.inf'
        stage = '[System Access]\nMinimumPasswordAge = 998\n'
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))
        for guid in guids:
            gpttmpl = gpofile % (local_path, guid)
            ret = stage_file(gpttmpl, stage)
            self.assertTrue(ret, 'Could not create the target %s' % gpttmpl)

        ret = gpupdate_force(self.lp)
        self.assertEqual(ret, 0, 'gpupdate force failed')

        gp_db = store.get_gplog(self.dc_account)

        applied_guids = gp_db.get_applied_guids()
        self.assertEqual(len(applied_guids), 2, 'The guids were not found')
        self.assertIn(guids[0], applied_guids,
                      '%s not in applied guids' % guids[0])
        self.assertIn(guids[1], applied_guids,
                      '%s not in applied guids' % guids[1])

        applied_settings = gp_db.get_applied_settings(applied_guids)
        for policy in applied_settings:
            self.assertIn('System Access', policy[1],
                          'System Access policies not set')
            self.assertIn('minPwdAge', policy[1]['System Access'],
                          'minPwdAge policy not set')
            if policy[0] == guids[0]:
                self.assertEqual(int(policy[1]['System Access']['minPwdAge']),
                                 days2rel_nttime(1),
                                 'minPwdAge policy not set')
            elif policy[0] == guids[1]:
                self.assertEqual(int(policy[1]['System Access']['minPwdAge']),
                                 days2rel_nttime(998),
                                 'minPwdAge policy not set')

        ads = gpo.ADS_STRUCT(self.server, self.lp, self.creds)
        if ads.connect():
            gpos = ads.get_gpo_list(self.dc_account)
        del_gpos = get_deleted_gpos_list(gp_db, gpos[:-1])
        self.assertEqual(len(del_gpos), 1, 'Returned delete gpos is incorrect')
        self.assertEqual(guids[-1], del_gpos[0][0],
                         'GUID for delete gpo is incorrect')
        self.assertIn('System Access', del_gpos[0][1],
                      'System Access policies not set for removal')
        self.assertIn('minPwdAge', del_gpos[0][1]['System Access'],
                      'minPwdAge policy not set for removal')

        for guid in guids:
            gpttmpl = gpofile % (local_path, guid)
            unstage_file(gpttmpl)

        ret = gpupdate_unapply(self.lp)
        self.assertEqual(ret, 0, 'gpupdate unapply failed')

    def test_process_group_policy(self):
        local_path = self.lp.cache_path('gpo_cache')
        guids = ['{31B2F340-016D-11D2-945F-00C04FB984F9}',
                 '{6AC1786C-016F-11D2-945F-00C04FB984F9}']
        gpofile = '%s/' + policies + '/%s/MACHINE/MICROSOFT/' \
                  'WINDOWS NT/SECEDIT/GPTTMPL.INF'
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_krb_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        stage = '[Kerberos Policy]\nMaxTicketAge = %d\n'
        opts = [100, 200]
        for i in range(0, 2):
            gpttmpl = gpofile % (local_path, guids[i])
            ret = stage_file(gpttmpl, stage % opts[i])
            self.assertTrue(ret, 'Could not create the target %s' % gpttmpl)

        # Process all gpos
        ext.process_group_policy([], gpos)

        ret = store.get_int('kdc:user_ticket_lifetime')
        self.assertEqual(ret, opts[1], 'Higher priority policy was not set')

        # Remove policy
        gp_db = store.get_gplog(machine_creds.get_username())
        del_gpos = get_deleted_gpos_list(gp_db, [])
        ext.process_group_policy(del_gpos, [])

        ret = store.get_int('kdc:user_ticket_lifetime')
        self.assertEqual(ret, None, 'MaxTicketAge should not have applied')

        # Process just the first gpo
        ext.process_group_policy([], gpos[:-1])

        ret = store.get_int('kdc:user_ticket_lifetime')
        self.assertEqual(ret, opts[0], 'Lower priority policy was not set')

        # Remove policy
        ext.process_group_policy(del_gpos, [])

        for guid in guids:
            gpttmpl = gpofile % (local_path, guid)
            unstage_file(gpttmpl)

    def test_gp_scripts(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_scripts_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        reg_key = b'Software\\Policies\\Samba\\Unix Settings'
        sections = { b'%s\\Daily Scripts' % reg_key : '.cron.daily',
                     b'%s\\Monthly Scripts' % reg_key : '.cron.monthly',
                     b'%s\\Weekly Scripts' % reg_key : '.cron.weekly',
                     b'%s\\Hourly Scripts' % reg_key : '.cron.hourly' }
        for keyname in sections.keys():
            # Stage the Registry.pol file with test data
            stage = preg.file()
            e = preg.entry()
            e.keyname = keyname
            e.valuename = b'Software\\Policies\\Samba\\Unix Settings'
            e.type = 1
            e.data = b'echo hello world'
            stage.num_entries = 1
            stage.entries = [e]
            ret = stage_file(reg_pol, ndr_pack(stage))
            self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

            # Process all gpos, with temp output directory
            with TemporaryDirectory(sections[keyname]) as dname:
                ext.process_group_policy([], gpos, dname)
                scripts = os.listdir(dname)
                self.assertEquals(len(scripts), 1,
                    'The %s script was not created' % keyname.decode())
                out, _ = Popen([os.path.join(dname, scripts[0])], stdout=PIPE).communicate()
                self.assertIn(b'hello world', out,
                    '%s script execution failed' % keyname.decode())

                # Remove policy
                gp_db = store.get_gplog(machine_creds.get_username())
                del_gpos = get_deleted_gpos_list(gp_db, [])
                ext.process_group_policy(del_gpos, [])
                self.assertEquals(len(os.listdir(dname)), 0,
                                  'Unapply failed to cleanup scripts')

            # Unstage the Registry.pol file
            unstage_file(reg_pol)

    def test_gp_sudoers(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_sudoers_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e = preg.entry()
        e.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Sudo Rights'
        e.valuename = b'Software\\Policies\\Samba\\Unix Settings'
        e.type = 1
        e.data = b'fakeu  ALL=(ALL) NOPASSWD: ALL'
        stage.num_entries = 1
        stage.entries = [e]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            sudoers = os.listdir(dname)
            self.assertEquals(len(sudoers), 1, 'The sudoer file was not created')
            self.assertIn(e.data,
                    open(os.path.join(dname, sudoers[0]), 'r').read(),
                    'The sudoers entry was not applied')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            self.assertEquals(len(os.listdir(dname)), 0,
                              'Unapply failed to cleanup scripts')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_vgp_sudoers(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/SUDO/SUDOERSCONFIGURATION/MANIFEST.XML')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_sudoers_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the manifest.xml file with test data
        stage = etree.Element('vgppolicy')
        policysetting = etree.Element('policysetting')
        stage.append(policysetting)
        version = etree.Element('version')
        version.text = '1'
        policysetting.append(version)
        data = etree.Element('data')
        sudoers_entry = etree.Element('sudoers_entry')
        command = etree.Element('command')
        command.text = 'ALL'
        sudoers_entry.append(command)
        user = etree.Element('user')
        user.text = 'ALL'
        sudoers_entry.append(user)
        principal_list = etree.Element('listelement')
        principal = etree.Element('principal')
        principal.text = 'fakeu'
        principal.attrib['type'] = 'user'
        group = etree.Element('principal')
        group.text = 'fakeg'
        group.attrib['type'] = 'group'
        principal_list.append(principal)
        principal_list.append(group)
        sudoers_entry.append(principal_list)
        data.append(sudoers_entry)
        # Ensure an empty principal doesn't cause a crash
        sudoers_entry = etree.SubElement(data, 'sudoers_entry')
        command = etree.SubElement(sudoers_entry, 'command')
        command.text = 'ALL'
        user = etree.SubElement(sudoers_entry, 'user')
        user.text = 'ALL'
        # Ensure having dispersed principals still works
        sudoers_entry = etree.SubElement(data, 'sudoers_entry')
        command = etree.SubElement(sudoers_entry, 'command')
        command.text = 'ALL'
        user = etree.SubElement(sudoers_entry, 'user')
        user.text = 'ALL'
        listelement = etree.SubElement(sudoers_entry, 'listelement')
        principal = etree.SubElement(listelement, 'principal')
        principal.text = 'fakeu2'
        principal.attrib['type'] = 'user'
        listelement = etree.SubElement(sudoers_entry, 'listelement')
        group = etree.SubElement(listelement, 'principal')
        group.text = 'fakeg2'
        group.attrib['type'] = 'group'
        policysetting.append(data)
        ret = stage_file(manifest, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest)

        # Process all gpos, with temp output directory
        data = 'fakeu,fakeg% ALL=(ALL) NOPASSWD: ALL'
        data2 = 'fakeu2,fakeg2% ALL=(ALL) NOPASSWD: ALL'
        data_no_principal = 'ALL ALL=(ALL) NOPASSWD: ALL'
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            sudoers = os.listdir(dname)
            self.assertEquals(len(sudoers), 3, 'The sudoer file was not created')
            output = open(os.path.join(dname, sudoers[0]), 'r').read() + \
                     open(os.path.join(dname, sudoers[1]), 'r').read() + \
                     open(os.path.join(dname, sudoers[2]), 'r').read()
            self.assertIn(data, output,
                    'The sudoers entry was not applied')
            self.assertIn(data2, output,
                    'The sudoers entry was not applied')
            self.assertIn(data_no_principal, output,
                    'The sudoers entry was not applied')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            self.assertEquals(len(os.listdir(dname)), 0,
                              'Unapply failed to cleanup scripts')

        # Unstage the Registry.pol file
        unstage_file(manifest)

    def test_gp_inf_ext_utf(self):
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        ext = gp_inf_ext(logger, self.lp, machine_creds, store)
        test_data = '[Kerberos Policy]\nMaxTicketAge = 99\n'

        with NamedTemporaryFile() as f:
            with codecs.open(f.name, 'w', 'utf-16') as w:
                w.write(test_data)
            try:
                inf_conf = ext.read(f.name)
            except UnicodeDecodeError:
                self.fail('Failed to parse utf-16')
            self.assertIn('Kerberos Policy', inf_conf.keys(),
                          'Kerberos Policy was not read from the file')
            self.assertEquals(inf_conf.get('Kerberos Policy', 'MaxTicketAge'),
                              '99', 'MaxTicketAge was not read from the file')

        with NamedTemporaryFile() as f:
            with codecs.open(f.name, 'w', 'utf-8') as w:
                w.write(test_data)
            inf_conf = ext.read(f.name)
            self.assertIn('Kerberos Policy', inf_conf.keys(),
                          'Kerberos Policy was not read from the file')
            self.assertEquals(inf_conf.get('Kerberos Policy', 'MaxTicketAge'),
                              '99', 'MaxTicketAge was not read from the file')

    def test_rsop(self):
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        local_path = self.lp.cache_path('gpo_cache')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        gp_extensions = []
        gp_extensions.append(gp_krb_ext)
        gp_extensions.append(gp_scripts_ext)
        gp_extensions.append(gp_sudoers_ext)
        gp_extensions.append(gp_smb_conf_ext)
        gp_extensions.append(gp_msgs_ext)

        # Create registry stage data
        reg_pol = os.path.join(local_path, policies, '%s/MACHINE/REGISTRY.POL')
        reg_stage = preg.file()
        e = preg.entry()
        e.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Daily Scripts'
        e.valuename = b'Software\\Policies\\Samba\\Unix Settings'
        e.type = 1
        e.data = b'echo hello world'
        e2 = preg.entry()
        e2.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Sudo Rights'
        e2.valuename = b'Software\\Policies\\Samba\\Unix Settings'
        e2.type = 1
        e2.data = b'fakeu  ALL=(ALL) NOPASSWD: ALL'
        e3 = preg.entry()
        e3.keyname = 'Software\\Policies\\Samba\\smb_conf\\apply group policies'
        e3.type = 4
        e3.data = 1
        e3.valuename = 'apply group policies'
        e4 = preg.entry()
        e4.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Messages'
        e4.valuename = b'issue'
        e4.type = 1
        e4.data = b'Welcome to \\s \\r \\l'
        reg_stage.num_entries = 4
        reg_stage.entries = [e, e2, e3, e4]

        # Create krb stage date
        gpofile = os.path.join(local_path, policies, '%s/MACHINE/MICROSOFT/' \
                  'WINDOWS NT/SECEDIT/GPTTMPL.INF')
        krb_stage = '[Kerberos Policy]\nMaxTicketAge = 99\n' \
                    '[System Access]\nMinimumPasswordAge = 998\n'

        for g in [g for g in gpos if g.file_sys_path]:
            ret = stage_file(gpofile % g.name, krb_stage)
            self.assertTrue(ret, 'Could not create the target %s' %
                                 (gpofile % g.name))
            ret = stage_file(reg_pol % g.name, ndr_pack(reg_stage))
            self.assertTrue(ret, 'Could not create the target %s' %
                                 (reg_pol % g.name))
            for ext in gp_extensions:
                ext = ext(logger, self.lp, machine_creds, store)
                ret = ext.rsop(g)
                self.assertEquals(len(ret.keys()), 1,
                                  'A single policy should have been displayed')

                # Check the Security Extension
                if type(ext) == gp_krb_ext:
                    self.assertIn('Kerberos Policy', ret.keys(),
                                  'Kerberos Policy not found')
                    self.assertIn('MaxTicketAge', ret['Kerberos Policy'],
                                  'MaxTicketAge setting not found')
                    self.assertEquals(ret['Kerberos Policy']['MaxTicketAge'], '99',
                                      'MaxTicketAge was not set to 99')
                # Check the Scripts Extension
                elif type(ext) == gp_scripts_ext:
                    self.assertIn('Daily Scripts', ret.keys(),
                                  'Daily Scripts not found')
                    self.assertIn('echo hello world', ret['Daily Scripts'],
                                  'Daily script was not created')
                # Check the Sudoers Extension
                elif type(ext) == gp_sudoers_ext:
                    self.assertIn('Sudo Rights', ret.keys(),
                                  'Sudoers not found')
                    self.assertIn('fakeu  ALL=(ALL) NOPASSWD: ALL',
                                  ret['Sudo Rights'],
                                  'Sudoers policy not created')
                # Check the smb.conf Extension
                elif type(ext) == gp_smb_conf_ext:
                    self.assertIn('smb.conf', ret.keys(),
                                  'apply group policies was not applied')
                    self.assertIn(e3.valuename, ret['smb.conf'],
                                  'apply group policies was not applied')
                    self.assertEquals(ret['smb.conf'][e3.valuename], e3.data,
                                      'apply group policies was not set')
                # Check the Messages Extension
                elif type(ext) == gp_msgs_ext:
                    self.assertIn('/etc/issue', ret,
                                  'Login Prompt Message not applied')
                    self.assertEquals(ret['/etc/issue'], e4.data,
                                      'Login Prompt Message not set')
            unstage_file(gpofile % g.name)
            unstage_file(reg_pol % g.name)

        # Check that a call to gpupdate --rsop also succeeds
        ret = rsop(self.lp)
        self.assertEquals(ret, 0, 'gpupdate --rsop failed!')

    def test_gp_unapply(self):
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        gp_extensions = []
        gp_extensions.append(gp_krb_ext)
        gp_extensions.append(gp_scripts_ext)
        gp_extensions.append(gp_sudoers_ext)

        # Create registry stage data
        reg_pol = os.path.join(local_path, policies, '%s/MACHINE/REGISTRY.POL')
        reg_stage = preg.file()
        e = preg.entry()
        e.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Daily Scripts'
        e.valuename = b'Software\\Policies\\Samba\\Unix Settings'
        e.type = 1
        e.data = b'echo hello world'
        e2 = preg.entry()
        e2.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Sudo Rights'
        e2.valuename = b'Software\\Policies\\Samba\\Unix Settings'
        e2.type = 1
        e2.data = b'fakeu  ALL=(ALL) NOPASSWD: ALL'
        reg_stage.num_entries = 2
        reg_stage.entries = [e, e2]

        # Create krb stage date
        gpofile = os.path.join(local_path, policies, '%s/MACHINE/MICROSOFT/' \
                  'WINDOWS NT/SECEDIT/GPTTMPL.INF')
        krb_stage = '[Kerberos Policy]\nMaxTicketAge = 99\n'

        ret = stage_file(gpofile % guid, krb_stage)
        self.assertTrue(ret, 'Could not create the target %s' %
                             (gpofile % guid))
        ret = stage_file(reg_pol % guid, ndr_pack(reg_stage))
        self.assertTrue(ret, 'Could not create the target %s' %
                             (reg_pol % guid))

        # Process all gpos, with temp output directory
        remove = []
        with TemporaryDirectory() as dname:
            for ext in gp_extensions:
                ext = ext(logger, self.lp, machine_creds, store)
                if type(ext) == gp_krb_ext:
                    ext.process_group_policy([], gpos)
                    ret = store.get_int('kdc:user_ticket_lifetime')
                    self.assertEqual(ret, 99, 'Kerberos policy was not set')
                elif type(ext) in [gp_scripts_ext, gp_sudoers_ext]:
                    ext.process_group_policy([], gpos, dname)
                    gp_db = store.get_gplog(machine_creds.get_username())
                    applied_settings = gp_db.get_applied_settings([guid])
                    for _, fname in applied_settings[-1][-1][str(ext)].items():
                        self.assertIn(dname, fname,
                                      'Test file not created in tmp dir')
                        self.assertTrue(os.path.exists(fname),
                                        'Test file not created')
                        remove.append(fname)

            # Unapply policy, and ensure policies are removed
            gpupdate_unapply(self.lp)

            for fname in remove:
                self.assertFalse(os.path.exists(fname),
                                 'Unapply did not remove test file')
            ret = store.get_int('kdc:user_ticket_lifetime')
            self.assertNotEqual(ret, 99, 'Kerberos policy was not unapplied')

        unstage_file(gpofile % guid)
        unstage_file(reg_pol % guid)

    def test_smb_conf_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        entries = []
        e = preg.entry()
        e.keyname = 'Software\\Policies\\Samba\\smb_conf\\template homedir'
        e.type = 1
        e.data = '/home/samba/%D/%U'
        e.valuename = 'template homedir'
        entries.append(e)
        e = preg.entry()
        e.keyname = 'Software\\Policies\\Samba\\smb_conf\\apply group policies'
        e.type = 4
        e.data = 1
        e.valuename = 'apply group policies'
        entries.append(e)
        e = preg.entry()
        e.keyname = 'Software\\Policies\\Samba\\smb_conf\\ldap timeout'
        e.type = 4
        e.data = 9999
        e.valuename = 'ldap timeout'
        entries.append(e)
        stage = preg.file()
        stage.num_entries = len(entries)
        stage.entries = entries

        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Failed to create the Registry.pol file')

        with NamedTemporaryFile(suffix='_smb.conf') as f:
            copyfile(self.lp.configfile, f.name)
            lp = LoadParm(f.name)

            # Initialize the group policy extension
            ext = gp_smb_conf_ext(logger, lp, machine_creds, store)
            ext.process_group_policy([], gpos)
            lp = LoadParm(f.name)

            template_homedir = lp.get('template homedir')
            self.assertEquals(template_homedir, '/home/samba/%D/%U',
                              'template homedir was not applied')
            apply_group_policies = lp.get('apply group policies')
            self.assertTrue(apply_group_policies,
                            'apply group policies was not applied')
            ldap_timeout = lp.get('ldap timeout')
            self.assertEquals(ldap_timeout, 9999, 'ldap timeout was not applied')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])

            lp = LoadParm(f.name)

            template_homedir = lp.get('template homedir')
            self.assertEquals(template_homedir, self.lp.get('template homedir'),
                              'template homedir was not unapplied')
            apply_group_policies = lp.get('apply group policies')
            self.assertEquals(apply_group_policies, self.lp.get('apply group policies'),
                              'apply group policies was not unapplied')
            ldap_timeout = lp.get('ldap timeout')
            self.assertEquals(ldap_timeout, self.lp.get('ldap timeout'),
                              'ldap timeout was not unapplied')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_gp_motd(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_msgs_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e1 = preg.entry()
        e1.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Messages'
        e1.valuename = b'motd'
        e1.type = 1
        e1.data = b'Have a lot of fun!'
        stage.num_entries = 2
        e2 = preg.entry()
        e2.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Messages'
        e2.valuename = b'issue'
        e2.type = 1
        e2.data = b'Welcome to \\s \\r \\l'
        stage.entries = [e1, e2]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            motd_file = os.path.join(dname, 'motd')
            self.assertTrue(os.path.exists(motd_file),
                            'Message of the day file not created')
            data = open(motd_file, 'r').read()
            self.assertEquals(data, e1.data, 'Message of the day not applied')
            issue_file = os.path.join(dname, 'issue')
            self.assertTrue(os.path.exists(issue_file),
                            'Login Prompt Message file not created')
            data = open(issue_file, 'r').read()
            self.assertEquals(data, e2.data, 'Login Prompt Message not applied')

            # Unapply policy, and ensure the test files are removed
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            data = open(motd_file, 'r').read()
            self.assertFalse(data, 'Message of the day file not removed')
            data = open(issue_file, 'r').read()
            self.assertFalse(data, 'Login Prompt Message file not removed')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_vgp_symlink(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/UNIX/SYMLINK/MANIFEST.XML')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_symlink_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        with TemporaryDirectory() as dname:
            test_source = os.path.join(dname, 'test.source')
            test_target = os.path.join(dname, 'test.target')

            # Stage the manifest.xml file with test data
            stage = etree.Element('vgppolicy')
            policysetting = etree.Element('policysetting')
            stage.append(policysetting)
            version = etree.Element('version')
            version.text = '1'
            policysetting.append(version)
            data = etree.Element('data')
            file_properties = etree.Element('file_properties')
            source = etree.Element('source')
            source.text = test_source
            file_properties.append(source)
            target = etree.Element('target')
            target.text = test_target
            file_properties.append(target)
            data.append(file_properties)
            policysetting.append(data)
            ret = stage_file(manifest, etree.tostring(stage))
            self.assertTrue(ret, 'Could not create the target %s' % manifest)

            # Create test source
            test_source_data = 'hello world!'
            with open(test_source, 'w') as w:
                w.write(test_source_data)

            # Process all gpos, with temp output directory
            ext.process_group_policy([], gpos)
            self.assertTrue(os.path.exists(test_target),
                            'The test symlink was not created')
            self.assertTrue(os.path.islink(test_target),
                            'The test file is not a symlink')
            self.assertIn(test_source_data, open(test_target, 'r').read(),
                          'Reading from symlink does not produce source data')

            # Unapply the policy, ensure removal
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            self.assertFalse(os.path.exists(test_target),
                            'The test symlink was not delete')

            # Verify RSOP
            ret = ext.rsop([g for g in gpos if g.name == guid][0])
            self.assertIn('ln -s %s %s' % (test_source, test_target),
                          list(ret.values())[0])

        # Unstage the manifest.xml file
        unstage_file(manifest)

    def test_vgp_files(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/UNIX/FILES/MANIFEST.XML')
        source_file = os.path.join(os.path.dirname(manifest), 'TEST.SOURCE')
        source_data = '#!/bin/sh\necho hello world'
        ret = stage_file(source_file, source_data)
        self.assertTrue(ret, 'Could not create the target %s' % source_file)
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_files_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the manifest.xml file with test data
        with TemporaryDirectory() as dname:
            stage = etree.Element('vgppolicy')
            policysetting = etree.Element('policysetting')
            stage.append(policysetting)
            version = etree.Element('version')
            version.text = '1'
            policysetting.append(version)
            data = etree.Element('data')
            file_properties = etree.SubElement(data, 'file_properties')
            source = etree.SubElement(file_properties, 'source')
            source.text = os.path.basename(source_file).lower()
            target = etree.SubElement(file_properties, 'target')
            target.text = os.path.join(dname, 'test.target')
            user = etree.SubElement(file_properties, 'user')
            user.text = pwd.getpwuid(os.getuid()).pw_name
            group = etree.SubElement(file_properties, 'group')
            group.text = grp.getgrgid(os.getgid()).gr_name
            # Request permissions of 755
            permissions = etree.SubElement(file_properties, 'permissions')
            permissions.set('type', 'user')
            etree.SubElement(permissions, 'read')
            etree.SubElement(permissions, 'write')
            etree.SubElement(permissions, 'execute')
            permissions = etree.SubElement(file_properties, 'permissions')
            permissions.set('type', 'group')
            etree.SubElement(permissions, 'read')
            etree.SubElement(permissions, 'execute')
            permissions = etree.SubElement(file_properties, 'permissions')
            permissions.set('type', 'other')
            etree.SubElement(permissions, 'read')
            etree.SubElement(permissions, 'execute')
            policysetting.append(data)
            ret = stage_file(manifest, etree.tostring(stage))
            self.assertTrue(ret, 'Could not create the target %s' % manifest)

            # Process all gpos, with temp output directory
            ext.process_group_policy([], gpos)
            self.assertTrue(os.path.exists(target.text),
                            'The target file does not exist')
            self.assertEquals(os.stat(target.text).st_mode & 0o777, 0o755,
                              'The target file permissions are incorrect')
            self.assertEquals(open(target.text).read(), source_data,
                              'The target file contents are incorrect')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            self.assertFalse(os.path.exists(target.text),
                             'The target file was not removed')

            # Test rsop
            g = [g for g in gpos if g.name == guid][0]
            ret = ext.rsop(g)
            self.assertIn(target.text, list(ret.values())[0][0],
                          'The target file was not listed by rsop')
            self.assertIn('-rwxr-xr-x', list(ret.values())[0][0],
                          'The target permissions were not listed by rsop')

        # Unstage the manifest and source files
        unstage_file(manifest)
        unstage_file(source_file)

    def test_vgp_openssh(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/SSHCFG/SSHD/MANIFEST.XML')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_openssh_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the manifest.xml file with test data
        stage = etree.Element('vgppolicy')
        policysetting = etree.Element('policysetting')
        stage.append(policysetting)
        version = etree.Element('version')
        version.text = '1'
        policysetting.append(version)
        data = etree.Element('data')
        configfile = etree.Element('configfile')
        configsection = etree.Element('configsection')
        sectionname = etree.Element('sectionname')
        configsection.append(sectionname)
        kvpair = etree.Element('keyvaluepair')
        key = etree.Element('key')
        key.text = 'AddressFamily'
        kvpair.append(key)
        value = etree.Element('value')
        value.text = 'inet6'
        kvpair.append(value)
        configsection.append(kvpair)
        configfile.append(configsection)
        data.append(configfile)
        policysetting.append(data)
        ret = stage_file(manifest, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest)

        # Process all gpos, with temp output directory
        data = 'AddressFamily inet6'
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            conf = os.listdir(dname)
            self.assertEquals(len(conf), 1, 'The conf file was not created')
            gp_cfg = os.path.join(dname, conf[0])
            self.assertIn(data, open(gp_cfg, 'r').read(),
                    'The sshd_config entry was not applied')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            self.assertFalse(os.path.exists(gp_cfg),
                             'Unapply failed to cleanup config')

        # Unstage the Registry.pol file
        unstage_file(manifest)

    def test_vgp_startup_scripts(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/UNIX/SCRIPTS/STARTUP/MANIFEST.XML')
        test_script = os.path.join(os.path.dirname(manifest), 'TEST.SH')
        test_data = '#!/bin/sh\necho $@ hello world'
        ret = stage_file(test_script, test_data)
        self.assertTrue(ret, 'Could not create the target %s' % test_script)
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_startup_scripts_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the manifest.xml file with test data
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        version = etree.SubElement(policysetting, 'version')
        version.text = '1'
        data = etree.SubElement(policysetting, 'data')
        listelement = etree.SubElement(data, 'listelement')
        script = etree.SubElement(listelement, 'script')
        script.text = os.path.basename(test_script).lower()
        parameters = etree.SubElement(listelement, 'parameters')
        parameters.text = '-n'
        hash = etree.SubElement(listelement, 'hash')
        hash.text = \
            hashlib.md5(open(test_script, 'rb').read()).hexdigest().upper()
        run_as = etree.SubElement(listelement, 'run_as')
        run_as.text = 'root'
        ret = stage_file(manifest, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            files = os.listdir(dname)
            self.assertEquals(len(files), 1,
                              'The target script was not created')
            entry = '@reboot %s %s %s' % (run_as.text, test_script,
                                          parameters.text)
            self.assertIn(entry,
                          open(os.path.join(dname, files[0]), 'r').read(),
                          'The test entry was not found')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            files = os.listdir(dname)
            self.assertEquals(len(files), 0,
                              'The target script was not removed')

            # Test rsop
            g = [g for g in gpos if g.name == guid][0]
            ret = ext.rsop(g)
            self.assertIn(entry, list(ret.values())[0][0],
                          'The target entry was not listed by rsop')

        # Unstage the manifest.xml and script files
        unstage_file(manifest)
        unstage_file(test_script)

        # Stage the manifest.xml file for run once scripts
        etree.SubElement(listelement, 'run_once')
        run_as.text = pwd.getpwuid(os.getuid()).pw_name
        ret = stage_file(manifest, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest)

        # Process all gpos, with temp output directory
        # A run once script will be executed immediately,
        # instead of creating a cron job
        with TemporaryDirectory() as dname:
            test_file = '%s/TESTING.txt' % dname
            test_data = '#!/bin/sh\ntouch %s' % test_file
            ret = stage_file(test_script, test_data)
            self.assertTrue(ret, 'Could not create the target %s' % test_script)

            ext.process_group_policy([], gpos, dname)
            files = os.listdir(dname)
            self.assertEquals(len(files), 1,
                              'The test file was not created')
            self.assertEquals(files[0], os.path.basename(test_file),
                              'The test file was not created')

            # Unlink the test file and ensure that processing
            # policy again does not recreate it.
            os.unlink(test_file)
            ext.process_group_policy([], gpos, dname)
            files = os.listdir(dname)
            self.assertEquals(len(files), 0,
                              'The test file should not have been created')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])

            # Test rsop
            entry = 'Run once as: %s `%s %s`' % (run_as.text, test_script,
                                            parameters.text)
            g = [g for g in gpos if g.name == guid][0]
            ret = ext.rsop(g)
            self.assertIn(entry, list(ret.values())[0][0],
                          'The target entry was not listed by rsop')

        # Unstage the manifest.xml and script files
        unstage_file(manifest)
        unstage_file(test_script)

    def test_vgp_motd(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/UNIX/MOTD/MANIFEST.XML')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_motd_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the manifest.xml file with test data
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        version = etree.SubElement(policysetting, 'version')
        version.text = '1'
        data = etree.SubElement(policysetting, 'data')
        filename = etree.SubElement(data, 'filename')
        filename.text = 'motd'
        text = etree.SubElement(data, 'text')
        text.text = 'This is the message of the day'
        ret = stage_file(manifest, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest)

        # Process all gpos, with temp output directory
        with NamedTemporaryFile() as f:
            ext.process_group_policy([], gpos, f.name)
            self.assertEquals(open(f.name, 'r').read(), text.text,
                              'The motd was not applied')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], f.name)
            self.assertNotEquals(open(f.name, 'r').read(), text.text,
                                 'The motd was not unapplied')

        # Unstage the Registry.pol file
        unstage_file(manifest)

    def test_vgp_issue(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/UNIX/ISSUE/MANIFEST.XML')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_issue_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the manifest.xml file with test data
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        version = etree.SubElement(policysetting, 'version')
        version.text = '1'
        data = etree.SubElement(policysetting, 'data')
        filename = etree.SubElement(data, 'filename')
        filename.text = 'issue'
        text = etree.SubElement(data, 'text')
        text.text = 'Welcome to Samba!'
        ret = stage_file(manifest, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest)

        # Process all gpos, with temp output directory
        with NamedTemporaryFile() as f:
            ext.process_group_policy([], gpos, f.name)
            self.assertEquals(open(f.name, 'r').read(), text.text,
                              'The issue was not applied')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], f.name)
            self.assertNotEquals(open(f.name, 'r').read(), text.text,
                                 'The issue was not unapplied')

        # Unstage the manifest.xml file
        unstage_file(manifest)

    def test_vgp_access(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        allow = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/VAS/HOSTACCESSCONTROL/ALLOW/MANIFEST.XML')
        deny = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/VAS/HOSTACCESSCONTROL/DENY/MANIFEST.XML')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_access_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the manifest.xml allow file
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        version = etree.SubElement(policysetting, 'version')
        version.text = '2'
        apply_mode = etree.SubElement(policysetting, 'apply_mode')
        apply_mode.text = 'merge'
        data = etree.SubElement(policysetting, 'data')
        # Add an allowed user
        listelement = etree.SubElement(data, 'listelement')
        otype = etree.SubElement(listelement, 'type')
        otype.text = 'USER'
        entry = etree.SubElement(listelement, 'entry')
        entry.text = 'goodguy@%s' % realm
        adobject = etree.SubElement(listelement, 'adobject')
        name = etree.SubElement(adobject, 'name')
        name.text = 'goodguy'
        domain = etree.SubElement(adobject, 'domain')
        domain.text = realm
        otype = etree.SubElement(adobject, 'type')
        otype.text = 'user'
        # Add an allowed group
        groupattr = etree.SubElement(data, 'groupattr')
        groupattr.text = 'samAccountName'
        listelement = etree.SubElement(data, 'listelement')
        otype = etree.SubElement(listelement, 'type')
        otype.text = 'GROUP'
        entry = etree.SubElement(listelement, 'entry')
        entry.text = '%s\\goodguys' % realm
        dn = etree.SubElement(listelement, 'dn')
        dn.text = 'CN=goodguys,CN=Users,%s' % base_dn
        adobject = etree.SubElement(listelement, 'adobject')
        name = etree.SubElement(adobject, 'name')
        name.text = 'goodguys'
        domain = etree.SubElement(adobject, 'domain')
        domain.text = realm
        otype = etree.SubElement(adobject, 'type')
        otype.text = 'group'
        ret = stage_file(allow, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % allow)

        # Stage the manifest.xml deny file
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        version = etree.SubElement(policysetting, 'version')
        version.text = '2'
        apply_mode = etree.SubElement(policysetting, 'apply_mode')
        apply_mode.text = 'merge'
        data = etree.SubElement(policysetting, 'data')
        # Add a denied user
        listelement = etree.SubElement(data, 'listelement')
        otype = etree.SubElement(listelement, 'type')
        otype.text = 'USER'
        entry = etree.SubElement(listelement, 'entry')
        entry.text = 'badguy@%s' % realm
        adobject = etree.SubElement(listelement, 'adobject')
        name = etree.SubElement(adobject, 'name')
        name.text = 'badguy'
        domain = etree.SubElement(adobject, 'domain')
        domain.text = realm
        otype = etree.SubElement(adobject, 'type')
        otype.text = 'user'
        # Add a denied group
        groupattr = etree.SubElement(data, 'groupattr')
        groupattr.text = 'samAccountName'
        listelement = etree.SubElement(data, 'listelement')
        otype = etree.SubElement(listelement, 'type')
        otype.text = 'GROUP'
        entry = etree.SubElement(listelement, 'entry')
        entry.text = '%s\\badguys' % realm
        dn = etree.SubElement(listelement, 'dn')
        dn.text = 'CN=badguys,CN=Users,%s' % base_dn
        adobject = etree.SubElement(listelement, 'adobject')
        name = etree.SubElement(adobject, 'name')
        name.text = 'badguys'
        domain = etree.SubElement(adobject, 'domain')
        domain.text = realm
        otype = etree.SubElement(adobject, 'type')
        otype.text = 'group'
        ret = stage_file(deny, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % deny)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            conf = os.listdir(dname)
            self.assertEquals(len(conf), 1, 'The conf file was not created')
            gp_cfg = os.path.join(dname, conf[0])

            # Check the access config for the correct access.conf entries
            print('Config file %s found' % gp_cfg)
            data = open(gp_cfg, 'r').read()
            self.assertIn('+:%s\\goodguy:ALL' % realm, data)
            self.assertIn('+:%s\\goodguys:ALL' % realm, data)
            self.assertIn('-:%s\\badguy:ALL' % realm, data)
            self.assertIn('-:%s\\badguys:ALL' % realm, data)

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            self.assertFalse(os.path.exists(gp_cfg),
                             'Unapply failed to cleanup config')

        # Unstage the manifest.pol files
        unstage_file(allow)
        unstage_file(deny)

    def test_gnome_settings(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        logger = logging.getLogger('gpo_tests')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_gnome_settings_ext(logger, self.lp, machine_creds, store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the Registry.pol file with test data
        parser = GPPolParser()
        parser.load_xml(etree.fromstring(gnome_test_reg_pol.strip()))
        ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)

            local_db = os.path.join(dname, 'etc/dconf/db/local.d')
            self.assertTrue(os.path.isdir(local_db),
                            'Local db dir not created')
            def db_check(name, data, count=1):
                db = glob(os.path.join(local_db, '*-%s' % name))
                self.assertEquals(len(db), count, '%s not created' % name)
                file_contents = ConfigParser()
                file_contents.read(db)
                for key in data.keys():
                    self.assertTrue(file_contents.has_section(key),
                                    'Section %s not found' % key)
                    options = data[key]
                    for k, v in options.items():
                        v_content = file_contents.get(key, k)
                        self.assertEqual(v_content, v,
                            '%s: %s != %s' % (key, v_content, v))

            def del_db_check(name):
                db = glob(os.path.join(local_db, '*-%s' % name))
                self.assertEquals(len(db), 0, '%s not deleted' % name)

            locks = os.path.join(local_db, 'locks')
            self.assertTrue(os.path.isdir(local_db), 'Locks dir not created')
            def lock_check(name, items, count=1):
                lock = glob(os.path.join(locks, '*%s' % name))
                self.assertEquals(len(lock), count,
                                  '%s lock not created' % name)
                file_contents = []
                for i in range(count):
                    file_contents.extend(open(lock[i], 'r').read().split('\n'))
                for data in items:
                    self.assertIn(data, file_contents,
                                  '%s lock not created' % data)

            def del_lock_check(name):
                lock = glob(os.path.join(locks, '*%s' % name))
                self.assertEquals(len(lock), 0, '%s lock not deleted' % name)

            # Check the user profile
            user_profile = os.path.join(dname, 'etc/dconf/profile/user')
            self.assertTrue(os.path.exists(user_profile),
                            'User profile not created')

            # Enable the compose key
            data = { 'org/gnome/desktop/input-sources':
                { 'xkb-options': '[\'compose:ralt\']' }
            }
            db_check('input-sources', data)
            items = ['/org/gnome/desktop/input-sources/xkb-options']
            lock_check('input-sources', items)

            # Dim screen when user is idle
            data = { 'org/gnome/settings-daemon/plugins/power':
                { 'idle-dim': 'true',
                  'idle-brightness': '30'
                }
            }
            db_check('power', data)
            data = { 'org/gnome/desktop/session':
                { 'idle-delay': 'uint32 300' }
            }
            db_check('session', data)
            items = ['/org/gnome/settings-daemon/plugins/power/idle-dim',
                     '/org/gnome/settings-daemon/plugins/power/idle-brightness',
                     '/org/gnome/desktop/session/idle-delay']
            lock_check('power-saving', items)

            # Lock down specific settings
            bg_locks = ['/org/gnome/desktop/background/picture-uri',
                        '/org/gnome/desktop/background/picture-options',
                        '/org/gnome/desktop/background/primary-color',
                        '/org/gnome/desktop/background/secondary-color']
            lock_check('group-policy', bg_locks)

            # Lock down enabled extensions
            data = { 'org/gnome/shell':
                { 'enabled-extensions':
                '[\'myextension1@myname.example.com\', \'myextension2@myname.example.com\']',
                  'development-tools': 'false' }
            }
            db_check('extensions', data)
            items = [ '/org/gnome/shell/enabled-extensions',
                      '/org/gnome/shell/development-tools' ]
            lock_check('extensions', items)

            # Disallow login using a fingerprint
            data = { 'org/gnome/login-screen':
                { 'enable-fingerprint-authentication': 'false' }
            }
            db_check('fingerprintreader', data)
            items = ['/org/gnome/login-screen/enable-fingerprint-authentication']
            lock_check('fingerprintreader', items)

            # Disable user logout and user switching
            data = { 'org/gnome/desktop/lockdown':
                { 'disable-log-out': 'true',
                  'disable-user-switching': 'true' }
            }
            db_check('logout', data, 2)
            items = ['/org/gnome/desktop/lockdown/disable-log-out',
                     '/org/gnome/desktop/lockdown/disable-user-switching']
            lock_check('logout', items, 2)

            # Disable repartitioning
            actions = os.path.join(dname, 'etc/share/polkit-1/actions')
            udisk2 = glob(os.path.join(actions,
                          'org.freedesktop.[u|U][d|D]isks2.policy'))
            self.assertEquals(len(udisk2), 1, 'udisk2 policy not created')
            udisk2_tree = etree.fromstring(open(udisk2[0], 'r').read())
            actions = udisk2_tree.findall('action')
            md = 'org.freedesktop.udisks2.modify-device'
            action = [a for a in actions if a.attrib['id'] == md]
            self.assertEquals(len(action), 1, 'modify-device not found')
            defaults = action[0].find('defaults')
            self.assertTrue(defaults is not None,
                            'modify-device defaults not found')
            allow_any = defaults.find('allow_any').text
            self.assertEquals(allow_any, 'no',
                              'modify-device allow_any not set to no')
            allow_inactive = defaults.find('allow_inactive').text
            self.assertEquals(allow_inactive, 'no',
                              'modify-device allow_inactive not set to no')
            allow_active = defaults.find('allow_active').text
            self.assertEquals(allow_active, 'yes',
                              'modify-device allow_active not set to yes')

            # Disable printing
            data = { 'org/gnome/desktop/lockdown':
                { 'disable-printing': 'true' }
            }
            db_check('printing', data)
            items = ['/org/gnome/desktop/lockdown/disable-printing']
            lock_check('printing', items)

            # Disable file saving
            data = { 'org/gnome/desktop/lockdown':
                { 'disable-save-to-disk': 'true' }
            }
            db_check('filesaving', data)
            items = ['/org/gnome/desktop/lockdown/disable-save-to-disk']
            lock_check('filesaving', items)

            # Disable command-line access
            data = { 'org/gnome/desktop/lockdown':
                { 'disable-command-line': 'true' }
            }
            db_check('cmdline', data)
            items = ['/org/gnome/desktop/lockdown/disable-command-line']
            lock_check('cmdline', items)

            # Allow or disallow online accounts
            data = { 'org/gnome/online-accounts':
                { 'whitelisted-providers': '[\'google\']' }
            }
            db_check('goa', data)
            items = ['/org/gnome/online-accounts/whitelisted-providers']
            lock_check('goa', items)

            # Verify RSOP does not fail
            ext.rsop([g for g in gpos if g.name == guid][0])

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            del_db_check('input-sources')
            del_lock_check('input-sources')
            del_db_check('power')
            del_db_check('session')
            del_lock_check('power-saving')
            del_lock_check('group-policy')
            del_db_check('extensions')
            del_lock_check('extensions')
            del_db_check('fingerprintreader')
            del_lock_check('fingerprintreader')
            del_db_check('logout')
            del_lock_check('logout')
            actions = os.path.join(dname, 'etc/share/polkit-1/actions')
            udisk2 = glob(os.path.join(actions,
                          'org.freedesktop.[u|U][d|D]isks2.policy'))
            self.assertEquals(len(udisk2), 0, 'udisk2 policy not deleted')
            del_db_check('printing')
            del_lock_check('printing')
            del_db_check('filesaving')
            del_lock_check('filesaving')
            del_db_check('cmdline')
            del_lock_check('cmdline')
            del_db_check('goa')
            del_lock_check('goa')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

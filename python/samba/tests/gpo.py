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

import os
import errno
from samba import gpo, tests
from samba.gpclass import register_gp_extension, list_gp_extensions, \
    unregister_gp_extension, GPOStorage
from samba.param import LoadParm
from samba.gpclass import check_refresh_gpo_list, check_safe_path, \
    check_guid, parse_gpext_conf, atomic_write_conf, get_deleted_gpos_list
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile, TemporaryDirectory
from samba.gp_sec_ext import gp_sec_ext
from samba.gp_scripts_ext import gp_scripts_ext
import logging
from samba.credentials import Credentials
from samba.compat import get_bytes
from samba.dcerpc import preg
from samba.ndr import ndr_pack

realm = os.environ.get('REALM')
policies = realm + '/POLICIES'
realm = realm.lower()
poldir = r'\\{0}\sysvol\{0}\Policies'.format(realm)
# the first part of the base DN varies by testenv. Work it out from the realm
base_dn = 'DC={0},DC=samba,DC=example,DC=com'.format(realm.split('.')[0])
dspath = 'CN=Policies,CN=System,' + base_dn
gpt_data = '[General]\nVersion=%d'

def days2rel_nttime(val):
    seconds = 60
    minutes = 60
    hours = 24
    sam_add = 10000000
    return -(val * seconds * minutes * hours * sam_add)

def gpupdate_force(lp):
    gpupdate = lp.get('gpo update command')
    gpupdate.append('--force')

    return Popen(gpupdate, stdout=PIPE, stderr=PIPE).wait()

def gpupdate_unapply(lp):
    gpupdate = lp.get('gpo update command')
    gpupdate.append('--unapply')

    return Popen(gpupdate, stdout=PIPE, stderr=PIPE).wait()

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

    def test_gpt_ext_register(self):
        this_path = os.path.dirname(os.path.realpath(__file__))
        samba_path = os.path.realpath(os.path.join(this_path, '../../../'))
        ext_path = os.path.join(samba_path, 'python/samba/gp_sec_ext.py')
        ext_guid = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
        ret = register_gp_extension(ext_guid, 'gp_sec_ext', ext_path,
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
        ext = gp_sec_ext(logger, self.lp, machine_creds, store)

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

    def test_gp_daily_scripts(self):
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

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e = preg.entry()
        e.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Daily Scripts'
        e.valuename = b'Software\\Policies\\Samba\\Unix Settings'
        e.type = 1
        e.data = b'echo hello world'
        stage.num_entries = 1
        stage.entries = [e]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            scripts = os.listdir(dname)
            self.assertEquals(len(scripts), 1, 'The daily script was not created')
            out, _ = Popen([os.path.join(dname, scripts[0])], stdout=PIPE).communicate()
            self.assertIn(b'hello world', out, 'Daily script execution failed')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

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
from samba import gpo, tests
from samba.param import LoadParm
from samba.gpclass import check_refresh_gpo_list, check_safe_path

poldir = r'\\addom.samba.example.com\sysvol\addom.samba.example.com\Policies'
dspath = 'CN=Policies,CN=System,DC=addom,DC=samba,DC=example,DC=com'
gpt_data = '[General]\nVersion=%d'

class GPOTests(tests.TestCase):
    def setUp(self):
        super(GPOTests, self).setUp()
        self.server = os.environ["SERVER"]
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
            assert gpos[i].name == names[i], \
              'The gpo name did not match expected name %s' % gpos[i].name
            assert gpos[i].file_sys_path == file_sys_paths[i], \
              'file_sys_path did not match expected %s' % gpos[i].file_sys_path
            assert gpos[i].ds_path == ds_paths[i], \
              'ds_path did not match expected %s' % gpos[i].ds_path


    def test_gpo_ads_does_not_segfault(self):
        try:
            ads = gpo.ADS_STRUCT(self.server, 42, self.creds)
        except:
            pass

    def test_gpt_version(self):
        global gpt_data
        local_path = self.lp.get("path", "sysvol")
        policies = 'addom.samba.example.com/Policies'
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        gpo_path = os.path.join(local_path, policies, guid)
        old_vers = gpo.gpo_get_sysvol_gpt_version(gpo_path)[1]

        with open(os.path.join(gpo_path, 'GPT.INI'), 'w') as gpt:
            gpt.write(gpt_data % 42)
        assert gpo.gpo_get_sysvol_gpt_version(gpo_path)[1] == 42, \
          'gpo_get_sysvol_gpt_version() did not return the expected version'

        with open(os.path.join(gpo_path, 'GPT.INI'), 'w') as gpt:
            gpt.write(gpt_data % old_vers)
        assert gpo.gpo_get_sysvol_gpt_version(gpo_path)[1] == old_vers, \
          'gpo_get_sysvol_gpt_version() did not return the expected version'

    def test_check_refresh_gpo_list(self):
        cache = self.lp.cache_path('gpo_cache')
        ads = gpo.ADS_STRUCT(self.server, self.lp, self.creds)
        if ads.connect():
            gpos = ads.get_gpo_list(self.creds.get_username())
        check_refresh_gpo_list(self.server, self.lp, self.creds, gpos)

        assert os.path.exists(cache), 'GPO cache %s was not created' % cache

        guid = '{31b2f340-016d-11d2-945f-00c04fb984f9}'
        gpt_ini = os.path.join(cache, 'addom.samba.example.com/policies',
                               guid, 'gpt.ini')
        assert os.path.exists(gpt_ini), 'GPT.INI was not cached for %s' % guid

    def test_check_refresh_gpo_list_malicious_paths(self):
        # the path cannot contain ..
        try:
            path = '/usr/local/samba/var/locks/sysvol/../../../../../../root/'
            check_safe_path(path)
            assert False, 'check_safe_path() succeeded on %s' % path
        except:
            pass

        # the path must contain 'sysvol'
        try:
            path = '/var/log/messages'
            check_safe_path(path)
            assert False, 'check_safe_path() succeeded on %s' % path
        except:
            pass

        # there should be no backslashes used to delineate paths
        before = 'sysvol/addom.samba.example.com\\Policies/' \
            '{31B2F340-016D-11D2-945F-00C04FB984F9}\\GPT.INI'
        after = 'addom.samba.example.com/Policies/' \
            '{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI'
        result = check_safe_path(before)
        assert result == after, 'check_safe_path() didn\'t' \
            ' correctly convert \\ to /'


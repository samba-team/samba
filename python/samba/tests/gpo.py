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

import os, grp, pwd, re
import errno
from samba import gpo, tests
from samba.gp.gpclass import register_gp_extension, list_gp_extensions, \
    unregister_gp_extension, GPOStorage, get_gpo_list
from samba.param import LoadParm
from samba.gp.gpclass import check_refresh_gpo_list, check_safe_path, \
    check_guid, parse_gpext_conf, atomic_write_conf, get_deleted_gpos_list
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile, TemporaryDirectory
from samba.gp import gpclass
# Disable privilege dropping for testing
gpclass.drop_privileges = lambda _, func, *args : func(*args)
from samba.gp.gp_sec_ext import gp_krb_ext
from samba.gp.gp_scripts_ext import gp_scripts_ext, gp_user_scripts_ext
from samba.gp.gp_sudoers_ext import gp_sudoers_ext
from samba.gp.vgp_sudoers_ext import vgp_sudoers_ext
from samba.gp.vgp_symlink_ext import vgp_symlink_ext
from samba.gp.gpclass import gp_inf_ext
from samba.gp.gp_smb_conf_ext import gp_smb_conf_ext
from samba.gp.vgp_files_ext import vgp_files_ext
from samba.gp.vgp_openssh_ext import vgp_openssh_ext
from samba.gp.vgp_startup_scripts_ext import vgp_startup_scripts_ext
from samba.gp.vgp_motd_ext import vgp_motd_ext
from samba.gp.vgp_issue_ext import vgp_issue_ext
from samba.gp.vgp_access_ext import vgp_access_ext
from samba.gp.gp_gnome_settings_ext import gp_gnome_settings_ext
from samba.gp import gp_cert_auto_enroll_ext as cae
from samba.gp.gp_firefox_ext import gp_firefox_ext
from samba.gp.gp_chromium_ext import gp_chromium_ext
from samba.gp.gp_firewalld_ext import gp_firewalld_ext
from samba.credentials import Credentials
from samba.gp.gp_msgs_ext import gp_msgs_ext
from samba.gp.gp_centrify_sudoers_ext import gp_centrify_sudoers_ext
from samba.gp.gp_centrify_crontab_ext import gp_centrify_crontab_ext, \
                                             gp_user_centrify_crontab_ext
from samba.gp.gp_drive_maps_ext import gp_drive_maps_user_ext
from samba.common import get_bytes
from samba.dcerpc import preg
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import misc

import codecs
from shutil import copyfile
import xml.etree.ElementTree as etree
import hashlib
from samba.gp_parse.gp_pol import GPPolParser
from glob import glob
from configparser import ConfigParser
from samba.gp.gpclass import get_dc_hostname, expand_pref_variables
from samba import Ldb
import ldb as _ldb
from samba.auth import system_session
import json
from shutil import which
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime, timedelta, timezone
from samba.samba3 import param as s3param

def dummy_certificate():
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME,
                           os.environ.get('SERVER'))
    ])
    cons = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.now(tz=timezone.utc)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                   backend=default_backend())

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(seconds=300))
        .add_extension(cons, False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    return cert.public_bytes(encoding=Encoding.DER)

# Dummy requests structure for Certificate Auto Enrollment
class dummy_requests(object):
    class exceptions(object):
        ConnectionError = Exception

    def __init__(self, want_exception=False):
        self.want_exception = want_exception

    def get(self, url=None, params=None):
        if self.want_exception:
            raise self.exceptions.ConnectionError

        dummy = requests.Response()
        dummy._content = dummy_certificate()
        dummy.headers = {'Content-Type': 'application/x-x509-ca-cert'}
        return dummy

realm = os.environ.get('REALM')
policies = realm + '/POLICIES'
realm = realm.lower()
poldir = r'\\{0}\sysvol\{0}\Policies'.format(realm)
# the first part of the base DN varies by testenv. Work it out from the realm
base_dn = 'DC={0},DC=samba,DC=example,DC=com'.format(realm.split('.')[0])
dspath = 'CN=Policies,CN=System,' + base_dn
gpt_data = '[General]\nVersion=%d'

gnome_test_reg_pol = \
br"""
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

auto_enroll_reg_pol = \
br"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="3" signature="PReg" version="1">
        <Entry type="4" type_name="REG_DWORD">
                <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
                <ValueName>AEPolicy</ValueName>
                <Value>7</Value>
        </Entry>
        <Entry type="4" type_name="REG_DWORD">
                <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
                <ValueName>OfflineExpirationPercent</ValueName>
                <Value>10</Value>
        </Entry>
        <Entry type="1" type_name="REG_SZ">
                <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
                <ValueName>OfflineExpirationStoreNames</ValueName>
                <Value>MY</Value>
        </Entry>
</PolFile>
"""

auto_enroll_unchecked_reg_pol = \
br"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="3" signature="PReg" version="1">
        <Entry type="4" type_name="REG_DWORD">
                <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
                <ValueName>AEPolicy</ValueName>
                <Value>0</Value>
        </Entry>
        <Entry type="4" type_name="REG_DWORD">
                <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
                <ValueName>OfflineExpirationPercent</ValueName>
                <Value>10</Value>
        </Entry>
        <Entry type="1" type_name="REG_SZ">
                <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
                <ValueName>OfflineExpirationStoreNames</ValueName>
                <Value>MY</Value>
        </Entry>
</PolFile>
"""

advanced_enroll_reg_pol = \
br"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="30" signature="PReg" version="1">
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography</Key>
        <ValueName>**DeleteKeys</ValueName>
        <Value>Software\Policies\Microsoft\Cryptography\PolicyServers</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
        <ValueName>AEPolicy</ValueName>
        <Value>7</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
        <ValueName>OfflineExpirationPercent</ValueName>
        <Value>25</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\AutoEnrollment</Key>
        <ValueName>OfflineExpirationStoreNames</ValueName>
        <Value>MY</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers</Key>
        <ValueName/>
        <Value>{5AD0BE6D-3393-4940-BFC3-6E19555A8919}</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers</Key>
        <ValueName>Flags</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54</Key>
        <ValueName>URL</ValueName>
        <Value>LDAP:</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54</Key>
        <ValueName>PolicyID</ValueName>
        <Value>%s</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54</Key>
        <ValueName>FriendlyName</ValueName>
        <Value>Example</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54</Key>
        <ValueName>Flags</ValueName>
        <Value>16</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54</Key>
        <ValueName>AuthFlags</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\37c9dc30f207f27f61a2f7c3aed598a6e2920b54</Key>
        <ValueName>Cost</ValueName>
        <Value>2147483645</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\144bdbb8e4717c26e408f3c9a0cb8d6cfacbcbbe</Key>
        <ValueName>URL</ValueName>
        <Value>https://example2.com/ADPolicyProvider_CEP_Certificate/service.svc/CEP</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\144bdbb8e4717c26e408f3c9a0cb8d6cfacbcbbe</Key>
        <ValueName>PolicyID</ValueName>
        <Value>%s</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\144bdbb8e4717c26e408f3c9a0cb8d6cfacbcbbe</Key>
        <ValueName>FriendlyName</ValueName>
        <Value>Example2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\144bdbb8e4717c26e408f3c9a0cb8d6cfacbcbbe</Key>
        <ValueName>Flags</ValueName>
        <Value>16</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\144bdbb8e4717c26e408f3c9a0cb8d6cfacbcbbe</Key>
        <ValueName>AuthFlags</ValueName>
        <Value>8</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\144bdbb8e4717c26e408f3c9a0cb8d6cfacbcbbe</Key>
        <ValueName>Cost</ValueName>
        <Value>10</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\20d46e856e9b9746c0b1265c328f126a7b3283a9</Key>
        <ValueName>URL</ValueName>
        <Value>https://example0.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\20d46e856e9b9746c0b1265c328f126a7b3283a9</Key>
        <ValueName>PolicyID</ValueName>
        <Value>%s</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\20d46e856e9b9746c0b1265c328f126a7b3283a9</Key>
        <ValueName>FriendlyName</ValueName>
        <Value>Example0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\20d46e856e9b9746c0b1265c328f126a7b3283a9</Key>
        <ValueName>Flags</ValueName>
        <Value>16</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\20d46e856e9b9746c0b1265c328f126a7b3283a9</Key>
        <ValueName>AuthFlags</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\20d46e856e9b9746c0b1265c328f126a7b3283a9</Key>
        <ValueName>Cost</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\855b5246433a48402ac4f5c3427566df26ccc9ac</Key>
        <ValueName>URL</ValueName>
        <Value>https://example1.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\855b5246433a48402ac4f5c3427566df26ccc9ac</Key>
        <ValueName>PolicyID</ValueName>
        <Value>%s</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\855b5246433a48402ac4f5c3427566df26ccc9ac</Key>
        <ValueName>FriendlyName</ValueName>
        <Value>Example1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\855b5246433a48402ac4f5c3427566df26ccc9ac</Key>
        <ValueName>Flags</ValueName>
        <Value>16</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\855b5246433a48402ac4f5c3427566df26ccc9ac</Key>
        <ValueName>AuthFlags</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Microsoft\Cryptography\PolicyServers\855b5246433a48402ac4f5c3427566df26ccc9ac</Key>
        <ValueName>Cost</ValueName>
        <Value>1</Value>
    </Entry>
</PolFile>
"""

firefox_reg_pol = \
b"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="241" signature="PReg" version="1">
    <Entry type="7" type_name="REG_MULTI_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>ExtensionSettings</ValueName>
        <Value>{ &quot;*&quot;: { &quot;blocked_install_message&quot;: &quot;Custom error message.&quot;, &quot;install_sources&quot;: [&quot;about:addons&quot;,&quot;https://addons.mozilla.org/&quot;], &quot;installation_mode&quot;: &quot;blocked&quot;, &quot;allowed_types&quot;: [&quot;extension&quot;] }, &quot;uBlock0@raymondhill.net&quot;: { &quot;installation_mode&quot;: &quot;force_installed&quot;, &quot;install_url&quot;: &quot;https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi&quot; }, &quot;https-everywhere@eff.org&quot;: { &quot;installation_mode&quot;: &quot;allowed&quot; } }</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>ExtensionUpdate</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>SearchSuggestEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>AppAutoUpdate</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>AppUpdateURL</ValueName>
        <Value>https://yoursite.com</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>BlockAboutAddons</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>BlockAboutConfig</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>BlockAboutProfiles</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>BlockAboutSupport</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>CaptivePortal</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="2" type_name="REG_EXPAND_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DefaultDownloadDirectory</ValueName>
        <Value>${home}/Downloads</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableAppUpdate</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableBuiltinPDFViewer</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableDefaultBrowserAgent</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableDeveloperTools</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableFeedbackCommands</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableFirefoxAccounts</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableFirefoxScreenshots</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableFirefoxStudies</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableForgetButton</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableFormHistory</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableMasterPasswordCreation</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisablePasswordReveal</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisablePocket</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisablePrivateBrowsing</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableProfileImport</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableProfileRefresh</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableSafeMode</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableSetDesktopBackground</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableSystemAddonUpdate</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisableTelemetry</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisplayBookmarksToolbar</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DisplayMenuBar</ValueName>
        <Value>default-on</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DontCheckDefaultBrowser</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="2" type_name="REG_EXPAND_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>DownloadDirectory</ValueName>
        <Value>${home}/Downloads</Value>
    </Entry>
    <Entry type="7" type_name="REG_MULTI_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>Handlers</ValueName>
        <Value>{ &quot;mimeTypes&quot;: { &quot;application/msword&quot;: { &quot;action&quot;: &quot;useSystemDefault&quot;, &quot;ask&quot;:  true } }, &quot;schemes&quot;: { &quot;mailto&quot;: { &quot;action&quot;: &quot;useHelperApp&quot;, &quot;ask&quot;:  true, &quot;handlers&quot;: [{ &quot;name&quot;: &quot;Gmail&quot;, &quot;uriTemplate&quot;: &quot;https://mail.google.com/mail/?extsrc=mailto&amp;url=%s&quot; }] } }, &quot;extensions&quot;: { &quot;pdf&quot;: { &quot;action&quot;: &quot;useHelperApp&quot;, &quot;ask&quot;:  true, &quot;handlers&quot;: [{ &quot;name&quot;: &quot;Adobe Acrobat&quot;, &quot;path&quot;: &quot;/usr/bin/acroread&quot; }] } } }</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>HardwareAcceleration</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="7" type_name="REG_MULTI_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>ManagedBookmarks</ValueName>
        <Value>[ { &quot;toplevel_name&quot;: &quot;My managed bookmarks folder&quot; }, { &quot;url&quot;: &quot;example.com&quot;, &quot;name&quot;: &quot;Example&quot; }, { &quot;name&quot;: &quot;Mozilla links&quot;, &quot;children&quot;: [ { &quot;url&quot;: &quot;https://mozilla.org&quot;, &quot;name&quot;: &quot;Mozilla.org&quot; }, { &quot;url&quot;: &quot;https://support.mozilla.org/&quot;, &quot;name&quot;: &quot;SUMO&quot; } ] } ]</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>NetworkPrediction</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>NewTabPage</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>NoDefaultBookmarks</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>OfferToSaveLogins</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>OfferToSaveLoginsDefault</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>OverrideFirstRunPage</ValueName>
        <Value>http://example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>OverridePostUpdatePage</ValueName>
        <Value>http://example.org</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>PasswordManagerEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="7" type_name="REG_MULTI_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>Preferences</ValueName>
        <Value>{ &quot;accessibility.force_disabled&quot;: { &quot;Value&quot;: 1, &quot;Status&quot;: &quot;default&quot; }, &quot;browser.cache.disk.parent_directory&quot;: { &quot;Value&quot;: &quot;SOME_NATIVE_PATH&quot;, &quot;Status&quot;: &quot;user&quot; }, &quot;browser.tabs.warnOnClose&quot;: { &quot;Value&quot;: false, &quot;Status&quot;: &quot;locked&quot; } }</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>PrimaryPassword</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>PromptForDownloadLocation</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\RequestedLocales</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\RequestedLocales</Key>
        <ValueName>1</ValueName>
        <Value>de</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\RequestedLocales</Key>
        <ValueName>2</ValueName>
        <Value>en-US</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>SSLVersionMax</ValueName>
        <Value>tls1.3</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>SSLVersionMin</ValueName>
        <Value>tls1.3</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>SearchBar</ValueName>
        <Value>unified</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication</Key>
        <ValueName>PrivateBrowsing</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\AllowNonFQDN</Key>
        <ValueName>NTLM</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\AllowNonFQDN</Key>
        <ValueName>SPNEGO</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\AllowProxies</Key>
        <ValueName>NTLM</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\AllowProxies</Key>
        <ValueName>SPNEGO</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\Delegated</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\Delegated</Key>
        <ValueName>1</ValueName>
        <Value>mydomain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\Delegated</Key>
        <ValueName>1</ValueName>
        <Value>https://myotherdomain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\NTLM</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\NTLM</Key>
        <ValueName>1</ValueName>
        <Value>mydomain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\NTLM</Key>
        <ValueName>1</ValueName>
        <Value>https://myotherdomain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\SPNEGO</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\SPNEGO</Key>
        <ValueName>1</ValueName>
        <Value>mydomain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Authentication\\SPNEGO</Key>
        <ValueName>1</ValueName>
        <Value>https://myotherdomain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\1</Key>
        <ValueName>Title</ValueName>
        <Value>Example</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\1</Key>
        <ValueName>URL</ValueName>
        <Value>https://example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\1</Key>
        <ValueName>Favicon</ValueName>
        <Value>https://example.com/favicon.ico</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\1</Key>
        <ValueName>Placement</ValueName>
        <Value>menu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\1</Key>
        <ValueName>Folder</ValueName>
        <Value>FolderName</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\10</Key>
        <ValueName>Title</ValueName>
        <Value>Samba</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\10</Key>
        <ValueName>URL</ValueName>
        <Value>www.samba.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\10</Key>
        <ValueName>Favicon</ValueName>
        <Value/>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\10</Key>
        <ValueName>Placement</ValueName>
        <Value>toolbar</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Bookmarks\\10</Key>
        <ValueName>Folder</ValueName>
        <Value/>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies</Key>
        <ValueName>AcceptThirdParty</ValueName>
        <Value>never</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies</Key>
        <ValueName>Default</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies</Key>
        <ValueName>ExpireAtSessionEnd</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies</Key>
        <ValueName>RejectTracker</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>http://example.org/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies\\AllowSession</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies\\AllowSession</Key>
        <ValueName>1</ValueName>
        <Value>http://example.edu/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Cookies\\Block</Key>
        <ValueName>1</ValueName>
        <Value>http://example.edu/</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_DHE_RSA_WITH_AES_128_CBC_SHA</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_DHE_RSA_WITH_AES_256_CBC_SHA</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_RSA_WITH_3DES_EDE_CBC_SHA</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_RSA_WITH_AES_128_CBC_SHA</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_RSA_WITH_AES_128_GCM_SHA256</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_RSA_WITH_AES_256_CBC_SHA</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisabledCiphers</Key>
        <ValueName>TLS_RSA_WITH_AES_256_GCM_SHA384</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisableSecurityBypass</Key>
        <ValueName>InvalidCertificate</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DisableSecurityBypass</Key>
        <ValueName>SafeBrowsing</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS</Key>
        <ValueName>Enabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS</Key>
        <ValueName>ProviderURL</ValueName>
        <Value>URL_TO_ALTERNATE_PROVIDER</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS\\ExcludedDomains</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS\\ExcludedDomains</Key>
        <ValueName>1</ValueName>
        <Value>example.com</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\EnableTrackingProtection</Key>
        <ValueName>Value</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\EnableTrackingProtection</Key>
        <ValueName>Cryptomining</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\EnableTrackingProtection</Key>
        <ValueName>Fingerprinting</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\EnableTrackingProtection</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\EnableTrackingProtection\\Exceptions</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\EnableTrackingProtection\\Exceptions</Key>
        <ValueName>1</ValueName>
        <Value>https://example.com</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\EncryptedMediaExtensions</Key>
        <ValueName>Enabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\EncryptedMediaExtensions</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Extensions\\Install</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="2" type_name="REG_EXPAND_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Extensions\\Install</Key>
        <ValueName>1</ValueName>
        <Value>https://addons.mozilla.org/firefox/downloads/somefile.xpi</Value>
    </Entry>
    <Entry type="2" type_name="REG_EXPAND_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Extensions\\Install</Key>
        <ValueName>2</ValueName>
        <Value>//path/to/xpi</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Extensions\\Locked</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Extensions\\Locked</Key>
        <ValueName>1</ValueName>
        <Value>addon_id@mozilla.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Extensions\\Uninstall</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Extensions\\Uninstall</Key>
        <ValueName>1</ValueName>
        <Value>bad_addon_id@mozilla.org</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FirefoxHome</Key>
        <ValueName>Search</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FirefoxHome</Key>
        <ValueName>TopSites</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FirefoxHome</Key>
        <ValueName>Highlights</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FirefoxHome</Key>
        <ValueName>Pocket</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FirefoxHome</Key>
        <ValueName>Snippets</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FirefoxHome</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FlashPlugin</Key>
        <ValueName>Default</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FlashPlugin</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FlashPlugin\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FlashPlugin\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>http://example.org/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FlashPlugin\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\FlashPlugin\\Block</Key>
        <ValueName>1</ValueName>
        <Value>http://example.edu/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Homepage</Key>
        <ValueName>StartPage</ValueName>
        <Value>homepage</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Homepage</Key>
        <ValueName>URL</ValueName>
        <Value>http://example.com/</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Homepage</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Homepage\\Additional</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Homepage\\Additional</Key>
        <ValueName>1</ValueName>
        <Value>http://example.org/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Homepage\\Additional</Key>
        <ValueName>2</ValueName>
        <Value>http://example.edu/</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\InstallAddonsPermission</Key>
        <ValueName>Default</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\InstallAddonsPermission\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\InstallAddonsPermission\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>http://example.org/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\InstallAddonsPermission\\Allow</Key>
        <ValueName>2</ValueName>
        <Value>http://example.edu/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\LocalFileLinks</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\LocalFileLinks</Key>
        <ValueName>1</ValueName>
        <Value>http://example.org/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\LocalFileLinks</Key>
        <ValueName>2</ValueName>
        <Value>http://example.edu/</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PDFjs</Key>
        <ValueName>EnablePermissions</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PDFjs</Key>
        <ValueName>Enabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Autoplay</Key>
        <ValueName>Default</ValueName>
        <Value>block-audio</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Autoplay</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Autoplay\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Autoplay\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>https://example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Autoplay\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Autoplay\\Block</Key>
        <ValueName>1</ValueName>
        <Value>https://example.edu</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Camera</Key>
        <ValueName>BlockNewRequests</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Camera</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Camera\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Camera\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>https://example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Camera\\Allow</Key>
        <ValueName>2</ValueName>
        <Value>https://example.org:1234</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Camera\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Camera\\Block</Key>
        <ValueName>1</ValueName>
        <Value>https://example.edu</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Location</Key>
        <ValueName>BlockNewRequests</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Location</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Location\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Location\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>https://example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Location\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Location\\Block</Key>
        <ValueName>1</ValueName>
        <Value>https://example.edu</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Microphone</Key>
        <ValueName>BlockNewRequests</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Microphone</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Microphone\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Microphone\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>https://example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Microphone\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Microphone\\Block</Key>
        <ValueName>1</ValueName>
        <Value>https://example.edu</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Notifications</Key>
        <ValueName>BlockNewRequests</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Notifications</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Notifications\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Notifications\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>https://example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Notifications\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\Notifications\\Block</Key>
        <ValueName>1</ValueName>
        <Value>https://example.edu</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\VirtualReality</Key>
        <ValueName>BlockNewRequests</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\VirtualReality</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\VirtualReality\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\VirtualReality\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>https://example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\VirtualReality\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Permissions\\VirtualReality\\Block</Key>
        <ValueName>1</ValueName>
        <Value>https://example.edu</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PictureInPicture</Key>
        <ValueName>Enabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PictureInPicture</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PopupBlocking</Key>
        <ValueName>Default</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PopupBlocking</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PopupBlocking\\Allow</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PopupBlocking\\Allow</Key>
        <ValueName>1</ValueName>
        <Value>http://example.org/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\PopupBlocking\\Allow</Key>
        <ValueName>2</ValueName>
        <Value>http://example.edu/</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>Locked</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>Mode</ValueName>
        <Value>autoDetect</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>HTTPProxy</ValueName>
        <Value>hostname</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>UseHTTPProxyForAllProtocols</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>SSLProxy</ValueName>
        <Value>hostname</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>FTPProxy</ValueName>
        <Value>hostname</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>SOCKSProxy</ValueName>
        <Value>hostname</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>SOCKSVersion</ValueName>
        <Value>5</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>Passthrough</ValueName>
        <Value>&lt;local&gt;</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>AutoConfigURL</ValueName>
        <Value>URL_TO_AUTOCONFIG</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>AutoLogin</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Proxy</Key>
        <ValueName>UseProxyForDNS</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>SanitizeOnShutdown</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines</Key>
        <ValueName>Default</ValueName>
        <Value>Google</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines</Key>
        <ValueName>PreventInstalls</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Add\\1</Key>
        <ValueName>Name</ValueName>
        <Value>Example1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Add\\1</Key>
        <ValueName>URLTemplate</ValueName>
        <Value>https://www.example.org/q={searchTerms}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Add\\1</Key>
        <ValueName>Method</ValueName>
        <Value>POST</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Add\\1</Key>
        <ValueName>IconURL</ValueName>
        <Value>https://www.example.org/favicon.ico</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Add\\1</Key>
        <ValueName>Alias</ValueName>
        <Value>example</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Add\\1</Key>
        <ValueName>Description</ValueName>
        <Value>Description</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Add\\1</Key>
        <ValueName>SuggestURLTemplate</ValueName>
        <Value>https://www.example.org/suggestions/q={searchTerms}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Add\\1</Key>
        <ValueName>PostData</ValueName>
        <Value>name=value&amp;q={searchTerms}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Remove</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SearchEngines\\Remove</Key>
        <ValueName>1</ValueName>
        <Value>Bing</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SupportMenu</Key>
        <ValueName>Title</ValueName>
        <Value>Support Menu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SupportMenu</Key>
        <ValueName>URL</ValueName>
        <Value>http://example.com/support</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SupportMenu</Key>
        <ValueName>AccessKey</ValueName>
        <Value>S</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\UserMessaging</Key>
        <ValueName>ExtensionRecommendations</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\UserMessaging</Key>
        <ValueName>FeatureRecommendations</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\UserMessaging</Key>
        <ValueName>WhatsNew</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\UserMessaging</Key>
        <ValueName>UrlbarInterventions</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\UserMessaging</Key>
        <ValueName>SkipOnboarding</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\WebsiteFilter\\Block</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\WebsiteFilter\\Block</Key>
        <ValueName>1</ValueName>
        <Value>&lt;all_urls&gt;</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\WebsiteFilter\\Exceptions</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\WebsiteFilter\\Exceptions</Key>
        <ValueName>1</ValueName>
        <Value>http://example.org/*</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>AllowedDomainsForApps</ValueName>
        <Value>managedfirefox.com,example.com</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>BackgroundAppUpdate</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Certificates</Key>
        <ValueName>ImportEnterpriseRoots</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Certificates\\Install</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Certificates\\Install</Key>
        <ValueName>1</ValueName>
        <Value>cert1.der</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\Certificates\\Install</Key>
        <ValueName>2</ValueName>
        <Value>/home/username/cert2.pem</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox\\SecurityDevices</Key>
        <ValueName>NAME_OF_DEVICE</ValueName>
        <Value>PATH_TO_LIBRARY_FOR_DEVICE</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>ShowHomeButton</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="7" type_name="REG_MULTI_SZ">
        <Key>Software\\Policies\\Mozilla\\Firefox</Key>
        <ValueName>AutoLaunchProtocolsFromOrigins</ValueName>
        <Value>[{&quot;protocol&quot;: &quot;zoommtg&quot;, &quot;allowed_origins&quot;: [&quot;https://somesite.zoom.us&quot;]}]</Value>
    </Entry>
</PolFile>
"""

firefox_json_expected = \
"""
{
  "policies": {
    "AppAutoUpdate": true,
    "AllowedDomainsForApps": "managedfirefox.com,example.com",
    "AppUpdateURL": "https://yoursite.com",
    "Authentication": {
      "SPNEGO": [
        "mydomain.com",
        "https://myotherdomain.com"
      ],
      "Delegated": [
        "mydomain.com",
        "https://myotherdomain.com"
      ],
      "NTLM": [
        "mydomain.com",
        "https://myotherdomain.com"
      ],
      "AllowNonFQDN": {
        "SPNEGO": true,
        "NTLM": true
      },
      "AllowProxies": {
        "SPNEGO": true,
        "NTLM": true
      },
      "Locked": true,
      "PrivateBrowsing": true
    },
    "AutoLaunchProtocolsFromOrigins": [
      {
        "protocol": "zoommtg",
        "allowed_origins": [
          "https://somesite.zoom.us"
        ]
      }
    ],
    "BackgroundAppUpdate": true,
    "BlockAboutAddons": true,
    "BlockAboutConfig": true,
    "BlockAboutProfiles": true,
    "BlockAboutSupport": true,
    "Bookmarks": [
      {
        "Title": "Example",
        "URL": "https://example.com",
        "Favicon": "https://example.com/favicon.ico",
        "Placement": "menu",
        "Folder": "FolderName"
      },
      {
        "Title": "Samba",
        "URL": "www.samba.org",
        "Favicon": "",
        "Placement": "toolbar",
        "Folder": ""
      }
    ],
    "CaptivePortal": true,
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": [
        "cert1.der",
        "/home/username/cert2.pem"
      ]
    },
    "Cookies": {
      "Allow": [
        "http://example.org/"
      ],
      "AllowSession": [
        "http://example.edu/"
      ],
      "Block": [
        "http://example.edu/"
      ],
      "Default": true,
      "AcceptThirdParty": "never",
      "ExpireAtSessionEnd": true,
      "RejectTracker": true,
      "Locked": true
    },
    "DisableSetDesktopBackground": true,
    "DisableMasterPasswordCreation": true,
    "DisableAppUpdate": true,
    "DisableBuiltinPDFViewer": true,
    "DisabledCiphers": {
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": true,
      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": true,
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": true,
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": true,
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": true,
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": true,
      "TLS_RSA_WITH_AES_128_CBC_SHA": true,
      "TLS_RSA_WITH_AES_256_CBC_SHA": true,
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA": true,
      "TLS_RSA_WITH_AES_128_GCM_SHA256": true,
      "TLS_RSA_WITH_AES_256_GCM_SHA384": true
    },
    "DisableDefaultBrowserAgent": true,
    "DisableDeveloperTools": true,
    "DisableFeedbackCommands": true,
    "DisableFirefoxScreenshots": true,
    "DisableFirefoxAccounts": true,
    "DisableFirefoxStudies": true,
    "DisableForgetButton": true,
    "DisableFormHistory": true,
    "DisablePasswordReveal": true,
    "DisablePocket": true,
    "DisablePrivateBrowsing": true,
    "DisableProfileImport": true,
    "DisableProfileRefresh": true,
    "DisableSafeMode": true,
    "DisableSecurityBypass": {
      "InvalidCertificate": true,
      "SafeBrowsing": true
    },
    "DisableSystemAddonUpdate": true,
    "DisableTelemetry": true,
    "DisplayBookmarksToolbar": true,
    "DisplayMenuBar": "default-on",
    "DNSOverHTTPS": {
      "Enabled": true,
      "ProviderURL": "URL_TO_ALTERNATE_PROVIDER",
      "Locked": true,
      "ExcludedDomains": [
        "example.com"
      ]
    },
    "DontCheckDefaultBrowser": true,
    "EnableTrackingProtection": {
      "Value": true,
      "Locked": true,
      "Cryptomining": true,
      "Fingerprinting": true,
      "Exceptions": [
        "https://example.com"
      ]
    },
    "EncryptedMediaExtensions": {
      "Enabled": true,
      "Locked": true
    },
    "Extensions": {
      "Install": [
        "https://addons.mozilla.org/firefox/downloads/somefile.xpi",
        "//path/to/xpi"
      ],
      "Uninstall": [
        "bad_addon_id@mozilla.org"
      ],
      "Locked": [
        "addon_id@mozilla.org"
      ]
    },
    "ExtensionSettings": {
      "*": {
        "blocked_install_message": "Custom error message.",
        "install_sources": [
          "about:addons",
          "https://addons.mozilla.org/"
        ],
        "installation_mode": "blocked",
        "allowed_types": [
          "extension"
        ]
      },
      "uBlock0@raymondhill.net": {
        "installation_mode": "force_installed",
        "install_url": "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"
      },
      "https-everywhere@eff.org": {
        "installation_mode": "allowed"
      }
    },
    "ExtensionUpdate": true,
    "FlashPlugin": {
      "Allow": [
        "http://example.org/"
      ],
      "Block": [
        "http://example.edu/"
      ],
      "Default": true,
      "Locked": true
    },
    "Handlers": {
      "mimeTypes": {
        "application/msword": {
          "action": "useSystemDefault",
          "ask": true
        }
      },
      "schemes": {
        "mailto": {
          "action": "useHelperApp",
          "ask": true,
          "handlers": [
            {
              "name": "Gmail",
              "uriTemplate": "https://mail.google.com/mail/?extsrc=mailto&url=%s"
            }
          ]
        }
      },
      "extensions": {
        "pdf": {
          "action": "useHelperApp",
          "ask": true,
          "handlers": [
            {
              "name": "Adobe Acrobat",
              "path": "/usr/bin/acroread"
            }
          ]
        }
      }
    },
    "FirefoxHome": {
      "Search": true,
      "TopSites": true,
      "Highlights": true,
      "Pocket": true,
      "Snippets": true,
      "Locked": true
    },
    "HardwareAcceleration": true,
    "Homepage": {
      "URL": "http://example.com/",
      "Locked": true,
      "Additional": [
        "http://example.org/",
        "http://example.edu/"
      ],
      "StartPage": "homepage"
    },
    "InstallAddonsPermission": {
      "Allow": [
        "http://example.org/",
        "http://example.edu/"
      ],
      "Default": true
    },
    "LocalFileLinks": [
      "http://example.org/",
      "http://example.edu/"
    ],
    "ManagedBookmarks": [
      {
        "toplevel_name": "My managed bookmarks folder"
      },
      {
        "url": "example.com",
        "name": "Example"
      },
      {
        "name": "Mozilla links",
        "children": [
          {
            "url": "https://mozilla.org",
            "name": "Mozilla.org"
          },
          {
            "url": "https://support.mozilla.org/",
            "name": "SUMO"
          }
        ]
      }
    ],
    "PrimaryPassword": true,
    "NoDefaultBookmarks": true,
    "OfferToSaveLogins": true,
    "OfferToSaveLoginsDefault": true,
    "OverrideFirstRunPage": "http://example.org",
    "OverridePostUpdatePage": "http://example.org",
    "PasswordManagerEnabled": true,
    "PSFjs": {
      "Enabled": true,
      "EnablePermissions": true
    },
    "Permissions": {
      "Camera": {
        "Allow": [
          "https://example.org",
          "https://example.org:1234"
        ],
        "Block": [
          "https://example.edu"
        ],
        "BlockNewRequests": true,
        "Locked": true
      },
      "Microphone": {
        "Allow": [
          "https://example.org"
        ],
        "Block": [
          "https://example.edu"
        ],
        "BlockNewRequests": true,
        "Locked": true
      },
      "Location": {
        "Allow": [
          "https://example.org"
        ],
        "Block": [
          "https://example.edu"
        ],
        "BlockNewRequests": true,
        "Locked": true
      },
      "Notifications": {
        "Allow": [
          "https://example.org"
        ],
        "Block": [
          "https://example.edu"
        ],
        "BlockNewRequests": true,
        "Locked": true
      },
      "Autoplay": {
        "Allow": [
          "https://example.org"
        ],
        "Block": [
          "https://example.edu"
        ],
        "Default": "block-audio",
        "Locked": true
      },
      "VirtualReality": {
        "Allow": [
          "https://example.org"
        ],
        "Block": [
          "https://example.edu"
        ],
        "BlockNewRequests": true,
        "Locked": true
      }
    },
    "PictureInPicture": {
      "Enabled": true,
      "Locked": true
    },
    "PopupBlocking": {
      "Allow": [
        "http://example.org/",
        "http://example.edu/"
      ],
      "Default": true,
      "Locked": true
    },
    "Preferences": {
      "accessibility.force_disabled": {
        "Value": 1,
        "Status": "default"
      },
      "browser.cache.disk.parent_directory": {
        "Value": "SOME_NATIVE_PATH",
        "Status": "user"
      },
      "browser.tabs.warnOnClose": {
        "Value": false,
        "Status": "locked"
      }
    },
    "PromptForDownloadLocation": true,
    "Proxy": {
      "Mode": "autoDetect",
      "Locked": true,
      "HTTPProxy": "hostname",
      "UseHTTPProxyForAllProtocols": true,
      "SSLProxy": "hostname",
      "FTPProxy": "hostname",
      "SOCKSProxy": "hostname",
      "SOCKSVersion": 5,
      "Passthrough": "<local>",
      "AutoConfigURL": "URL_TO_AUTOCONFIG",
      "AutoLogin": true,
      "UseProxyForDNS": true
    },
    "SanitizeOnShutdown": true,
    "SearchEngines": {
      "Add": [
        {
          "Name": "Example1",
          "URLTemplate": "https://www.example.org/q={searchTerms}",
          "Method": "POST",
          "IconURL": "https://www.example.org/favicon.ico",
          "Alias": "example",
          "Description": "Description",
          "PostData": "name=value&q={searchTerms}",
          "SuggestURLTemplate": "https://www.example.org/suggestions/q={searchTerms}"
        }
      ],
      "Remove": [
        "Bing"
      ],
      "Default": "Google",
      "PreventInstalls": true
    },
    "SearchSuggestEnabled": true,
    "SecurityDevices": {
      "NAME_OF_DEVICE": "PATH_TO_LIBRARY_FOR_DEVICE"
    },
    "ShowHomeButton": true,
    "SSLVersionMax": "tls1.3",
    "SSLVersionMin": "tls1.3",
    "SupportMenu": {
      "Title": "Support Menu",
      "URL": "http://example.com/support",
      "AccessKey": "S"
    },
    "UserMessaging": {
      "WhatsNew": true,
      "ExtensionRecommendations": true,
      "FeatureRecommendations": true,
      "UrlbarInterventions": true,
      "SkipOnboarding": true
    },
    "WebsiteFilter": {
      "Block": [
        "<all_urls>"
      ],
      "Exceptions": [
        "http://example.org/*"
      ]
    },
    "DefaultDownloadDirectory": "${home}/Downloads",
    "DownloadDirectory": "${home}/Downloads",
    "NetworkPrediction": true,
    "NewTabPage": true,
    "RequestedLocales": ["de", "en-US"],
    "SearchBar": "unified"
  }
}
"""

chromium_reg_pol = \
br"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="418" signature="PReg" version="1">
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AbusiveExperienceInterventionEnforce</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AccessibilityImageLabelsEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AdditionalDnsQueryTypesEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AdsSettingForIntrusiveAdsSites</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AdvancedProtectionAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AllowCrossOriginAuthPrompt</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AllowDeletingBrowserHistory</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AllowDinosaurEasterEgg</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AllowFileSelectionDialogs</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AllowSyncXHRInPageDismissal</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AllowedDomainsForApps</ValueName>
        <Value>managedchrome.com,example.com</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AlternateErrorPagesEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AlternativeBrowserPath</ValueName>
        <Value>${ie}</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AlwaysOpenPdfExternally</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AmbientAuthenticationInPrivateModesEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AppCacheForceEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ApplicationLocaleValue</ValueName>
        <Value>en</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AudioCaptureAllowed</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AudioProcessHighPriorityEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AudioSandboxEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AuthNegotiateDelegateAllowlist</ValueName>
        <Value>foobar.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AuthSchemes</ValueName>
        <Value>basic,digest,ntlm,negotiate</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AuthServerAllowlist</ValueName>
        <Value>*.example.com,example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AutoLaunchProtocolsFromOrigins</ValueName>
        <Value>[{&quot;allowed_origins&quot;: [&quot;example.com&quot;, &quot;http://www.example.com:8080&quot;], &quot;protocol&quot;: &quot;spotify&quot;}, {&quot;allowed_origins&quot;: [&quot;https://example.com&quot;, &quot;https://.mail.example.com&quot;], &quot;protocol&quot;: &quot;teams&quot;}, {&quot;allowed_origins&quot;: [&quot;*&quot;], &quot;protocol&quot;: &quot;outlook&quot;}]</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AutofillAddressEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AutofillCreditCardEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>AutoplayAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BackgroundModeEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BasicAuthOverHttpEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BlockExternalExtensions</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BlockThirdPartyCookies</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BookmarkBarEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserAddPersonEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserGuestModeEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserGuestModeEnforced</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserLabsEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserNetworkTimeQueriesEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserSignin</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserSwitcherChromePath</ValueName>
        <Value>${chrome}</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserSwitcherDelay</ValueName>
        <Value>10000</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserSwitcherEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserSwitcherExternalGreylistUrl</ValueName>
        <Value>http://example.com/greylist.xml</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserSwitcherExternalSitelistUrl</ValueName>
        <Value>http://example.com/sitelist.xml</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserSwitcherKeepLastChromeTab</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserSwitcherUseIeSitelist</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowserThemeColor</ValueName>
        <Value>#FFFFFF</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BrowsingDataLifetime</ValueName>
        <Value>[{&quot;data_types&quot;: [&quot;browsing_history&quot;], &quot;time_to_live_in_hours&quot;: 24}, {&quot;data_types&quot;: [&quot;password_signin&quot;, &quot;autofill&quot;], &quot;time_to_live_in_hours&quot;: 12}]</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>BuiltInDnsClientEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>CECPQ2Enabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ChromeCleanupEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ChromeCleanupReportingEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ChromeVariations</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ClickToCallEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>CloudManagementEnrollmentMandatory</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>CloudManagementEnrollmentToken</ValueName>
        <Value>37185d02-e055-11e7-80c1-9a214cf093ae</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>CloudPolicyOverridesPlatformPolicy</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>CloudPrintProxyEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>CloudPrintSubmitEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>CloudUserPolicyMerge</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>CommandLineFlagSecurityWarningsEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ComponentUpdatesEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DNSInterceptionChecksEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultBrowserSettingEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultCookiesSetting</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultFileHandlingGuardSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultFileSystemReadGuardSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultFileSystemWriteGuardSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultGeolocationSetting</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultImagesSetting</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultInsecureContentSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultJavaScriptSetting</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultNotificationsSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultPopupsSetting</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultPrinterSelection</ValueName>
        <Value>{ &quot;kind&quot;: &quot;cloud&quot;, &quot;idPattern&quot;: &quot;.*public&quot;, &quot;namePattern&quot;: &quot;.*Color&quot; }</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderContextMenuAccessAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderIconURL</ValueName>
        <Value>https://search.my.company/favicon.ico</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderImageURL</ValueName>
        <Value>https://search.my.company/searchbyimage/upload</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderImageURLPostParams</ValueName>
        <Value>content={imageThumbnail},url={imageURL},sbisrc={SearchSource}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderKeyword</ValueName>
        <Value>mis</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderName</ValueName>
        <Value>My Intranet Search</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderNewTabURL</ValueName>
        <Value>https://search.my.company/newtab</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderSearchURL</ValueName>
        <Value>https://search.my.company/search?q={searchTerms}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderSearchURLPostParams</ValueName>
        <Value>q={searchTerms},ie=utf-8,oe=utf-8</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderSuggestURL</ValueName>
        <Value>https://search.my.company/suggest?q={searchTerms}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSearchProviderSuggestURLPostParams</ValueName>
        <Value>q={searchTerms},ie=utf-8,oe=utf-8</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSensorsSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultSerialGuardSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultWebBluetoothGuardSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DefaultWebUsbGuardSetting</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DeveloperToolsAvailability</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>Disable3DAPIs</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DisableAuthNegotiateCnameLookup</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DisablePrintPreview</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DisableSafeBrowsingProceedAnyway</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DisableScreenshots</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DiskCacheDir</ValueName>
        <Value>${user_home}/Chrome_cache</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DiskCacheSize</ValueName>
        <Value>104857600</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DnsOverHttpsMode</ValueName>
        <Value>off</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DnsOverHttpsTemplates</ValueName>
        <Value>https://dns.example.net/dns-query{?dns}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DownloadDirectory</ValueName>
        <Value>/home/${user_name}/Downloads</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>DownloadRestrictions</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>EditBookmarksEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>EnableAuthNegotiatePort</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>EnableDeprecatedPrivetPrinting</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>EnableMediaRouter</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>EnableOnlineRevocationChecks</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>EnterpriseHardwarePlatformAPIEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ExtensionSettings</ValueName>
        <Value>{&quot;*&quot;: {&quot;allowed_types&quot;: [&quot;hosted_app&quot;], &quot;blocked_install_message&quot;: &quot;Custom error message.&quot;, &quot;blocked_permissions&quot;: [&quot;downloads&quot;, &quot;bookmarks&quot;], &quot;install_sources&quot;: [&quot;https://company-intranet/chromeapps&quot;], &quot;installation_mode&quot;: &quot;blocked&quot;, &quot;runtime_allowed_hosts&quot;: [&quot;*://good.example.com&quot;], &quot;runtime_blocked_hosts&quot;: [&quot;*://*.example.com&quot;]}, &quot;abcdefghijklmnopabcdefghijklmnop&quot;: {&quot;blocked_permissions&quot;: [&quot;history&quot;], &quot;installation_mode&quot;: &quot;allowed&quot;, &quot;minimum_version_required&quot;: &quot;1.0.1&quot;, &quot;toolbar_pin&quot;: &quot;force_pinned&quot;}, &quot;bcdefghijklmnopabcdefghijklmnopa&quot;: {&quot;allowed_permissions&quot;: [&quot;downloads&quot;], &quot;installation_mode&quot;: &quot;force_installed&quot;, &quot;runtime_allowed_hosts&quot;: [&quot;*://good.example.com&quot;], &quot;runtime_blocked_hosts&quot;: [&quot;*://*.example.com&quot;], &quot;update_url&quot;: &quot;https://example.com/update_url&quot;}, &quot;cdefghijklmnopabcdefghijklmnopab&quot;: {&quot;blocked_install_message&quot;: &quot;Custom error message.&quot;, &quot;installation_mode&quot;: &quot;blocked&quot;}, &quot;defghijklmnopabcdefghijklmnopabc,efghijklmnopabcdefghijklmnopabcd&quot;: {&quot;blocked_install_message&quot;: &quot;Custom error message.&quot;, &quot;installation_mode&quot;: &quot;blocked&quot;}, &quot;fghijklmnopabcdefghijklmnopabcde&quot;: {&quot;blocked_install_message&quot;: &quot;Custom removal message.&quot;, &quot;installation_mode&quot;: &quot;removed&quot;}, &quot;ghijklmnopabcdefghijklmnopabcdef&quot;: {&quot;installation_mode&quot;: &quot;force_installed&quot;, &quot;override_update_url&quot;: true, &quot;update_url&quot;: &quot;https://example.com/update_url&quot;}, &quot;update_url:https://www.example.com/update.xml&quot;: {&quot;allowed_permissions&quot;: [&quot;downloads&quot;], &quot;blocked_permissions&quot;: [&quot;wallpaper&quot;], &quot;installation_mode&quot;: &quot;allowed&quot;}}</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ExternalProtocolDialogShowAlwaysOpenCheckbox</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>FetchKeepaliveDurationSecondsOnShutdown</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ForceEphemeralProfiles</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ForceGoogleSafeSearch</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ForceYouTubeRestrict</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>FullscreenAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>GloballyScopeHTTPAuthCacheEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>HardwareAccelerationModeEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>HeadlessMode</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>HideWebStoreIcon</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>HomepageIsNewTabPage</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>HomepageLocation</ValueName>
        <Value>https://www.chromium.org</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ImportAutofillFormData</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ImportBookmarks</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ImportHistory</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ImportHomepage</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ImportSavedPasswords</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ImportSearchEngine</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>IncognitoModeAvailability</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>InsecureFormsWarningsEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>InsecurePrivateNetworkRequestsAllowed</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>IntensiveWakeUpThrottlingEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>IntranetRedirectBehavior</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>IsolateOrigins</ValueName>
        <Value>https://example.com/,https://othersite.org/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ManagedBookmarks</ValueName>
        <Value>[{&quot;toplevel_name&quot;: &quot;My managed bookmarks folder&quot;}, {&quot;name&quot;: &quot;Google&quot;, &quot;url&quot;: &quot;google.com&quot;}, {&quot;name&quot;: &quot;Youtube&quot;, &quot;url&quot;: &quot;youtube.com&quot;}, {&quot;children&quot;: [{&quot;name&quot;: &quot;Chromium&quot;, &quot;url&quot;: &quot;chromium.org&quot;}, {&quot;name&quot;: &quot;Chromium Developers&quot;, &quot;url&quot;: &quot;dev.chromium.org&quot;}], &quot;name&quot;: &quot;Chrome links&quot;}]</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ManagedConfigurationPerOrigin</ValueName>
        <Value>[{&quot;managed_configuration_hash&quot;: &quot;asd891jedasd12ue9h&quot;, &quot;managed_configuration_url&quot;: &quot;https://gstatic.google.com/configuration.json&quot;, &quot;origin&quot;: &quot;https://www.google.com&quot;}, {&quot;managed_configuration_hash&quot;: &quot;djio12easd89u12aws&quot;, &quot;managed_configuration_url&quot;: &quot;https://gstatic.google.com/configuration2.json&quot;, &quot;origin&quot;: &quot;https://www.example.com&quot;}]</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>MaxConnectionsPerProxy</ValueName>
        <Value>32</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>MaxInvalidationFetchDelay</ValueName>
        <Value>10000</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>MediaRecommendationsEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>MediaRouterCastAllowAllIPs</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>MetricsReportingEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>NTPCardsVisible</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>NTPCustomBackgroundEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>NativeMessagingUserLevelHosts</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>NetworkPredictionOptions</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>NewTabPageLocation</ValueName>
        <Value>https://www.chromium.org</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PasswordLeakDetectionEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PasswordManagerEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PasswordProtectionChangePasswordURL</ValueName>
        <Value>https://mydomain.com/change_password.html</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PasswordProtectionWarningTrigger</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PaymentMethodQueryEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PolicyAtomicGroupsEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PolicyRefreshRate</ValueName>
        <Value>3600000</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PrintHeaderFooter</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PrintPreviewUseSystemDefaultPrinter</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PrintRasterizationMode</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PrintingAllowedBackgroundGraphicsModes</ValueName>
        <Value>enabled</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PrintingBackgroundGraphicsDefault</ValueName>
        <Value>enabled</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PrintingEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PrintingPaperSizeDefault</ValueName>
        <Value>{&quot;custom_size&quot;: {&quot;height&quot;: 297000, &quot;width&quot;: 210000}, &quot;name&quot;: &quot;custom&quot;}</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ProfilePickerOnStartupAvailability</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PromotionalTabsEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>PromptForDownloadLocation</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ProxySettings</ValueName>
        <Value>{&quot;ProxyBypassList&quot;: &quot;https://www.example1.com,https://www.example2.com,https://internalsite/&quot;, &quot;ProxyMode&quot;: &quot;direct&quot;, &quot;ProxyPacUrl&quot;: &quot;https://internal.site/example.pac&quot;, &quot;ProxyServer&quot;: &quot;123.123.123.123:8080&quot;, &quot;ProxyServerMode&quot;: 2}</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>QuicAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RelaunchNotification</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RelaunchNotificationPeriod</ValueName>
        <Value>604800000</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostAllowClientPairing</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostAllowFileTransfer</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostAllowRelayedConnection</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostAllowRemoteAccessConnections</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostAllowUiAccessForRemoteAssistance</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostFirewallTraversal</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostMaximumSessionDurationMinutes</ValueName>
        <Value>1200</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostRequireCurtain</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RemoteAccessHostUdpPortRange</ValueName>
        <Value>12400-12409</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RendererCodeIntegrityEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RequireOnlineRevocationChecksForLocalAnchors</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RestoreOnStartup</ValueName>
        <Value>4</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RestrictSigninToPattern</ValueName>
        <Value>.*@example\.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RoamingProfileLocation</ValueName>
        <Value>${roaming_app_data}\chrome-profile</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>RoamingProfileSupportEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SSLErrorOverrideAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SSLVersionMin</ValueName>
        <Value>tls1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SafeBrowsingExtendedReportingEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SafeBrowsingForTrustedSourcesEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SafeBrowsingProtectionLevel</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SafeSitesFilterBehavior</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SavingBrowserHistoryDisabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ScreenCaptureAllowed</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ScrollToTextFragmentEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SearchSuggestEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SharedArrayBufferUnrestrictedAccessAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SharedClipboardEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ShowAppsShortcutInBookmarkBar</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ShowCastIconInToolbar</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ShowFullUrlsInAddressBar</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ShowHomeButton</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SignedHTTPExchangeEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SigninInterceptionEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SitePerProcess</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SpellCheckServiceEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SpellcheckEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SuppressDifferentOriginSubframeDialogs</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SuppressUnsupportedOSWarning</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>SyncDisabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>TargetBlankImpliesNoOpener</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>TaskManagerEndProcessEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>ThirdPartyBlockingEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>TotalMemoryLimitMb</ValueName>
        <Value>2048</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>TranslateEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>TripleDESEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>UrlKeyedAnonymizedDataCollectionEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>UserAgentClientHintsEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>UserDataDir</ValueName>
        <Value>${users}/${user_name}/Chrome</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>UserDataSnapshotRetentionLimit</ValueName>
        <Value>3</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>UserFeedbackAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>VideoCaptureAllowed</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>WPADQuickCheckEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>WebAppInstallForceList</ValueName>
        <Value>[{&quot;create_desktop_shortcut&quot;: true, &quot;default_launch_container&quot;: &quot;window&quot;, &quot;url&quot;: &quot;https://www.google.com/maps&quot;}, {&quot;default_launch_container&quot;: &quot;tab&quot;, &quot;url&quot;: &quot;https://docs.google.com&quot;}, {&quot;default_launch_container&quot;: &quot;window&quot;, &quot;fallback_app_name&quot;: &quot;Editor&quot;, &quot;url&quot;: &quot;https://docs.google.com/editor&quot;}]</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>WebRtcAllowLegacyTLSProtocols</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>WebRtcEventLogCollectionAllowed</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>WebRtcIPHandling</ValueName>
        <Value>default</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>WebRtcUdpPortRange</ValueName>
        <Value>10000-11999</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>WebUsbAllowDevicesForUrls</ValueName>
        <Value>[{&quot;devices&quot;: [{&quot;product_id&quot;: 5678, &quot;vendor_id&quot;: 1234}], &quot;urls&quot;: [&quot;https://google.com&quot;]}]</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome</Key>
        <ValueName>WindowOcclusionEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AlternativeBrowserParameters</Key>
        <ValueName>1</ValueName>
        <Value>-foreground</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AlternativeBrowserParameters</Key>
        <ValueName>2</ValueName>
        <Value>-new-window</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AlternativeBrowserParameters</Key>
        <ValueName>3</ValueName>
        <Value>${url}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AlternativeBrowserParameters</Key>
        <ValueName>4</ValueName>
        <Value>-profile</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AlternativeBrowserParameters</Key>
        <ValueName>5</ValueName>
        <Value>%HOME%\browser_profile</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AudioCaptureAllowedUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AudioCaptureAllowedUrls</Key>
        <ValueName>2</ValueName>
        <Value>https://[*.]example.edu/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoOpenAllowedForURLs</Key>
        <ValueName>1</ValueName>
        <Value>example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoOpenAllowedForURLs</Key>
        <ValueName>2</ValueName>
        <Value>https://ssl.server.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoOpenAllowedForURLs</Key>
        <ValueName>3</ValueName>
        <Value>hosting.com/good_path</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoOpenAllowedForURLs</Key>
        <ValueName>4</ValueName>
        <Value>https://server:8080/path</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoOpenAllowedForURLs</Key>
        <ValueName>5</ValueName>
        <Value>.exact.hostname.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoOpenFileTypes</Key>
        <ValueName>1</ValueName>
        <Value>exe</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoOpenFileTypes</Key>
        <ValueName>2</ValueName>
        <Value>txt</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoSelectCertificateForUrls</Key>
        <ValueName>1</ValueName>
        <Value>{&quot;pattern&quot;:&quot;https://www.example.com&quot;,&quot;filter&quot;:{&quot;ISSUER&quot;:{&quot;CN&quot;:&quot;certificate issuer name&quot;, &quot;L&quot;: &quot;certificate issuer location&quot;, &quot;O&quot;: &quot;certificate issuer org&quot;, &quot;OU&quot;: &quot;certificate issuer org unit&quot;}, &quot;SUBJECT&quot;:{&quot;CN&quot;:&quot;certificate subject name&quot;, &quot;L&quot;: &quot;certificate subject location&quot;, &quot;O&quot;: &quot;certificate subject org&quot;, &quot;OU&quot;: &quot;certificate subject org unit&quot;}}}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoplayAllowlist</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\AutoplayAllowlist</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\BrowserSwitcherChromeParameters</Key>
        <ValueName>1</ValueName>
        <Value>--force-dark-mode</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\BrowserSwitcherUrlGreylist</Key>
        <ValueName>1</ValueName>
        <Value>ie.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\BrowserSwitcherUrlGreylist</Key>
        <ValueName>2</ValueName>
        <Value>!open-in-chrome.ie.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\BrowserSwitcherUrlGreylist</Key>
        <ValueName>3</ValueName>
        <Value>foobar.com/ie-only/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\BrowserSwitcherUrlList</Key>
        <ValueName>1</ValueName>
        <Value>ie.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\BrowserSwitcherUrlList</Key>
        <ValueName>2</ValueName>
        <Value>!open-in-chrome.ie.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\BrowserSwitcherUrlList</Key>
        <ValueName>3</ValueName>
        <Value>foobar.com/ie-only/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CertificateTransparencyEnforcementDisabledForCas</Key>
        <ValueName>1</ValueName>
        <Value>sha256/AAAAAAAAAAAAAAAAAAAAAA==</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CertificateTransparencyEnforcementDisabledForCas</Key>
        <ValueName>2</ValueName>
        <Value>sha256//////////////////////w==</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CertificateTransparencyEnforcementDisabledForLegacyCas</Key>
        <ValueName>1</ValueName>
        <Value>sha256/AAAAAAAAAAAAAAAAAAAAAA==</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CertificateTransparencyEnforcementDisabledForLegacyCas</Key>
        <ValueName>2</ValueName>
        <Value>sha256//////////////////////w==</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CertificateTransparencyEnforcementDisabledForUrls</Key>
        <ValueName>1</ValueName>
        <Value>example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CertificateTransparencyEnforcementDisabledForUrls</Key>
        <ValueName>2</ValueName>
        <Value>.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList</Key>
        <ValueName>1</ValueName>
        <Value>browsing_history</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList</Key>
        <ValueName>2</ValueName>
        <Value>download_history</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList</Key>
        <ValueName>3</ValueName>
        <Value>cookies_and_other_site_data</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList</Key>
        <ValueName>4</ValueName>
        <Value>cached_images_and_files</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList</Key>
        <ValueName>5</ValueName>
        <Value>password_signin</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList</Key>
        <ValueName>6</ValueName>
        <Value>autofill</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList</Key>
        <ValueName>7</ValueName>
        <Value>site_settings</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList</Key>
        <ValueName>8</ValueName>
        <Value>hosted_app_data</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CookiesAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CookiesAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CookiesBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CookiesBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\DefaultSearchProviderAlternateURLs</Key>
        <ValueName>1</ValueName>
        <Value>https://search.my.company/suggest#q={searchTerms}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\DefaultSearchProviderAlternateURLs</Key>
        <ValueName>2</ValueName>
        <Value>https://search.my.company/suggest/search#q={searchTerms}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\DefaultSearchProviderEncodings</Key>
        <ValueName>1</ValueName>
        <Value>UTF-8</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\DefaultSearchProviderEncodings</Key>
        <ValueName>2</ValueName>
        <Value>UTF-16</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\DefaultSearchProviderEncodings</Key>
        <ValueName>3</ValueName>
        <Value>GB2312</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\DefaultSearchProviderEncodings</Key>
        <ValueName>4</ValueName>
        <Value>ISO-8859-1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\EnableExperimentalPolicies</Key>
        <ValueName>1</ValueName>
        <Value>ExtensionInstallAllowlist</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\EnableExperimentalPolicies</Key>
        <ValueName>2</ValueName>
        <Value>ExtensionInstallBlocklist</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExplicitlyAllowedNetworkPorts</Key>
        <ValueName>1</ValueName>
        <Value>10080</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExtensionAllowedTypes</Key>
        <ValueName>1</ValueName>
        <Value>hosted_app</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExtensionInstallAllowlist</Key>
        <ValueName>1</ValueName>
        <Value>extension_id1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExtensionInstallAllowlist</Key>
        <ValueName>2</ValueName>
        <Value>extension_id2</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExtensionInstallBlocklist</Key>
        <ValueName>1</ValueName>
        <Value>extension_id1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExtensionInstallBlocklist</Key>
        <ValueName>2</ValueName>
        <Value>extension_id2</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExtensionInstallForcelist</Key>
        <ValueName>1</ValueName>
        <Value>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;https://clients2.google.com/service/update2/crx</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExtensionInstallForcelist</Key>
        <ValueName>2</ValueName>
        <Value>abcdefghijklmnopabcdefghijklmnop</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ExtensionInstallSources</Key>
        <ValueName>1</ValueName>
        <Value>https://corp.mycompany.com/*</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileHandlingAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileHandlingAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileHandlingBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileHandlingBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileSystemReadAskForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileSystemReadAskForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileSystemReadBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileSystemReadBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileSystemWriteAskForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileSystemWriteAskForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileSystemWriteBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\FileSystemWriteBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ForcedLanguages</Key>
        <ValueName>1</ValueName>
        <Value>en-US</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\HSTSPolicyBypassList</Key>
        <ValueName>1</ValueName>
        <Value>meet</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ImagesAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ImagesAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ImagesBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\ImagesBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\InsecureContentAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\InsecureContentAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\InsecureContentBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\InsecureContentBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\InsecurePrivateNetworkRequestsAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>http://www.example.com:8080</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\InsecurePrivateNetworkRequestsAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\JavaScriptAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\JavaScriptAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\JavaScriptBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\JavaScriptBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\LegacySameSiteCookieBehaviorEnabledForDomainList</Key>
        <ValueName>1</ValueName>
        <Value>www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\LegacySameSiteCookieBehaviorEnabledForDomainList</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\LookalikeWarningAllowlistDomains</Key>
        <ValueName>1</ValueName>
        <Value>foo.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\LookalikeWarningAllowlistDomains</Key>
        <ValueName>2</ValueName>
        <Value>example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\NativeMessagingAllowlist</Key>
        <ValueName>1</ValueName>
        <Value>com.native.messaging.host.name1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\NativeMessagingAllowlist</Key>
        <ValueName>2</ValueName>
        <Value>com.native.messaging.host.name2</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\NativeMessagingBlocklist</Key>
        <ValueName>1</ValueName>
        <Value>com.native.messaging.host.name1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\NativeMessagingBlocklist</Key>
        <ValueName>2</ValueName>
        <Value>com.native.messaging.host.name2</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\NotificationsAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\NotificationsAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\NotificationsBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\NotificationsBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\OverrideSecurityRestrictionsOnInsecureOrigin</Key>
        <ValueName>1</ValueName>
        <Value>http://testserver.example.com/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\OverrideSecurityRestrictionsOnInsecureOrigin</Key>
        <ValueName>2</ValueName>
        <Value>*.example.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PasswordProtectionLoginURLs</Key>
        <ValueName>1</ValueName>
        <Value>https://mydomain.com/login.html</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PasswordProtectionLoginURLs</Key>
        <ValueName>2</ValueName>
        <Value>https://login.mydomain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PolicyDictionaryMultipleSourceMergeList</Key>
        <ValueName>1</ValueName>
        <Value>ExtensionSettings</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PolicyListMultipleSourceMergeList</Key>
        <ValueName>1</ValueName>
        <Value>ExtensionInstallAllowlist</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PolicyListMultipleSourceMergeList</Key>
        <ValueName>2</ValueName>
        <Value>ExtensionInstallBlocklist</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PopupsAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PopupsAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PopupsBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PopupsBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PrinterTypeDenyList</Key>
        <ValueName>1</ValueName>
        <Value>cloud</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\PrinterTypeDenyList</Key>
        <ValueName>2</ValueName>
        <Value>privet</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\RemoteAccessHostClientDomainList</Key>
        <ValueName>1</ValueName>
        <Value>my-awesome-domain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\RemoteAccessHostClientDomainList</Key>
        <ValueName>2</ValueName>
        <Value>my-auxiliary-domain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\RemoteAccessHostDomainList</Key>
        <ValueName>1</ValueName>
        <Value>my-awesome-domain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\RemoteAccessHostDomainList</Key>
        <ValueName>2</ValueName>
        <Value>my-auxiliary-domain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\RestoreOnStartupURLs</Key>
        <ValueName>1</ValueName>
        <Value>https://example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\RestoreOnStartupURLs</Key>
        <ValueName>2</ValueName>
        <Value>https://www.chromium.org</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SSLErrorOverrideAllowedForOrigins</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SSLErrorOverrideAllowedForOrigins</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SafeBrowsingAllowlistDomains</Key>
        <ValueName>1</ValueName>
        <Value>mydomain.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SafeBrowsingAllowlistDomains</Key>
        <ValueName>2</ValueName>
        <Value>myuniversity.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SecurityKeyPermitAttestation</Key>
        <ValueName>1</ValueName>
        <Value>https://example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SensorsAllowedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SensorsAllowedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SensorsBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SensorsBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SerialAskForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SerialAskForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SerialBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SerialBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SpellcheckLanguage</Key>
        <ValueName>1</ValueName>
        <Value>fr</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SpellcheckLanguage</Key>
        <ValueName>2</ValueName>
        <Value>es</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SpellcheckLanguageBlocklist</Key>
        <ValueName>1</ValueName>
        <Value>fr</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SpellcheckLanguageBlocklist</Key>
        <ValueName>2</ValueName>
        <Value>es</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\SyncTypesListDisabled</Key>
        <ValueName>1</ValueName>
        <Value>bookmarks</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLAllowlist</Key>
        <ValueName>1</ValueName>
        <Value>example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLAllowlist</Key>
        <ValueName>2</ValueName>
        <Value>https://ssl.server.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLAllowlist</Key>
        <ValueName>3</ValueName>
        <Value>hosting.com/good_path</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLAllowlist</Key>
        <ValueName>4</ValueName>
        <Value>https://server:8080/path</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLAllowlist</Key>
        <ValueName>5</ValueName>
        <Value>.exact.hostname.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLBlocklist</Key>
        <ValueName>1</ValueName>
        <Value>example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLBlocklist</Key>
        <ValueName>2</ValueName>
        <Value>https://ssl.server.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLBlocklist</Key>
        <ValueName>3</ValueName>
        <Value>hosting.com/bad_path</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLBlocklist</Key>
        <ValueName>4</ValueName>
        <Value>https://server:8080/path</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLBlocklist</Key>
        <ValueName>5</ValueName>
        <Value>.exact.hostname.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLBlocklist</Key>
        <ValueName>6</ValueName>
        <Value>file://*</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLBlocklist</Key>
        <ValueName>7</ValueName>
        <Value>custom_scheme:*</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\URLBlocklist</Key>
        <ValueName>8</ValueName>
        <Value>*</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\VideoCaptureAllowedUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\VideoCaptureAllowedUrls</Key>
        <ValueName>2</ValueName>
        <Value>https://[*.]example.edu/</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\WebRtcLocalIpsAllowedUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\WebRtcLocalIpsAllowedUrls</Key>
        <ValueName>2</ValueName>
        <Value>*example.com*</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\WebUsbAskForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\WebUsbAskForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\WebUsbBlockedForUrls</Key>
        <ValueName>1</ValueName>
        <Value>https://www.example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\WebUsbBlockedForUrls</Key>
        <ValueName>2</ValueName>
        <Value>[*.]example.edu</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>AlternateErrorPagesEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>ApplicationLocaleValue</ValueName>
        <Value>en</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>AutofillAddressEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>AutofillCreditCardEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>BackgroundModeEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>BlockThirdPartyCookies</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>BookmarkBarEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>DefaultDownloadDirectory</ValueName>
        <Value>/home/${user_name}/Downloads</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>DownloadDirectory</ValueName>
        <Value>/home/${user_name}/Downloads</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>DownloadRestrictions</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>HomepageIsNewTabPage</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>HomepageLocation</ValueName>
        <Value>https://www.chromium.org</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>ImportAutofillFormData</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>ImportBookmarks</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>ImportHistory</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>ImportSavedPasswords</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>ImportSearchEngine</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>MetricsReportingEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>NetworkPredictionOptions</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>PasswordLeakDetectionEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>PasswordManagerEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>PrintHeaderFooter</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>PrintPreviewUseSystemDefaultPrinter</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>RegisteredProtocolHandlers</ValueName>
        <Value>[{&quot;default&quot;: true, &quot;protocol&quot;: &quot;mailto&quot;, &quot;url&quot;: &quot;https://mail.google.com/mail/?extsrc=mailto&amp;url=%s&quot;}]</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>RestoreOnStartup</ValueName>
        <Value>4</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>SafeBrowsingForTrustedSourcesEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>SafeBrowsingProtectionLevel</ValueName>
        <Value>2</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>SearchSuggestEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>ShowFullUrlsInAddressBar</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>ShowHomeButton</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>SpellCheckServiceEnabled</ValueName>
        <Value>0</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Google\Chrome\Recommended</Key>
        <ValueName>TranslateEnabled</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\Recommended\RestoreOnStartupURLs</Key>
        <ValueName>1</ValueName>
        <Value>https://example.com</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Google\Chrome\Recommended\RestoreOnStartupURLs</Key>
        <ValueName>2</ValueName>
        <Value>https://www.chromium.org</Value>
    </Entry>
</PolFile>
"""

chromium_json_expected_managed = \
b"""
{
  "FileSystemWriteAskForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "InsecureContentBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "DefaultSearchProviderImageURLPostParams": "content={imageThumbnail},url={imageURL},sbisrc={SearchSource}",
  "BrowserAddPersonEnabled": true,
  "DefaultSearchProviderImageURL": "https://search.my.company/searchbyimage/upload",
  "ShowHomeButton": true,
  "ClearBrowsingDataOnExitList": [
    "browsing_history",
    "download_history",
    "cookies_and_other_site_data",
    "cached_images_and_files",
    "password_signin",
    "autofill",
    "site_settings",
    "hosted_app_data"
  ],
  "JavaScriptAllowedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "AmbientAuthenticationInPrivateModesEnabled": 0,
  "AllowFileSelectionDialogs": true,
  "PrintingAllowedBackgroundGraphicsModes": "enabled",
  "DnsOverHttpsTemplates": "https://dns.example.net/dns-query{?dns}",
  "ComponentUpdatesEnabled": true,
  "RemoteAccessHostAllowRemoteAccessConnections": false,
  "WindowOcclusionEnabled": true,
  "PrintPreviewUseSystemDefaultPrinter": false,
  "AutoLaunchProtocolsFromOrigins": [
    {
      "allowed_origins": [
        "example.com",
        "http://www.example.com:8080"
      ],
      "protocol": "spotify"
    },
    {
      "allowed_origins": [
        "https://example.com",
        "https://.mail.example.com"
      ],
      "protocol": "teams"
    },
    {
      "allowed_origins": [
        "*"
      ],
      "protocol": "outlook"
    }
  ],
  "ManagedConfigurationPerOrigin": [
    {
      "origin": "https://www.google.com",
      "managed_configuration_hash": "asd891jedasd12ue9h",
      "managed_configuration_url": "https://gstatic.google.com/configuration.json"
    },
    {
      "origin": "https://www.example.com",
      "managed_configuration_hash": "djio12easd89u12aws",
      "managed_configuration_url": "https://gstatic.google.com/configuration2.json"
    }
  ],
  "SyncTypesListDisabled": [
    "bookmarks"
  ],
  "SecurityKeyPermitAttestation": [
    "https://example.com"
  ],
  "DefaultSearchProviderSearchURL": "https://search.my.company/search?q={searchTerms}",
  "MetricsReportingEnabled": true,
  "MaxInvalidationFetchDelay": 10000,
  "AudioProcessHighPriorityEnabled": true,
  "ExtensionInstallForcelist": [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;https://clients2.google.com/service/update2/crx",
    "abcdefghijklmnopabcdefghijklmnop"
  ],
  "ExternalProtocolDialogShowAlwaysOpenCheckbox": true,
  "CookiesBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "BrowserSwitcherExternalSitelistUrl": "http://example.com/sitelist.xml",
  "AudioCaptureAllowedUrls": [
    "https://www.example.com/",
    "https://[*.]example.edu/"
  ],
  "NTPCustomBackgroundEnabled": true,
  "BlockExternalExtensions": true,
  "BrowserSwitcherChromeParameters": [
    "--force-dark-mode"
  ],
  "SafeSitesFilterBehavior": 0,
  "EnableOnlineRevocationChecks": false,
  "ImagesBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "InsecureFormsWarningsEnabled": true,
  "RelaunchNotificationPeriod": 604800000,
  "TotalMemoryLimitMb": 2048,
  "CloudManagementEnrollmentMandatory": true,
  "ClickToCallEnabled": true,
  "AppCacheForceEnabled": false,
  "UrlKeyedAnonymizedDataCollectionEnabled": true,
  "FullscreenAllowed": true,
  "AuthSchemes": "basic,digest,ntlm,negotiate",
  "PasswordLeakDetectionEnabled": true,
  "AuthServerAllowlist": "*.example.com,example.com",
  "AllowSyncXHRInPageDismissal": false,
  "PasswordProtectionChangePasswordURL": "https://mydomain.com/change_password.html",
  "MaxConnectionsPerProxy": 32,
  "RemoteAccessHostMaximumSessionDurationMinutes": 1200,
  "RemoteAccessHostAllowFileTransfer": false,
  "PrintRasterizationMode": 1,
  "CertificateTransparencyEnforcementDisabledForLegacyCas": [
    "sha256/AAAAAAAAAAAAAAAAAAAAAA==",
    "sha256//////////////////////w=="
  ],
  "DefaultWebBluetoothGuardSetting": 2,
  "AutoplayAllowed": true,
  "BrowserSwitcherUrlList": [
    "ie.com",
    "!open-in-chrome.ie.com",
    "foobar.com/ie-only/"
  ],
  "CertificateTransparencyEnforcementDisabledForUrls": [
    "example.com",
    ".example.com"
  ],
  "SpellcheckLanguageBlocklist": [
    "fr",
    "es"
  ],
  "PrintHeaderFooter": false,
  "ShowAppsShortcutInBookmarkBar": false,
  "SerialAskForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "ImagesAllowedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "ProfilePickerOnStartupAvailability": 0,
  "CommandLineFlagSecurityWarningsEnabled": true,
  "QuicAllowed": true,
  "IntensiveWakeUpThrottlingEnabled": true,
  "WPADQuickCheckEnabled": true,
  "SensorsAllowedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "NTPCardsVisible": true,
  "DefaultSearchProviderAlternateURLs": [
    "https://search.my.company/suggest#q={searchTerms}",
    "https://search.my.company/suggest/search#q={searchTerms}"
  ],
  "DisableSafeBrowsingProceedAnyway": true,
  "DefaultFileSystemWriteGuardSetting": 2,
  "DefaultSearchProviderSuggestURL": "https://search.my.company/suggest?q={searchTerms}",
  "SSLErrorOverrideAllowed": true,
  "CloudPrintProxyEnabled": true,
  "BrowserSwitcherUrlGreylist": [
    "ie.com",
    "!open-in-chrome.ie.com",
    "foobar.com/ie-only/"
  ],
  "BrowserNetworkTimeQueriesEnabled": true,
  "WebUsbAllowDevicesForUrls": [
    {
      "urls": [
        "https://google.com"
      ],
      "devices": [
        {
          "vendor_id": 1234,
          "product_id": 5678
        }
      ]
    }
  ],
  "TaskManagerEndProcessEnabled": true,
  "SuppressDifferentOriginSubframeDialogs": true,
  "UserDataDir": "${users}/${user_name}/Chrome",
  "CookiesAllowedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "SuppressUnsupportedOSWarning": true,
  "RequireOnlineRevocationChecksForLocalAnchors": false,
  "BrowsingDataLifetime": [
    {
      "data_types": [
        "browsing_history"
      ],
      "time_to_live_in_hours": 24
    },
    {
      "data_types": [
        "password_signin",
        "autofill"
      ],
      "time_to_live_in_hours": 12
    }
  ],
  "FileHandlingBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "AudioCaptureAllowed": false,
  "PromotionalTabsEnabled": false,
  "ShowFullUrlsInAddressBar": false,
  "EnableMediaRouter": true,
  "BrowserSwitcherDelay": 10000,
  "AllowDinosaurEasterEgg": false,
  "ImportSearchEngine": true,
  "PrintingBackgroundGraphicsDefault": "enabled",
  "TripleDESEnabled": false,
  "AutoplayAllowlist": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "RemoteAccessHostUdpPortRange": "12400-12409",
  "DefaultSearchProviderIconURL": "https://search.my.company/favicon.ico",
  "BrowserSwitcherChromePath": "${chrome}",
  "InsecureContentAllowedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "DefaultSearchProviderSearchURLPostParams": "q={searchTerms},ie=utf-8,oe=utf-8",
  "ForceGoogleSafeSearch": false,
  "UserFeedbackAllowed": true,
  "ForceYouTubeRestrict": 0,
  "ApplicationLocaleValue": "en",
  "RoamingProfileSupportEnabled": true,
  "AlternativeBrowserPath": "${ie}",
  "AlternativeBrowserParameters": [
    "-foreground",
    "-new-window",
    "${url}",
    "-profile",
    "%HOME%\\\\browser_profile"
  ],
  "AdvancedProtectionAllowed": true,
  "EditBookmarksEnabled": false,
  "DefaultPrinterSelection": "{ \\"kind\\": \\"cloud\\", \\"idPattern\\": \\".*public\\", \\"namePattern\\": \\".*Color\\" }",
  "SSLVersionMin": "tls1",
  "SharedArrayBufferUnrestrictedAccessAllowed": true,
  "DefaultSerialGuardSetting": 2,
  "DefaultPopupsSetting": 1,
  "IntranetRedirectBehavior": 1,
  "RendererCodeIntegrityEnabled": false,
  "BrowserGuestModeEnforced": true,
  "HSTSPolicyBypassList": [
    "meet"
  ],
  "DefaultWebUsbGuardSetting": 2,
  "CECPQ2Enabled": true,
  "RemoteAccessHostDomainList": [
    "my-awesome-domain.com",
    "my-auxiliary-domain.com"
  ],
  "URLBlocklist": [
    "example.com",
    "https://ssl.server.com",
    "hosting.com/bad_path",
    "https://server:8080/path",
    ".exact.hostname.com",
    "file://*",
    "custom_scheme:*",
    "*"
  ],
  "IsolateOrigins": "https://example.com/,https://othersite.org/",
  "ExtensionAllowedTypes": [
    "hosted_app"
  ],
  "NativeMessagingBlocklist": [
    "com.native.messaging.host.name1",
    "com.native.messaging.host.name2"
  ],
  "ExtensionSettings": {
    "abcdefghijklmnopabcdefghijklmnop": {
      "blocked_permissions": [
        "history"
      ],
      "minimum_version_required": "1.0.1",
      "toolbar_pin": "force_pinned",
      "installation_mode": "allowed"
    },
    "bcdefghijklmnopabcdefghijklmnopa": {
      "runtime_blocked_hosts": [
        "*://*.example.com"
      ],
      "allowed_permissions": [
        "downloads"
      ],
      "update_url": "https://example.com/update_url",
      "runtime_allowed_hosts": [
        "*://good.example.com"
      ],
      "installation_mode": "force_installed"
    },
    "update_url:https://www.example.com/update.xml": {
      "allowed_permissions": [
        "downloads"
      ],
      "blocked_permissions": [
        "wallpaper"
      ],
      "installation_mode": "allowed"
    },
    "cdefghijklmnopabcdefghijklmnopab": {
      "blocked_install_message": "Custom error message.",
      "installation_mode": "blocked"
    },
    "*": {
      "blocked_permissions": [
        "downloads",
        "bookmarks"
      ],
      "installation_mode": "blocked",
      "runtime_blocked_hosts": [
        "*://*.example.com"
      ],
      "blocked_install_message": "Custom error message.",
      "allowed_types": [
        "hosted_app"
      ],
      "runtime_allowed_hosts": [
        "*://good.example.com"
      ],
      "install_sources": [
        "https://company-intranet/chromeapps"
      ]
    },
    "defghijklmnopabcdefghijklmnopabc,efghijklmnopabcdefghijklmnopabcd": {
      "blocked_install_message": "Custom error message.",
      "installation_mode": "blocked"
    },
    "fghijklmnopabcdefghijklmnopabcde": {
      "blocked_install_message": "Custom removal message.",
      "installation_mode": "removed"
    },
    "ghijklmnopabcdefghijklmnopabcdef": {
      "update_url": "https://example.com/update_url",
      "override_update_url": true,
      "installation_mode": "force_installed"
    }
  },
  "FileSystemReadAskForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "SpellCheckServiceEnabled": false,
  "ExtensionInstallSources": [
    "https://corp.mycompany.com/*"
  ],
  "PrinterTypeDenyList": [
    "cloud",
    "privet"
  ],
  "SharedClipboardEnabled": true,
  "BlockThirdPartyCookies": false,
  "MediaRouterCastAllowAllIPs": false,
  "DnsOverHttpsMode": "off",
  "SyncDisabled": true,
  "LookalikeWarningAllowlistDomains": [
    "foo.example.com",
    "example.org"
  ],
  "UserDataSnapshotRetentionLimit": 3,
  "SafeBrowsingProtectionLevel": 2,
  "ScrollToTextFragmentEnabled": false,
  "ImportBookmarks": true,
  "DefaultBrowserSettingEnabled": true,
  "DefaultSearchProviderEnabled": true,
  "AdditionalDnsQueryTypesEnabled": true,
  "PolicyRefreshRate": 3600000,
  "PrintingPaperSizeDefault": {
    "custom_size": {
      "width": 210000,
      "height": 297000
    },
    "name": "custom"
  },
  "RestoreOnStartup": 4,
  "PasswordProtectionWarningTrigger": 1,
  "ChromeCleanupEnabled": true,
  "AbusiveExperienceInterventionEnforce": true,
  "BasicAuthOverHttpEnabled": false,
  "EnableAuthNegotiatePort": false,
  "DefaultGeolocationSetting": 1,
  "PolicyDictionaryMultipleSourceMergeList": [
    "ExtensionSettings"
  ],
  "AllowedDomainsForApps": "managedchrome.com,example.com",
  "DisableAuthNegotiateCnameLookup": false,
  "IncognitoModeAvailability": 1,
  "ChromeVariations": 1,
  "DefaultSearchProviderNewTabURL": "https://search.my.company/newtab",
  "SavingBrowserHistoryDisabled": true,
  "SpellcheckEnabled": false,
  "FileSystemWriteBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "BuiltInDnsClientEnabled": true,
  "SSLErrorOverrideAllowedForOrigins": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "WebRtcIPHandling": "default",
  "DefaultNotificationsSetting": 2,
  "PopupsAllowedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "TranslateEnabled": true,
  "DefaultSearchProviderEncodings": [
    "UTF-8",
    "UTF-16",
    "GB2312",
    "ISO-8859-1"
  ],
  "DownloadRestrictions": 2,
  "PromptForDownloadLocation": false,
  "DisablePrintPreview": false,
  "NetworkPredictionOptions": 1,
  "FileSystemReadBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "AutoOpenFileTypes": [
    "exe",
    "txt"
  ],
  "DownloadDirectory": "/home/${user_name}/Downloads",
  "ImportHomepage": true,
  "GloballyScopeHTTPAuthCacheEnabled": false,
  "CloudManagementEnrollmentToken": "37185d02-e055-11e7-80c1-9a214cf093ae",
  "ThirdPartyBlockingEnabled": false,
  "AdsSettingForIntrusiveAdsSites": 1,
  "FetchKeepaliveDurationSecondsOnShutdown": 1,
  "BookmarkBarEnabled": true,
  "DisableScreenshots": true,
  "AccessibilityImageLabelsEnabled": false,
  "RemoteAccessHostAllowUiAccessForRemoteAssistance": true,
  "PopupsBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "DefaultFileSystemReadGuardSetting": 2,
  "BrowserSignin": 2,
  "WebRtcAllowLegacyTLSProtocols": false,
  "PasswordManagerEnabled": true,
  "SafeBrowsingExtendedReportingEnabled": true,
  "CloudPolicyOverridesPlatformPolicy": false,
  "InsecurePrivateNetworkRequestsAllowedForUrls": [
    "http://www.example.com:8080",
    "[*.]example.edu"
  ],
  "RelaunchNotification": 1,
  "AlwaysOpenPdfExternally": true,
  "DefaultFileHandlingGuardSetting": 2,
  "ForceEphemeralProfiles": true,
  "PasswordProtectionLoginURLs": [
    "https://mydomain.com/login.html",
    "https://login.mydomain.com"
  ],
  "BrowserSwitcherExternalGreylistUrl": "http://example.com/greylist.xml",
  "BrowserGuestModeEnabled": true,
  "MediaRecommendationsEnabled": true,
  "WebRtcLocalIpsAllowedUrls": [
    "https://www.example.com",
    "*example.com*"
  ],
  "DeveloperToolsAvailability": 2,
  "DNSInterceptionChecksEnabled": true,
  "DefaultSearchProviderContextMenuAccessAllowed": true,
  "RemoteAccessHostRequireCurtain": false,
  "PaymentMethodQueryEnabled": true,
  "HomepageLocation": "https://www.chromium.org",
  "WebUsbAskForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "RemoteAccessHostAllowClientPairing": false,
  "ProxySettings": {
    "ProxyMode": "direct",
    "ProxyPacUrl": "https://internal.site/example.pac",
    "ProxyServer": "123.123.123.123:8080",
    "ProxyServerMode": 2,
    "ProxyBypassList": "https://www.example1.com,https://www.example2.com,https://internalsite/"
  },
  "AutofillCreditCardEnabled": false,
  "FileHandlingAllowedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "ChromeCleanupReportingEnabled": true,
  "AlternateErrorPagesEnabled": true,
  "WebRtcEventLogCollectionAllowed": true,
  "AutoSelectCertificateForUrls": [
    "{\\"pattern\\":\\"https://www.example.com\\",\\"filter\\":{\\"ISSUER\\":{\\"CN\\":\\"certificate issuer name\\", \\"L\\": \\"certificate issuer location\\", \\"O\\": \\"certificate issuer org\\", \\"OU\\": \\"certificate issuer org unit\\"}, \\"SUBJECT\\":{\\"CN\\":\\"certificate subject name\\", \\"L\\": \\"certificate subject location\\", \\"O\\": \\"certificate subject org\\", \\"OU\\": \\"certificate subject org unit\\"}}}"
  ],
  "PolicyListMultipleSourceMergeList": [
    "ExtensionInstallAllowlist",
    "ExtensionInstallBlocklist"
  ],
  "CertificateTransparencyEnforcementDisabledForCas": [
    "sha256/AAAAAAAAAAAAAAAAAAAAAA==",
    "sha256//////////////////////w=="
  ],
  "CookiesSessionOnlyForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "SitePerProcess": true,
  "RemoteAccessHostFirewallTraversal": false,
  "DefaultSearchProviderSuggestURLPostParams": "q={searchTerms},ie=utf-8,oe=utf-8",
  "BackgroundModeEnabled": true,
  "DefaultJavaScriptSetting": 1,
  "ForcedLanguages": [
    "en-US"
  ],
  "ManagedBookmarks": [
    {
      "toplevel_name": "My managed bookmarks folder"
    },
    {
      "url": "google.com",
      "name": "Google"
    },
    {
      "url": "youtube.com",
      "name": "Youtube"
    },
    {
      "children": [
        {
          "url": "chromium.org",
          "name": "Chromium"
        },
        {
          "url": "dev.chromium.org",
          "name": "Chromium Developers"
        }
      ],
      "name": "Chrome links"
    }
  ],
  "Disable3DAPIs": false,
  "CloudPrintSubmitEnabled": true,
  "DefaultCookiesSetting": 1,
  "ExtensionInstallBlocklist": [
    "extension_id1",
    "extension_id2"
  ],
  "URLAllowlist": [
    "example.com",
    "https://ssl.server.com",
    "hosting.com/good_path",
    "https://server:8080/path",
    ".exact.hostname.com"
  ],
  "ExplicitlyAllowedNetworkPorts": [
    "10080"
  ],
  "HomepageIsNewTabPage": true,
  "SensorsBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "BrowserLabsEnabled": false,
  "NotificationsAllowedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "NativeMessagingUserLevelHosts": false,
  "AuthNegotiateDelegateAllowlist": "foobar.example.com",
  "CloudUserPolicyMerge": true,
  "OverrideSecurityRestrictionsOnInsecureOrigin": [
    "http://testserver.example.com/",
    "*.example.org"
  ],
  "HideWebStoreIcon": true,
  "SafeBrowsingForTrustedSourcesEnabled": false,
  "NewTabPageLocation": "https://www.chromium.org",
  "DiskCacheSize": 104857600,
  "BrowserSwitcherUseIeSitelist": true,
  "WebRtcUdpPortRange": "10000-11999",
  "EnterpriseHardwarePlatformAPIEnabled": true,
  "AutoOpenAllowedForURLs": [
    "example.com",
    "https://ssl.server.com",
    "hosting.com/good_path",
    "https://server:8080/path",
    ".exact.hostname.com"
  ],
  "NativeMessagingAllowlist": [
    "com.native.messaging.host.name1",
    "com.native.messaging.host.name2"
  ],
  "DefaultSearchProviderName": "My Intranet Search",
  "JavaScriptBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "EnableExperimentalPolicies": [
    "ExtensionInstallAllowlist",
    "ExtensionInstallBlocklist"
  ],
  "SafeBrowsingAllowlistDomains": [
    "mydomain.com",
    "myuniversity.edu"
  ],
  "AutofillAddressEnabled": false,
  "AllowCrossOriginAuthPrompt": false,
  "SpellcheckLanguage": [
    "fr",
    "es"
  ],
  "VideoCaptureAllowed": false,
  "ScreenCaptureAllowed": false,
  "VideoCaptureAllowedUrls": [
    "https://www.example.com/",
    "https://[*.]example.edu/"
  ],
  "ImportHistory": true,
  "ShowCastIconInToolbar": false,
  "RestoreOnStartupURLs": [
    "https://example.com",
    "https://www.chromium.org"
  ],
  "LegacySameSiteCookieBehaviorEnabledForDomainList": [
    "www.example.com",
    "[*.]example.edu"
  ],
  "PrintingEnabled": true,
  "ImportSavedPasswords": true,
  "EnableDeprecatedPrivetPrinting": true,
  "InsecurePrivateNetworkRequestsAllowed": false,
  "HeadlessMode": 2,
  "PolicyAtomicGroupsEnabled": true,
  "HardwareAccelerationModeEnabled": true,
  "AllowDeletingBrowserHistory": true,
  "DefaultSearchProviderKeyword": "mis",
  "ExtensionInstallAllowlist": [
    "extension_id1",
    "extension_id2"
  ],
  "WebAppInstallForceList": [
    {
      "url": "https://www.google.com/maps",
      "create_desktop_shortcut": true,
      "default_launch_container": "window"
    },
    {
      "url": "https://docs.google.com",
      "default_launch_container": "tab"
    },
    {
      "url": "https://docs.google.com/editor",
      "fallback_app_name": "Editor",
      "default_launch_container": "window"
    }
  ],
  "DiskCacheDir": "${user_home}/Chrome_cache",
  "SignedHTTPExchangeEnabled": true,
  "SearchSuggestEnabled": true,
  "BrowserThemeColor": "#FFFFFF",
  "RestrictSigninToPattern": ".*@example\\\\.com",
  "DefaultInsecureContentSetting": 2,
  "DefaultSensorsSetting": 2,
  "AudioSandboxEnabled": true,
  "RemoteAccessHostAllowRelayedConnection": false,
  "RoamingProfileLocation": "${roaming_app_data}\\\\chrome-profile",
  "UserAgentClientHintsEnabled": true,
  "TargetBlankImpliesNoOpener": false,
  "BrowserSwitcherKeepLastChromeTab": false,
  "RemoteAccessHostClientDomainList": [
    "my-awesome-domain.com",
    "my-auxiliary-domain.com"
  ],
  "NotificationsBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "SerialBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "DefaultImagesSetting": 1,
  "SigninInterceptionEnabled": true,
  "WebUsbBlockedForUrls": [
    "https://www.example.com",
    "[*.]example.edu"
  ],
  "ImportAutofillFormData": true,
  "BrowserSwitcherEnabled": true
}
"""

chromium_json_expected_recommended = \
b"""
{
  "BackgroundModeEnabled": true,
  "RestoreOnStartup": 4,
  "RegisteredProtocolHandlers": [
    {
      "default": true,
      "url": "https://mail.google.com/mail/?extsrc=mailto&url=%s",
      "protocol": "mailto"
    }
  ],
  "ShowHomeButton": true,
  "PrintHeaderFooter": false,
  "SafeBrowsingForTrustedSourcesEnabled": false,
  "ShowFullUrlsInAddressBar": false,
  "MetricsReportingEnabled": true,
  "SpellCheckServiceEnabled": false,
  "ImportSearchEngine": true,
  "DownloadRestrictions": 2,
  "NetworkPredictionOptions": 1,
  "DownloadDirectory": "/home/${user_name}/Downloads",
  "TranslateEnabled": true,
  "AutofillAddressEnabled": false,
  "BookmarkBarEnabled": true,
  "PrintPreviewUseSystemDefaultPrinter": false,
  "ApplicationLocaleValue": "en",
  "ImportHistory": true,
  "RestoreOnStartupURLs": [
    "https://example.com",
    "https://www.chromium.org"
  ],
  "PasswordManagerEnabled": true,
  "ImportSavedPasswords": true,
  "DefaultDownloadDirectory": "/home/${user_name}/Downloads",
  "PasswordLeakDetectionEnabled": true,
  "SearchSuggestEnabled": true,
  "AlternateErrorPagesEnabled": true,
  "HomepageIsNewTabPage": true,
  "ImportAutofillFormData": true,
  "BlockThirdPartyCookies": false,
  "AutofillCreditCardEnabled": false,
  "HomepageLocation": "https://www.chromium.org",
  "SafeBrowsingProtectionLevel": 2,
  "ImportBookmarks": true
}
"""

firewalld_reg_pol = \
br"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="6" signature="PReg" version="1">
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Samba\Unix Settings\Firewalld</Key>
        <ValueName>Zones</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="4" type_name="REG_DWORD">
        <Key>Software\Policies\Samba\Unix Settings\Firewalld</Key>
        <ValueName>Rules</ValueName>
        <Value>1</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Samba\Unix Settings\Firewalld\Rules</Key>
        <ValueName>Rules</ValueName>
        <Value>{&quot;work&quot;: [{&quot;rule&quot;: {&quot;family&quot;: &quot;ipv4&quot;}, &quot;source address&quot;: &quot;172.25.1.7&quot;, &quot;service name&quot;: &quot;ftp&quot;, &quot;reject&quot;: {}}]}</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Samba\Unix Settings\Firewalld\Zones</Key>
        <ValueName>**delvals.</ValueName>
        <Value> </Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Samba\Unix Settings\Firewalld\Zones</Key>
        <ValueName>work</ValueName>
        <Value>work</Value>
    </Entry>
    <Entry type="1" type_name="REG_SZ">
        <Key>Software\Policies\Samba\Unix Settings\Firewalld\Zones</Key>
        <ValueName>home</ValueName>
        <Value>home</Value>
    </Entry>
</PolFile>
"""

drive_maps_xml = b"""<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}"><Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="A:" status="A:" image="2" changed="2023-03-08 19:23:02" uid="{1641E121-DEF3-418D-A428-2D8DF4749504}" bypassErrors="1"><Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\\\example.com\\test" label="TEST" persistent="1" useLetter="0" letter="A"/></Drive>
</Drives>
"""

empty_multi_sz_reg_pol = \
br"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="1" signature="PReg" version="1">
    <Entry type="7" type_name="REG_MULTI_SZ">
        <Key>KeyName</Key>
        <ValueName>ValueName</ValueName>
        <Value/>
    </Entry>
</PolFile>
"""

multiple_values_multi_sz_reg_pol = \
br"""
<?xml version="1.0" encoding="utf-8"?>
<PolFile num_entries="1" signature="PReg" version="1">
    <Entry type="7" type_name="REG_MULTI_SZ">
        <Key>KeyName</Key>
        <ValueName>ValueName</ValueName>
        <Value>Value1</Value>
        <Value>Value2</Value>
        <Value>Value3</Value>
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
    print(stderrdata)
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
        super().setUp()
        self.server = os.environ["SERVER"]
        self.dc_account = self.server.upper() + '$'
        self.lp = s3param.get_context()
        self.lp.load_default()
        self.creds = self.insta_creds(template=self.get_credentials())

    def test_gpo_list(self):
        global poldir, dspath
        gpos = get_gpo_list(self.server, self.creds, self.lp,
                            self.creds.get_username())
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
        gpos = get_gpo_list(self.server, self.creds, self.lp,
                            self.creds.get_username())
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
        ext_path = os.path.join(samba_path, 'python/samba/gp/gp_sec_ext.py')
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

        gpos = get_gpo_list(self.server, self.creds, self.lp,
                            self.dc_account)
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
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_krb_ext(self.lp, machine_creds,
                         machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Include MaxClockSkew to ensure we don't fail on a key we ignore
        stage = '[Kerberos Policy]\nMaxTicketAge = %d\nMaxClockSkew = 5'
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
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_scripts_ext(self.lp, machine_creds,
                             machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
                self.assertEqual(len(scripts), 1,
                    'The %s script was not created' % keyname.decode())
                out, _ = Popen([os.path.join(dname, scripts[0])], stdout=PIPE).communicate()
                self.assertIn(b'hello world', out,
                    '%s script execution failed' % keyname.decode())

                # Check that a call to gpupdate --rsop also succeeds
                ret = rsop(self.lp)
                self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

                # Remove policy
                gp_db = store.get_gplog(machine_creds.get_username())
                del_gpos = get_deleted_gpos_list(gp_db, [])
                ext.process_group_policy(del_gpos, [])
                self.assertEqual(len(os.listdir(dname)), 0,
                                 'Unapply failed to cleanup scripts')

            # Unstage the Registry.pol file
            unstage_file(reg_pol)

    def test_gp_sudoers(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_sudoers_ext(self.lp, machine_creds,
                             machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
            self.assertEqual(len(sudoers), 1, 'The sudoer file was not created')
            self.assertIn(e.data,
                    open(os.path.join(dname, sudoers[0]), 'r').read(),
                    'The sudoers entry was not applied')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            self.assertEqual(len(os.listdir(dname)), 0,
                             'Unapply failed to cleanup scripts')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_vgp_sudoers(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/SUDO/SUDOERSCONFIGURATION/MANIFEST.XML')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_sudoers_ext(self.lp, machine_creds,
                              machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
            self.assertEqual(len(sudoers), 3, 'The sudoer file was not created')
            output = open(os.path.join(dname, sudoers[0]), 'r').read() + \
                     open(os.path.join(dname, sudoers[1]), 'r').read() + \
                     open(os.path.join(dname, sudoers[2]), 'r').read()
            self.assertIn(data, output,
                    'The sudoers entry was not applied')
            self.assertIn(data2, output,
                    'The sudoers entry was not applied')
            self.assertIn(data_no_principal, output,
                    'The sudoers entry was not applied')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            self.assertEqual(len(os.listdir(dname)), 0,
                             'Unapply failed to cleanup scripts')

        # Unstage the Registry.pol file
        unstage_file(manifest)

    def test_gp_inf_ext_utf(self):
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        ext = gp_inf_ext(self.lp, machine_creds,
                         machine_creds.get_username(), store)
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
            self.assertEqual(inf_conf.get('Kerberos Policy', 'MaxTicketAge'),
                             '99', 'MaxTicketAge was not read from the file')

        with NamedTemporaryFile() as f:
            with codecs.open(f.name, 'w', 'utf-8') as w:
                w.write(test_data)
            inf_conf = ext.read(f.name)
            self.assertIn('Kerberos Policy', inf_conf.keys(),
                          'Kerberos Policy was not read from the file')
            self.assertEqual(inf_conf.get('Kerberos Policy', 'MaxTicketAge'),
                             '99', 'MaxTicketAge was not read from the file')

    def test_rsop(self):
        cache_dir = self.lp.get('cache directory')
        local_path = self.lp.cache_path('gpo_cache')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
                ext = ext(self.lp, machine_creds,
                          machine_creds.get_username(), store)
                ret = ext.rsop(g)
                self.assertEqual(len(ret.keys()), 1,
                                 'A single policy should have been displayed')

                # Check the Security Extension
                if type(ext) == gp_krb_ext:
                    self.assertIn('Kerberos Policy', ret.keys(),
                                  'Kerberos Policy not found')
                    self.assertIn('MaxTicketAge', ret['Kerberos Policy'],
                                  'MaxTicketAge setting not found')
                    self.assertEqual(ret['Kerberos Policy']['MaxTicketAge'], '99',
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
                    self.assertEqual(ret['smb.conf'][e3.valuename], e3.data,
                                     'apply group policies was not set')
                # Check the Messages Extension
                elif type(ext) == gp_msgs_ext:
                    self.assertIn('/etc/issue', ret,
                                  'Login Prompt Message not applied')
                    self.assertEqual(ret['/etc/issue'], e4.data,
                                     'Login Prompt Message not set')

                # Check that a call to gpupdate --rsop also succeeds
                ret = rsop(self.lp)
                self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            unstage_file(gpofile % g.name)
            unstage_file(reg_pol % g.name)

    def test_gp_unapply(self):
        cache_dir = self.lp.get('cache directory')
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
                ext = ext(self.lp, machine_creds,
                          machine_creds.get_username(), store)
                if type(ext) == gp_krb_ext:
                    ext.process_group_policy([], gpos)
                    ret = store.get_int('kdc:user_ticket_lifetime')
                    self.assertEqual(ret, 99, 'Kerberos policy was not set')
                elif type(ext) in [gp_scripts_ext, gp_sudoers_ext]:
                    ext.process_group_policy([], gpos, dname)
                    gp_db = store.get_gplog(machine_creds.get_username())
                    applied_settings = gp_db.get_applied_settings([guid])
                    for _, fname in applied_settings[-1][-1][str(ext)].items():
                        fname = fname.split(':')[-1]
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
        guids = ['{31B2F340-016D-11D2-945F-00C04FB984F9}',
                 '{6AC1786C-016F-11D2-945F-00C04FB984F9}']
        reg_pol = os.path.join(local_path, policies, guids[0],
                               'MACHINE/REGISTRY.POL')
        reg_pol2 = os.path.join(local_path, policies, guids[1],
                                'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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

        # Stage the other Registry.pol
        entries = []
        e = preg.entry()
        e.keyname = 'Software\\Policies\\Samba\\smb_conf\\apply group policies'
        e.type = 4
        e.data = 0
        e.valuename = 'apply group policies'
        entries.append(e)
        stage = preg.file()
        stage.num_entries = len(entries)
        stage.entries = entries
        ret = stage_file(reg_pol2, ndr_pack(stage))
        self.assertTrue(ret, 'Failed to create the Registry.pol file')

        with NamedTemporaryFile(suffix='_smb.conf') as f:
            copyfile(self.lp.configfile, f.name)
            lp = LoadParm(f.name)

            # Initialize the group policy extension
            ext = gp_smb_conf_ext(lp, machine_creds,
                                  machine_creds.get_username(), store)
            ext.process_group_policy([], gpos)
            lp = LoadParm(f.name)

            template_homedir = lp.get('template homedir')
            self.assertEqual(template_homedir, '/home/samba/%D/%U',
                             'template homedir was not applied')
            apply_group_policies = lp.get('apply group policies')
            self.assertFalse(apply_group_policies,
                            'apply group policies was not applied')
            ldap_timeout = lp.get('ldap timeout')
            self.assertEqual(ldap_timeout, 9999, 'ldap timeout was not applied')

            # Force apply with removal of second GPO
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = gp_db.get_applied_settings([guids[1]])
            gpos = [gpo for gpo in gpos if gpo.name != guids[1]]
            ext.process_group_policy(del_gpos, gpos)
            lp = LoadParm(f.name)

            template_homedir = lp.get('template homedir')
            self.assertEqual(template_homedir, '/home/samba/%D/%U',
                             'template homedir was not applied')
            apply_group_policies = lp.get('apply group policies')
            self.assertTrue(apply_group_policies,
                            'apply group policies was not applied')
            ldap_timeout = lp.get('ldap timeout')
            self.assertEqual(ldap_timeout, 9999, 'ldap timeout was not applied')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])

            lp = LoadParm(f.name)

            template_homedir = lp.get('template homedir')
            self.assertEqual(template_homedir, self.lp.get('template homedir'),
                             'template homedir was not unapplied')
            apply_group_policies = lp.get('apply group policies')
            self.assertEqual(apply_group_policies, self.lp.get('apply group policies'),
                             'apply group policies was not unapplied')
            ldap_timeout = lp.get('ldap timeout')
            self.assertEqual(ldap_timeout, self.lp.get('ldap timeout'),
                             'ldap timeout was not unapplied')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_gp_motd(self):
        local_path = self.lp.cache_path('gpo_cache')
        guids = ['{31B2F340-016D-11D2-945F-00C04FB984F9}',
                 '{6AC1786C-016F-11D2-945F-00C04FB984F9}']
        reg_pol = os.path.join(local_path, policies, guids[0],
                               'MACHINE/REGISTRY.POL')
        reg_pol2 = os.path.join(local_path, policies, guids[1],
                                'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_msgs_ext(self.lp, machine_creds,
                          machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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

        # Stage the other Registry.pol
        stage = preg.file()
        e3 = preg.entry()
        e3.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Messages'
        e3.valuename = b'motd'
        e3.type = 1
        e3.data = b'This should overwrite the first policy'
        stage.num_entries = 1
        stage.entries = [e3]
        ret = stage_file(reg_pol2, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol2)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            motd_file = os.path.join(dname, 'motd')
            self.assertTrue(os.path.exists(motd_file),
                            'Message of the day file not created')
            data = open(motd_file, 'r').read()
            self.assertEqual(data, e3.data, 'Message of the day not applied')
            issue_file = os.path.join(dname, 'issue')
            self.assertTrue(os.path.exists(issue_file),
                            'Login Prompt Message file not created')
            data = open(issue_file, 'r').read()
            self.assertEqual(data, e2.data, 'Login Prompt Message not applied')

            # Force apply with removal of second GPO
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = gp_db.get_applied_settings([guids[1]])
            gpos = [gpo for gpo in gpos if gpo.name != guids[1]]
            ext.process_group_policy(del_gpos, gpos, dname)

            self.assertTrue(os.path.exists(motd_file),
                            'Message of the day file not created')
            data = open(motd_file, 'r').read()
            self.assertEqual(data, e1.data, 'Message of the day not applied')
            issue_file = os.path.join(dname, 'issue')
            self.assertTrue(os.path.exists(issue_file),
                            'Login Prompt Message file not created')
            data = open(issue_file, 'r').read()
            self.assertEqual(data, e2.data, 'Login Prompt Message not applied')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Unapply policy, and ensure the test files are removed
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
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_symlink_ext(self.lp, machine_creds,
                              machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

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
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_files_ext(self.lp, machine_creds,
                            machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
            self.assertEqual(os.stat(target.text).st_mode & 0o777, 0o755,
                             'The target file permissions are incorrect')
            self.assertEqual(open(target.text).read(), source_data,
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

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

        # Unstage the manifest and source files
        unstage_file(manifest)
        unstage_file(source_file)

    def test_vgp_openssh(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        manifest = os.path.join(local_path, policies, guid, 'MACHINE',
            'VGP/VTLA/SSHCFG/SSHD/MANIFEST.XML')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_openssh_ext(self.lp, machine_creds,
                              machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
            self.assertEqual(len(conf), 1, 'The conf file was not created')
            gp_cfg = os.path.join(dname, conf[0])
            self.assertIn(data, open(gp_cfg, 'r').read(),
                    'The sshd_config entry was not applied')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

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
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_startup_scripts_ext(self.lp, machine_creds,
                                      machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
            self.assertEqual(len(files), 1,
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
            self.assertEqual(len(files), 0,
                             'The target script was not removed')

            # Test rsop
            g = [g for g in gpos if g.name == guid][0]
            ret = ext.rsop(g)
            self.assertIn(entry, list(ret.values())[0][0],
                          'The target entry was not listed by rsop')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

        # Unstage the manifest.xml and script files
        unstage_file(manifest)

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
            self.assertEqual(len(files), 1,
                             'The test file was not created')
            self.assertEqual(files[0], os.path.basename(test_file),
                             'The test file was not created')

            # Unlink the test file and ensure that processing
            # policy again does not recreate it.
            os.unlink(test_file)
            ext.process_group_policy([], gpos, dname)
            files = os.listdir(dname)
            self.assertEqual(len(files), 0,
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

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

        # Unstage the manifest.xml and script files
        unstage_file(manifest)

        # Stage the manifest.xml file for a script without parameters
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        version = etree.SubElement(policysetting, 'version')
        version.text = '1'
        data = etree.SubElement(policysetting, 'data')
        listelement = etree.SubElement(data, 'listelement')
        script = etree.SubElement(listelement, 'script')
        script.text = os.path.basename(test_script).lower()
        hash = etree.SubElement(listelement, 'hash')
        hash.text = \
            hashlib.md5(open(test_script, 'rb').read()).hexdigest().upper()
        run_as = etree.SubElement(listelement, 'run_as')
        run_as.text = 'root'
        ret = stage_file(manifest, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            try:
                ext.process_group_policy([], gpos, dname)
            except Exception as e:
                self.fail(str(e))
            files = os.listdir(dname)
            self.assertEqual(len(files), 1,
                             'The target script was not created')
            entry = '@reboot %s %s' % (run_as.text, test_script)
            self.assertIn(entry,
                          open(os.path.join(dname, files[0]), 'r').read(),
                          'The test entry was not found')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            files = os.listdir(dname)
            self.assertEqual(len(files), 0,
                             'The target script was not removed')

            # Test rsop
            g = [g for g in gpos if g.name == guid][0]
            ret = ext.rsop(g)
            self.assertIn(entry, list(ret.values())[0][0],
                          'The target entry was not listed by rsop')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

        # Unstage the manifest.xml and script files
        unstage_file(manifest)
        unstage_file(test_script)

    def test_vgp_motd(self):
        local_path = self.lp.cache_path('gpo_cache')
        guids = ['{31B2F340-016D-11D2-945F-00C04FB984F9}',
                 '{6AC1786C-016F-11D2-945F-00C04FB984F9}']
        manifest = os.path.join(local_path, policies, guids[0], 'MACHINE',
            'VGP/VTLA/UNIX/MOTD/MANIFEST.XML')
        manifest2 = os.path.join(local_path, policies, guids[1], 'MACHINE',
            'VGP/VTLA/UNIX/MOTD/MANIFEST.XML')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_motd_ext(self.lp, machine_creds,
                           machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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

        # Stage the other manifest.xml
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        version = etree.SubElement(policysetting, 'version')
        version.text = '1'
        data = etree.SubElement(policysetting, 'data')
        filename = etree.SubElement(data, 'filename')
        filename.text = 'motd'
        text2 = etree.SubElement(data, 'text')
        text2.text = 'This should overwrite the first policy'
        ret = stage_file(manifest2, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest2)

        # Process all gpos, with temp output directory
        with NamedTemporaryFile() as f:
            ext.process_group_policy([], gpos, f.name)
            self.assertTrue(os.path.exists(f.name),
                            'Message of the day file not created')
            data = open(f.name, 'r').read()
            self.assertEqual(data, text2.text, 'Message of the day not applied')

            # Force apply with removal of second GPO
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = gp_db.get_applied_settings([guids[1]])
            gpos = [gpo for gpo in gpos if gpo.name != guids[1]]
            ext.process_group_policy(del_gpos, gpos, f.name)

            self.assertEqual(open(f.name, 'r').read(), text.text,
                             'The motd was not applied')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], f.name)
            self.assertNotEqual(open(f.name, 'r').read(), text.text,
                                'The motd was not unapplied')

        # Unstage the manifest files
        unstage_file(manifest)
        unstage_file(manifest2)

    def test_vgp_issue(self):
        local_path = self.lp.cache_path('gpo_cache')
        guids = ['{31B2F340-016D-11D2-945F-00C04FB984F9}',
                 '{6AC1786C-016F-11D2-945F-00C04FB984F9}']
        manifest = os.path.join(local_path, policies, guids[0], 'MACHINE',
            'VGP/VTLA/UNIX/ISSUE/MANIFEST.XML')
        manifest2 = os.path.join(local_path, policies, guids[1], 'MACHINE',
            'VGP/VTLA/UNIX/ISSUE/MANIFEST.XML')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = vgp_issue_ext(self.lp, machine_creds,
                            machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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

        # Stage the other manifest.xml
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        version = etree.SubElement(policysetting, 'version')
        version.text = '1'
        data = etree.SubElement(policysetting, 'data')
        filename = etree.SubElement(data, 'filename')
        filename.text = 'issue'
        text2 = etree.SubElement(data, 'text')
        text2.text = 'This test message overwrites the first'
        ret = stage_file(manifest2, etree.tostring(stage))
        self.assertTrue(ret, 'Could not create the target %s' % manifest2)

        # Process all gpos, with temp output directory
        with NamedTemporaryFile() as f:
            ext.process_group_policy([], gpos, f.name)
            self.assertEqual(open(f.name, 'r').read(), text2.text,
                             'The issue was not applied')

            # Force apply with removal of second GPO
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = gp_db.get_applied_settings([guids[1]])
            gpos = [gpo for gpo in gpos if gpo.name != guids[1]]
            ext.process_group_policy(del_gpos, gpos, f.name)

            self.assertEqual(open(f.name, 'r').read(), text.text,
                             'The issue was not applied')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], f.name)
            self.assertNotEqual(open(f.name, 'r').read(), text.text,
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
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        winbind_sep = self.lp.get('winbind separator')
        self.addCleanup(self.lp.set, 'winbind separator', winbind_sep)
        self.lp.set('winbind separator', '+')
        ext = vgp_access_ext(self.lp, machine_creds,
                             machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
            # There will be 2 files, the policy file and the deny file
            self.assertEqual(len(conf), 2, 'The conf file was not created')
            # Ignore the DENY_ALL conf file
            gp_cfg = os.path.join(dname,
                [c for c in conf if '_gp_DENY_ALL.conf' not in c][0])

            # Check the access config for the correct access.conf entries
            print('Config file %s found' % gp_cfg)
            data = open(gp_cfg, 'r').read()
            self.assertIn('+:%s+goodguy:ALL' % realm, data)
            self.assertIn('+:%s+goodguys:ALL' % realm, data)
            self.assertIn('-:%s+badguy:ALL' % realm, data)
            self.assertIn('-:%s+badguys:ALL' % realm, data)

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

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
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_gnome_settings_ext(self.lp, machine_creds,
                                    machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

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
                self.assertEqual(len(db), count, '%s not created' % name)
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
                self.assertEqual(len(db), 0, '%s not deleted' % name)

            locks = os.path.join(local_db, 'locks')
            self.assertTrue(os.path.isdir(local_db), 'Locks dir not created')
            def lock_check(name, items, count=1):
                lock = glob(os.path.join(locks, '*%s' % name))
                self.assertEqual(len(lock), count,
                                 '%s lock not created' % name)
                file_contents = []
                for i in range(count):
                    file_contents.extend(open(lock[i], 'r').read().split('\n'))
                for data in items:
                    self.assertIn(data, file_contents,
                                  '%s lock not created' % data)

            def del_lock_check(name):
                lock = glob(os.path.join(locks, '*%s' % name))
                self.assertEqual(len(lock), 0, '%s lock not deleted' % name)

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
            self.assertEqual(len(udisk2), 1, 'udisk2 policy not created')
            udisk2_tree = etree.fromstring(open(udisk2[0], 'r').read())
            actions = udisk2_tree.findall('action')
            md = 'org.freedesktop.udisks2.modify-device'
            action = [a for a in actions if a.attrib['id'] == md]
            self.assertEqual(len(action), 1, 'modify-device not found')
            defaults = action[0].find('defaults')
            self.assertTrue(defaults is not None,
                            'modify-device defaults not found')
            allow_any = defaults.find('allow_any').text
            self.assertEqual(allow_any, 'no',
                             'modify-device allow_any not set to no')
            allow_inactive = defaults.find('allow_inactive').text
            self.assertEqual(allow_inactive, 'no',
                             'modify-device allow_inactive not set to no')
            allow_active = defaults.find('allow_active').text
            self.assertEqual(allow_active, 'yes',
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

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

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
            self.assertEqual(len(udisk2), 0, 'udisk2 policy not deleted')
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

    def test_gp_cert_auto_enroll_ext_without_ndes(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        cae.requests = dummy_requests(want_exception=True)
        ext = cae.gp_cert_auto_enroll_ext(self.lp, machine_creds,
                                          machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Stage the Registry.pol file with test data
        parser = GPPolParser()
        parser.load_xml(etree.fromstring(auto_enroll_reg_pol.strip()))
        ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Write the dummy CA entry, Enrollment Services, and Templates Entries
        admin_creds = Credentials()
        admin_creds.set_username(os.environ.get('DC_USERNAME'))
        admin_creds.set_password(os.environ.get('DC_PASSWORD'))
        admin_creds.set_realm(os.environ.get('REALM'))
        hostname = get_dc_hostname(machine_creds, self.lp)
        url = 'ldap://%s' % hostname
        ldb = Ldb(url=url, session_info=system_session(),
                  lp=self.lp, credentials=admin_creds)
        # Write the dummy CA
        confdn = 'CN=Public Key Services,CN=Services,CN=Configuration,%s' % base_dn
        ca_cn = '%s-CA' % hostname.replace('.', '-')
        certa_dn = 'CN=%s,CN=Certification Authorities,%s' % (ca_cn, confdn)
        ldb.add({'dn': certa_dn,
                 'objectClass': 'certificationAuthority',
                 'authorityRevocationList': ['XXX'],
                 'cACertificate': dummy_certificate(),
                 'certificateRevocationList': ['XXX'],
                })
        # Write the dummy pKIEnrollmentService
        enroll_dn = 'CN=%s,CN=Enrollment Services,%s' % (ca_cn, confdn)
        ldb.add({'dn': enroll_dn,
                 'objectClass': 'pKIEnrollmentService',
                 'cACertificate': dummy_certificate(),
                 'certificateTemplates': ['Machine'],
                 'dNSHostName': hostname,
                })
        # Write the dummy pKICertificateTemplate
        template_dn = 'CN=Machine,CN=Certificate Templates,%s' % confdn
        ldb.add({'dn': template_dn,
                 'objectClass': 'pKICertificateTemplate',
                })

        with TemporaryDirectory() as dname:
            try:
                ext.process_group_policy([], gpos, dname, dname)
            except Exception as e:
                self.fail(str(e))

            ca_crt = os.path.join(dname, '%s.crt' % ca_cn)
            self.assertTrue(os.path.exists(ca_crt),
                            'Root CA certificate was not requested')
            machine_crt = os.path.join(dname, '%s.Machine.crt' % ca_cn)
            self.assertTrue(os.path.exists(machine_crt),
                            'Machine certificate was not requested')
            machine_key = os.path.join(dname, '%s.Machine.key' % ca_cn)
            self.assertTrue(os.path.exists(machine_key),
                            'Machine key was not generated')

            # Verify RSOP does not fail
            ext.rsop([g for g in gpos if g.name == guid][0])

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            self.assertFalse(os.path.exists(ca_crt),
                            'Root CA certificate was not removed')
            self.assertFalse(os.path.exists(machine_crt),
                            'Machine certificate was not removed')
            self.assertFalse(os.path.exists(machine_key),
                            'Machine key was not removed')
            out, _ = Popen(['getcert', 'list-cas'], stdout=PIPE).communicate()
            self.assertNotIn(get_bytes(ca_cn), out, 'CA was not removed')
            out, _ = Popen(['getcert', 'list'], stdout=PIPE).communicate()
            self.assertNotIn(b'Machine', out,
                             'Machine certificate not removed')
            self.assertNotIn(b'Workstation', out,
                             'Workstation certificate not removed')

        # Remove the dummy CA, pKIEnrollmentService, and pKICertificateTemplate
        ldb.delete(certa_dn)
        ldb.delete(enroll_dn)
        ldb.delete(template_dn)

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_gp_cert_auto_enroll_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        cae.requests = dummy_requests()
        ext = cae.gp_cert_auto_enroll_ext(self.lp, machine_creds,
                                          machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Stage the Registry.pol file with test data
        parser = GPPolParser()
        parser.load_xml(etree.fromstring(auto_enroll_reg_pol.strip()))
        ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Write the dummy CA entry, Enrollment Services, and Templates Entries
        admin_creds = Credentials()
        admin_creds.set_username(os.environ.get('DC_USERNAME'))
        admin_creds.set_password(os.environ.get('DC_PASSWORD'))
        admin_creds.set_realm(os.environ.get('REALM'))
        hostname = get_dc_hostname(machine_creds, self.lp)
        url = 'ldap://%s' % hostname
        ldb = Ldb(url=url, session_info=system_session(),
                  lp=self.lp, credentials=admin_creds)
        # Write the dummy CA
        confdn = 'CN=Public Key Services,CN=Services,CN=Configuration,%s' % base_dn
        ca_cn = '%s-CA' % hostname.replace('.', '-')
        certa_dn = 'CN=%s,CN=Certification Authorities,%s' % (ca_cn, confdn)
        ldb.add({'dn': certa_dn,
                 'objectClass': 'certificationAuthority',
                 'authorityRevocationList': ['XXX'],
                 'cACertificate': b'0\x82\x03u0\x82\x02]\xa0\x03\x02\x01\x02\x02\x10I',
                 'certificateRevocationList': ['XXX'],
                })
        # Write the dummy pKIEnrollmentService
        enroll_dn = 'CN=%s,CN=Enrollment Services,%s' % (ca_cn, confdn)
        ldb.add({'dn': enroll_dn,
                 'objectClass': 'pKIEnrollmentService',
                 'cACertificate': b'0\x82\x03u0\x82\x02]\xa0\x03\x02\x01\x02\x02\x10I',
                 'certificateTemplates': ['Machine'],
                 'dNSHostName': hostname,
                })
        # Write the dummy pKICertificateTemplate
        template_dn = 'CN=Machine,CN=Certificate Templates,%s' % confdn
        ldb.add({'dn': template_dn,
                 'objectClass': 'pKICertificateTemplate',
                })

        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname, dname)
            ca_crt = os.path.join(dname, '%s.crt' % ca_cn)
            self.assertTrue(os.path.exists(ca_crt),
                            'Root CA certificate was not requested')
            machine_crt = os.path.join(dname, '%s.Machine.crt' % ca_cn)
            self.assertTrue(os.path.exists(machine_crt),
                            'Machine certificate was not requested')
            machine_key = os.path.join(dname, '%s.Machine.key' % ca_cn)
            self.assertTrue(os.path.exists(machine_key),
                            'Machine key was not generated')

            # Subsequent apply should react to new certificate templates
            os.environ['CEPCES_SUBMIT_SUPPORTED_TEMPLATES'] = 'Machine,Workstation'
            self.addCleanup(os.environ.pop, 'CEPCES_SUBMIT_SUPPORTED_TEMPLATES')
            ext.process_group_policy([], gpos, dname, dname)
            self.assertTrue(os.path.exists(ca_crt),
                            'Root CA certificate was not requested')
            self.assertTrue(os.path.exists(machine_crt),
                            'Machine certificate was not requested')
            self.assertTrue(os.path.exists(machine_key),
                            'Machine key was not generated')
            workstation_crt = os.path.join(dname, '%s.Workstation.crt' % ca_cn)
            self.assertTrue(os.path.exists(workstation_crt),
                            'Workstation certificate was not requested')
            workstation_key = os.path.join(dname, '%s.Workstation.key' % ca_cn)
            self.assertTrue(os.path.exists(workstation_key),
                            'Workstation key was not generated')

            # Verify RSOP does not fail
            ext.rsop([g for g in gpos if g.name == guid][0])

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy by staging pol file with auto-enroll unchecked
            parser.load_xml(etree.fromstring(auto_enroll_unchecked_reg_pol.strip()))
            ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
            self.assertTrue(ret, 'Could not create the target %s' % reg_pol)
            ext.process_group_policy([], gpos, dname, dname)
            self.assertFalse(os.path.exists(ca_crt),
                            'Root CA certificate was not removed')
            self.assertFalse(os.path.exists(machine_crt),
                            'Machine certificate was not removed')
            self.assertFalse(os.path.exists(machine_key),
                            'Machine key was not removed')
            self.assertFalse(os.path.exists(workstation_crt),
                            'Workstation certificate was not removed')
            self.assertFalse(os.path.exists(workstation_key),
                            'Workstation key was not removed')

            # Reapply policy by staging the enabled pol file
            parser.load_xml(etree.fromstring(auto_enroll_reg_pol.strip()))
            ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
            self.assertTrue(ret, 'Could not create the target %s' % reg_pol)
            ext.process_group_policy([], gpos, dname, dname)
            self.assertTrue(os.path.exists(ca_crt),
                            'Root CA certificate was not requested')
            self.assertTrue(os.path.exists(machine_crt),
                            'Machine certificate was not requested')
            self.assertTrue(os.path.exists(machine_key),
                            'Machine key was not generated')
            self.assertTrue(os.path.exists(workstation_crt),
                            'Workstation certificate was not requested')
            self.assertTrue(os.path.exists(workstation_key),
                            'Workstation key was not generated')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            self.assertFalse(os.path.exists(ca_crt),
                            'Root CA certificate was not removed')
            self.assertFalse(os.path.exists(machine_crt),
                            'Machine certificate was not removed')
            self.assertFalse(os.path.exists(machine_key),
                            'Machine key was not removed')
            self.assertFalse(os.path.exists(workstation_crt),
                            'Workstation certificate was not removed')
            self.assertFalse(os.path.exists(workstation_key),
                            'Workstation key was not removed')
            out, _ = Popen(['getcert', 'list-cas'], stdout=PIPE).communicate()
            self.assertNotIn(get_bytes(ca_cn), out, 'CA was not removed')
            out, _ = Popen(['getcert', 'list'], stdout=PIPE).communicate()
            self.assertNotIn(b'Machine', out,
                             'Machine certificate not removed')
            self.assertNotIn(b'Workstation', out,
                             'Workstation certificate not removed')

        # Remove the dummy CA, pKIEnrollmentService, and pKICertificateTemplate
        ldb.delete(certa_dn)
        ldb.delete(enroll_dn)
        ldb.delete(template_dn)

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_gp_user_scripts_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guids = ['{31B2F340-016D-11D2-945F-00C04FB984F9}',
                 '{6AC1786C-016F-11D2-945F-00C04FB984F9}']
        reg_pol = os.path.join(local_path, policies, guids[0],
                               'USER/REGISTRY.POL')
        reg_pol2 = os.path.join(local_path, policies, guids[1],
                                'USER/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_user_scripts_ext(self.lp, machine_creds,
                                  os.environ.get('DC_USERNAME'), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        reg_key = b'Software\\Policies\\Samba\\Unix Settings'
        sections = { b'%s\\Daily Scripts' % reg_key : b'@daily',
                     b'%s\\Monthly Scripts' % reg_key : b'@monthly',
                     b'%s\\Weekly Scripts' % reg_key : b'@weekly',
                     b'%s\\Hourly Scripts' % reg_key : b'@hourly' }
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

            # Stage the other Registry.pol
            stage = preg.file()
            e2 = preg.entry()
            e2.keyname = keyname
            e2.valuename = b'Software\\Policies\\Samba\\Unix Settings'
            e2.type = 1
            e2.data = b'echo this is a second policy'
            stage.num_entries = 1
            stage.entries = [e2]
            ret = stage_file(reg_pol2, ndr_pack(stage))
            self.assertTrue(ret, 'Could not create the target %s' % reg_pol2)

            # Process all gpos, intentionally skipping the privilege drop
            ext.process_group_policy([], gpos)
            # Dump the fake crontab setup for testing
            p = Popen(['crontab', '-l'], stdout=PIPE)
            crontab, _ = p.communicate()
            entry = b'%s %s' % (sections[keyname], e.data.encode())
            self.assertIn(entry, crontab,
                'The crontab entry was not installed')
            entry2 = b'%s %s' % (sections[keyname], e2.data.encode())
            self.assertIn(entry2, crontab,
                'The crontab entry was not installed')

            # Force apply with removal of second GPO
            gp_db = store.get_gplog(os.environ.get('DC_USERNAME'))
            del_gpos = gp_db.get_applied_settings([guids[1]])
            rgpos = [gpo for gpo in gpos if gpo.name != guids[1]]
            ext.process_group_policy(del_gpos, rgpos)

            # Dump the fake crontab setup for testing
            p = Popen(['crontab', '-l'], stdout=PIPE)
            crontab, _ = p.communicate()

            # Ensure the first entry remains, and the second entry is removed
            self.assertIn(entry, crontab,
                'The first crontab entry was not found')
            self.assertNotIn(entry2, crontab,
                'The second crontab entry was still present')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            # Dump the fake crontab setup for testing
            p = Popen(['crontab', '-l'], stdout=PIPE)
            crontab, _ = p.communicate()
            self.assertNotIn(entry, crontab,
                'Unapply failed to cleanup crontab entry')

            # Unstage the Registry.pol files
            unstage_file(reg_pol)
            unstage_file(reg_pol2)

    def test_gp_firefox_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_firefox_ext(self.lp, machine_creds,
                             machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Stage the Registry.pol file with test data
        parser = GPPolParser()
        parser.load_xml(etree.fromstring(firefox_reg_pol.strip()))
        ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            policies_file = os.path.join(dname, 'policies.json')
            with open(policies_file, 'r') as r:
                policy_data = json.load(r)
            expected_policy_data = json.loads(firefox_json_expected)
            self.assertIn('policies', policy_data, 'Policies were not applied')
            self.assertEqual(expected_policy_data['policies'].keys(),
                             policy_data['policies'].keys(),
                             'Firefox policies are missing')
            for name in expected_policy_data['policies'].keys():
                self.assertEqual(expected_policy_data['policies'][name],
                                 policy_data['policies'][name],
                                 'Policies were not applied')

            # Check that modifying the policy will enforce the correct settings
            entries = [e for e in parser.pol_file.entries
                       if e.valuename != 'AppUpdateURL']
            for e in entries:
                if e.valuename == 'AppAutoUpdate':
                    e.data = 0
            parser.pol_file.entries = entries
            parser.pol_file.num_entries = len(entries)
            # Stage the Registry.pol file with altered test data
            unstage_file(reg_pol)
            ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
            self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

            # Enforce the altered policy
            ext.process_group_policy([], gpos)

            # Check that the App Update policy was altered
            with open(policies_file, 'r') as r:
                policy_data = json.load(r)
            self.assertIn('policies', policy_data, 'Policies were not applied')
            keys = list(expected_policy_data['policies'].keys())
            keys.remove('AppUpdateURL')
            keys.sort()
            policy_keys = list(policy_data['policies'].keys())
            policy_keys.sort()
            self.assertEqual(keys, policy_keys, 'Firefox policies are incorrect')
            for name in policy_data['policies'].keys():
                self.assertNotEqual(name, 'AppUpdateURL',
                                    'Failed to remove AppUpdateURL policy')
                if name == 'AppAutoUpdate':
                    self.assertEqual(False, policy_data['policies'][name],
                                     'Failed to alter AppAutoUpdate policy')
                    continue
                self.assertEqual(expected_policy_data['policies'][name],
                                 policy_data['policies'][name],
                                 'Policies were not applied')

            # Verify RSOP does not fail
            ext.rsop([g for g in gpos if g.name == guid][0])

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Unapply the policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            if os.path.exists(policies_file):
                data = json.load(open(policies_file, 'r'))
                if 'policies' in data.keys():
                    self.assertEqual(len(data['policies'].keys()), 0,
                                     'The policy was not unapplied')

            # Initialize the cache with old style existing policies,
            # ensure they are overwritten.
            old_cache = {'policies': {}}
            ext.cache_add_attribute(guid, 'policies.json',
                                    json.dumps(old_cache))
            with open(policies_file, 'w') as w:
                w.write(firefox_json_expected)

            # Overwrite policy
            ext.process_group_policy([], gpos)

            # Check that policy was overwritten
            with open(policies_file, 'r') as r:
                policy_data = json.load(r)
            self.assertIn('policies', policy_data, 'Policies were not applied')
            policy_keys = list(policy_data['policies'].keys())
            policy_keys.sort()
            self.assertEqual(keys, policy_keys, 'Firefox policies are incorrect')
            for name in policy_data['policies'].keys():
                self.assertNotEqual(name, 'AppUpdateURL',
                                    'Failed to remove AppUpdateURL policy')
                if name == 'AppAutoUpdate':
                    self.assertEqual(False, policy_data['policies'][name],
                                     'Failed to overwrite AppAutoUpdate policy')
                    continue
                self.assertEqual(expected_policy_data['policies'][name],
                                 policy_data['policies'][name],
                                 'Policies were not applied')

            # Unapply the policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            if os.path.exists(policies_file):
                data = json.load(open(policies_file, 'r'))
                if 'policies' in data.keys():
                    self.assertEqual(len(data['policies'].keys()), 0,
                                     'The policy was not unapplied')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_gp_chromium_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_chromium_ext(self.lp, machine_creds,
                              machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Stage the Registry.pol file with test data
        parser = GPPolParser()
        parser.load_xml(etree.fromstring(chromium_reg_pol.strip()))
        ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            managed = os.path.join(dname, 'managed')
            managed_files = os.listdir(managed)
            self.assertEqual(len(managed_files), 1,
                             'Chromium policies are missing')
            managed_file = os.path.join(managed, managed_files[0])
            with open(managed_file, 'r') as r:
                managed_data = json.load(r)
            recommended = os.path.join(dname, 'recommended')
            recommended_files = os.listdir(recommended)
            self.assertEqual(len(recommended_files), 1,
                             'Chromium policies are missing')
            recommended_file = os.path.join(recommended, recommended_files[0])
            with open(recommended_file, 'r') as r:
                recommended_data = json.load(r)
            expected_managed_data = json.loads(chromium_json_expected_managed)
            expected_recommended_data = \
                json.loads(chromium_json_expected_recommended)
            self.maxDiff = None
            self.assertEqual(sorted(expected_managed_data.keys()),
                             sorted(managed_data.keys()),
                             'Chromium policies are missing')
            for name in expected_managed_data.keys():
                self.assertEqual(expected_managed_data[name],
                                 managed_data[name],
                                 'Policies were not applied')
            self.assertEqual(expected_recommended_data.keys(),
                             recommended_data.keys(),
                             'Chromium policies are missing')
            for name in expected_recommended_data.keys():
                self.assertEqual(expected_recommended_data[name],
                                 recommended_data[name],
                                 'Policies were not applied')

            # Ensure modifying the policy does not generate extra policy files
            unstage_file(reg_pol)
            # Change a managed entry:
            parser.pol_file.entries[0].data = 0
            # Change a recommended entry:
            parser.pol_file.entries[-1].data = b'https://google.com'
            ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
            self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

            ext.process_group_policy([], gpos, dname)
            managed_files = os.listdir(managed)
            self.assertEqual(len(managed_files), 1,
                             'Number of Chromium policies is incorrect')
            omanaged_file = managed_file
            managed_file = os.path.join(managed, managed_files[0])
            self.assertNotEqual(omanaged_file, managed_file,
                                'The managed Chromium file did not change')

            recommended_files = os.listdir(recommended)
            self.assertEqual(len(recommended_files), 1,
                             'Number of Chromium policies is incorrect')
            orecommended_file = recommended_file
            recommended_file = os.path.join(recommended, recommended_files[0])
            self.assertNotEqual(orecommended_file, recommended_file,
                                'The recommended Chromium file did not change')

            # Verify RSOP does not fail
            ext.rsop([g for g in gpos if g.name == guid][0])

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Unapply the policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            managed = os.path.join(managed, managed_files[0])
            if os.path.exists(managed):
                data = json.load(open(managed, 'r'))
                self.assertEqual(len(data.keys()), 0,
                                 'The policy was not unapplied')
            recommended = os.path.join(recommended, recommended_files[0])
            if os.path.exists(recommended):
                data = json.load(open(recommended, 'r'))
                self.assertEqual(len(data.keys()), 0,
                                 'The policy was not unapplied')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_gp_firewalld_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_firewalld_ext(self.lp, machine_creds,
                               machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Stage the Registry.pol file with test data
        parser = GPPolParser()
        parser.load_xml(etree.fromstring(firewalld_reg_pol.strip()))
        ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        ext.process_group_policy([], gpos)

        # Check that the policy was applied
        firewall_cmd = which('firewall-cmd')
        cmd = [firewall_cmd, '--get-zones']
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertIn(b'work', out, 'Failed to apply zones')
        self.assertIn(b'home', out, 'Failed to apply zones')

        cmd = [firewall_cmd, '--zone=work', '--list-interfaces']
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertIn(b'eth0', out, 'Failed to set interface on zone')

        cmd = [firewall_cmd, '--zone=home', '--list-interfaces']
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertIn(b'eth0', out, 'Failed to set interface on zone')

        cmd = [firewall_cmd, '--zone=work', '--list-rich-rules']
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        # Firewalld will report the rule one of two ways:
        rules = [b'rule family=ipv4 source address=172.25.1.7 ' +
                 b'service name=ftp reject',
                 b'rule family="ipv4" source address="172.25.1.7" ' +
                 b'service name="ftp" reject']
        self.assertIn(out.strip(), rules, 'Failed to set rich rule')

        # Check that modifying the policy will enforce the correct settings
        entries = [e for e in parser.pol_file.entries if e.data != 'home']
        self.assertEqual(len(entries), len(parser.pol_file.entries)-1,
                         'Failed to remove the home zone entry')
        parser.pol_file.entries = entries
        parser.pol_file.num_entries = len(entries)
        # Stage the Registry.pol file with altered test data
        unstage_file(reg_pol)
        ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Enforce the altered policy
        ext.process_group_policy([], gpos)

        # Check that the home zone was removed
        cmd = [firewall_cmd, '--get-zones']
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertIn(b'work', out, 'Failed to apply zones')
        self.assertNotIn(b'home', out, 'Failed to apply zones')

        # Verify RSOP does not fail
        ext.rsop([g for g in gpos if g.name == guid][0])

        # Check that a call to gpupdate --rsop also succeeds
        ret = rsop(self.lp)
        self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

        # Unapply the policy
        gp_db = store.get_gplog(machine_creds.get_username())
        del_gpos = get_deleted_gpos_list(gp_db, [])
        ext.process_group_policy(del_gpos, [])

        # Check that the policy was unapplied
        cmd = [firewall_cmd, '--get-zones']
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertNotIn(b'work', out, 'Failed to unapply zones')
        self.assertNotIn(b'home', out, 'Failed to unapply zones')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_advanced_gp_cert_auto_enroll_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        cae.requests = dummy_requests()
        ext = cae.gp_cert_auto_enroll_ext(self.lp, machine_creds,
                                          machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        admin_creds = Credentials()
        admin_creds.set_username(os.environ.get('DC_USERNAME'))
        admin_creds.set_password(os.environ.get('DC_PASSWORD'))
        admin_creds.set_realm(os.environ.get('REALM'))
        hostname = get_dc_hostname(machine_creds, self.lp)
        url = 'ldap://%s' % hostname
        ldb = Ldb(url=url, session_info=system_session(),
                  lp=self.lp, credentials=admin_creds)

        # Stage the Registry.pol file with test data
        res = ldb.search('', _ldb.SCOPE_BASE, '(objectClass=*)',
                         ['rootDomainNamingContext'])
        self.assertTrue(len(res) == 1, 'rootDomainNamingContext not found')
        res2 = ldb.search(res[0]['rootDomainNamingContext'][0],
                          _ldb.SCOPE_BASE, '(objectClass=*)', ['objectGUID'])
        self.assertTrue(len(res2) == 1, 'objectGUID not found')
        objectGUID = b'{%s}' % \
            str(ndr_unpack(misc.GUID, res2[0]['objectGUID'][0])).upper().encode()
        parser = GPPolParser()
        parser.load_xml(etree.fromstring(advanced_enroll_reg_pol.strip() %
            (objectGUID, objectGUID, objectGUID, objectGUID)))
        ret = stage_file(reg_pol, ndr_pack(parser.pol_file))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Write the dummy CA entry
        confdn = 'CN=Public Key Services,CN=Services,CN=Configuration,%s' % base_dn
        ca_cn = '%s-CA' % hostname.replace('.', '-')
        certa_dn = 'CN=%s,CN=Certification Authorities,%s' % (ca_cn, confdn)
        ldb.add({'dn': certa_dn,
                 'objectClass': 'certificationAuthority',
                 'authorityRevocationList': ['XXX'],
                 'cACertificate': b'0\x82\x03u0\x82\x02]\xa0\x03\x02\x01\x02\x02\x10I',
                 'certificateRevocationList': ['XXX'],
                })
        # Write the dummy pKIEnrollmentService
        enroll_dn = 'CN=%s,CN=Enrollment Services,%s' % (ca_cn, confdn)
        ldb.add({'dn': enroll_dn,
                 'objectClass': 'pKIEnrollmentService',
                 'cACertificate': b'0\x82\x03u0\x82\x02]\xa0\x03\x02\x01\x02\x02\x10I',
                 'certificateTemplates': ['Machine'],
                 'dNSHostName': hostname,
                })
        # Write the dummy pKICertificateTemplate
        template_dn = 'CN=Machine,CN=Certificate Templates,%s' % confdn
        ldb.add({'dn': template_dn,
                 'objectClass': 'pKICertificateTemplate',
                })

        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname, dname)
            ca_list = [ca_cn, 'example0-com-CA', 'example1-com-CA',
                       'example2-com-CA']
            for ca in ca_list:
                ca_crt = os.path.join(dname, '%s.crt' % ca)
                self.assertTrue(os.path.exists(ca_crt),
                                'Root CA certificate was not requested')
                machine_crt = os.path.join(dname, '%s.Machine.crt' % ca)
                self.assertTrue(os.path.exists(machine_crt),
                                'Machine certificate was not requested')
                machine_key = os.path.join(dname, '%s.Machine.key' % ca)
                self.assertTrue(os.path.exists(machine_key),
                                'Machine key was not generated')

            # Subsequent apply should react to new certificate templates
            os.environ['CEPCES_SUBMIT_SUPPORTED_TEMPLATES'] = 'Machine,Workstation'
            self.addCleanup(os.environ.pop, 'CEPCES_SUBMIT_SUPPORTED_TEMPLATES')
            ext.process_group_policy([], gpos, dname, dname)
            for ca in ca_list:
                self.assertTrue(os.path.exists(ca_crt),
                                'Root CA certificate was not requested')
                self.assertTrue(os.path.exists(machine_crt),
                                'Machine certificate was not requested')
                self.assertTrue(os.path.exists(machine_key),
                                'Machine key was not generated')

                workstation_crt = os.path.join(dname, '%s.Workstation.crt' % ca)
                self.assertTrue(os.path.exists(workstation_crt),
                                'Workstation certificate was not requested')
                workstation_key = os.path.join(dname, '%s.Workstation.key' % ca)
                self.assertTrue(os.path.exists(workstation_key),
                                'Workstation key was not generated')

            # Verify RSOP does not fail
            ext.rsop([g for g in gpos if g.name == guid][0])

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [], dname)
            self.assertFalse(os.path.exists(ca_crt),
                            'Root CA certificate was not removed')
            self.assertFalse(os.path.exists(machine_crt),
                            'Machine certificate was not removed')
            self.assertFalse(os.path.exists(machine_key),
                            'Machine key was not removed')
            self.assertFalse(os.path.exists(workstation_crt),
                            'Workstation certificate was not removed')
            self.assertFalse(os.path.exists(workstation_key),
                            'Workstation key was not removed')
            out, _ = Popen(['getcert', 'list-cas'], stdout=PIPE).communicate()
            for ca in ca_list:
                self.assertNotIn(get_bytes(ca), out, 'CA was not removed')
            out, _ = Popen(['getcert', 'list'], stdout=PIPE).communicate()
            self.assertNotIn(b'Machine', out,
                             'Machine certificate not removed')
            self.assertNotIn(b'Workstation', out,
                             'Workstation certificate not removed')

        # Remove the dummy CA, pKIEnrollmentService, and pKICertificateTemplate
        ldb.delete(certa_dn)
        ldb.delete(enroll_dn)
        ldb.delete(template_dn)

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_gp_centrify_sudoers_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_centrify_sudoers_ext(self.lp, machine_creds,
                                      machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e1 = preg.entry()
        e1.keyname = b'Software\\Policies\\Centrify\\UnixSettings'
        e1.valuename = b'sudo.enabled'
        e1.type = 4
        e1.data = 1
        e2 = preg.entry()
        e2.keyname = b'Software\\Policies\\Centrify\\UnixSettings\\SuDo'
        e2.valuename = b'1'
        e2.type = 1
        e2.data = b'fakeu ALL=(ALL) NOPASSWD: ALL'
        stage.num_entries = 2
        stage.entries = [e1, e2]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            sudoers = os.listdir(dname)
            self.assertEqual(len(sudoers), 1, 'The sudoer file was not created')
            sudoers_file = os.path.join(dname, sudoers[0])
            self.assertIn(e2.data, open(sudoers_file, 'r').read(),
                    'The sudoers entry was not applied')

            # Remove the sudoers file, and make sure a re-apply puts it back
            os.unlink(sudoers_file)
            ext.process_group_policy([], gpos, dname)
            sudoers = os.listdir(dname)
            self.assertEqual(len(sudoers), 1,
                             'The sudoer file was not recreated')
            sudoers_file = os.path.join(dname, sudoers[0])
            self.assertIn(e2.data, open(sudoers_file, 'r').read(),
                    'The sudoers entry was not reapplied')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            self.assertEqual(len(os.listdir(dname)), 0,
                             'Unapply failed to cleanup scripts')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_gp_centrify_crontab_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        reg_pol = os.path.join(local_path, policies, guid,
                               'MACHINE/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_centrify_crontab_ext(self.lp, machine_creds,
                                      machine_creds.get_username(), store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e = preg.entry()
        e.keyname = \
            b'Software\\Policies\\Centrify\\UnixSettings\\CrontabEntries'
        e.valuename = b'Command1'
        e.type = 1
        e.data = b'17 * * * * root echo hello world'
        stage.num_entries = 1
        stage.entries = [e]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Process all gpos, with temp output directory
        with TemporaryDirectory() as dname:
            ext.process_group_policy([], gpos, dname)
            cron_entries = os.listdir(dname)
            self.assertEqual(len(cron_entries), 1, 'Cron entry not created')
            fname = os.path.join(dname, cron_entries[0])
            data = open(fname, 'rb').read()
            self.assertIn(get_bytes(e.data), data, 'Cron entry is missing')

            # Check that a call to gpupdate --rsop also succeeds
            ret = rsop(self.lp)
            self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

            # Remove policy
            gp_db = store.get_gplog(machine_creds.get_username())
            del_gpos = get_deleted_gpos_list(gp_db, [])
            ext.process_group_policy(del_gpos, [])
            self.assertEqual(len(os.listdir(dname)), 0,
                             'Unapply failed to cleanup script')

            # Unstage the Registry.pol file
            unstage_file(reg_pol)

    def test_gp_user_centrify_crontab_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guids = ['{31B2F340-016D-11D2-945F-00C04FB984F9}',
                 '{6AC1786C-016F-11D2-945F-00C04FB984F9}']
        reg_pol = os.path.join(local_path, policies, guids[0],
                               'USER/REGISTRY.POL')
        reg_pol2 = os.path.join(local_path, policies, guids[1],
                                'USER/REGISTRY.POL')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_user_centrify_crontab_ext(self.lp, machine_creds,
                                           os.environ.get('DC_USERNAME'),
                                           store)

        gpos = get_gpo_list(self.server, machine_creds, self.lp,
                            machine_creds.get_username())

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e = preg.entry()
        e.keyname = \
            b'Software\\Policies\\Centrify\\UnixSettings\\CrontabEntries'
        e.valuename = b'Command1'
        e.type = 1
        e.data = b'17 * * * * echo hello world'
        stage.num_entries = 1
        stage.entries = [e]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        # Stage the other Registry.pol
        stage = preg.file()
        e2 = preg.entry()
        e2.keyname = \
            b'Software\\Policies\\Centrify\\UnixSettings\\CrontabEntries'
        e2.valuename = b'Command1'
        e2.type = 1
        e2.data = b'17 * * * * echo this is a second policy'
        stage.num_entries = 1
        stage.entries = [e2]
        ret = stage_file(reg_pol2, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol2)

        # Process all gpos, intentionally skipping the privilege drop
        ext.process_group_policy([], gpos)
        # Dump the fake crontab setup for testing
        p = Popen(['crontab', '-l'], stdout=PIPE)
        crontab, _ = p.communicate()
        self.assertIn(get_bytes(e.data), crontab,
            'The crontab entry was not installed')
        self.assertIn(get_bytes(e2.data), crontab,
            'The crontab entry was not installed')

        # Force apply with removal of second GPO
        gp_db = store.get_gplog(os.environ.get('DC_USERNAME'))
        del_gpos = gp_db.get_applied_settings([guids[1]])
        gpos = [gpo for gpo in gpos if gpo.name != guids[1]]
        ext.process_group_policy(del_gpos, gpos)

        # Dump the fake crontab setup for testing
        p = Popen(['crontab', '-l'], stdout=PIPE)
        crontab, _ = p.communicate()

        # Ensure the first entry remains, and the second entry is removed
        self.assertIn(get_bytes(e.data), crontab,
            'The first crontab entry was not found')
        self.assertNotIn(get_bytes(e2.data), crontab,
            'The second crontab entry was still present')

        # Check that a call to gpupdate --rsop also succeeds
        ret = rsop(self.lp)
        self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

        # Remove policy
        del_gpos = get_deleted_gpos_list(gp_db, [])
        ext.process_group_policy(del_gpos, [])
        # Dump the fake crontab setup for testing
        p = Popen(['crontab', '-l'], stdout=PIPE)
        crontab, _ = p.communicate()
        self.assertNotIn(get_bytes(e.data), crontab,
            'Unapply failed to cleanup crontab entry')

        # Unstage the Registry.pol files
        unstage_file(reg_pol)
        unstage_file(reg_pol2)

    def test_gp_drive_maps_user_ext(self):
        local_path = self.lp.cache_path('gpo_cache')
        guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        xml_path = os.path.join(local_path, policies, guid,
                                'USER/PREFERENCES/DRIVES/DRIVES.XML')
        cache_dir = self.lp.get('cache directory')
        store = GPOStorage(os.path.join(cache_dir, 'gpo.tdb'))

        machine_creds = Credentials()
        machine_creds.guess(self.lp)
        machine_creds.set_machine_account()

        # Initialize the group policy extension
        ext = gp_drive_maps_user_ext(self.lp, machine_creds,
                                     os.environ.get('DC_USERNAME'), store)

        ads = gpo.ADS_STRUCT(self.server, self.lp, machine_creds)
        if ads.connect():
            gpos = ads.get_gpo_list(machine_creds.get_username())

        # Stage the Drives.xml file with test data
        ret = stage_file(xml_path, drive_maps_xml)
        self.assertTrue(ret, 'Could not create the target %s' % xml_path)

        # Process all gpos, intentionally skipping the privilege drop
        ext.process_group_policy([], gpos)
        # Dump the fake crontab setup for testing
        p = Popen(['crontab', '-l'], stdout=PIPE)
        crontab, _ = p.communicate()
        entry = b'@hourly gio mount smb://example.com/test'
        self.assertIn(entry, crontab,
            'The crontab entry was not installed')

        # Check that a call to gpupdate --rsop also succeeds
        ret = rsop(self.lp)
        self.assertEqual(ret, 0, 'gpupdate --rsop failed!')

        # Unstage the Drives.xml
        unstage_file(xml_path)

        # Modify the policy and ensure it is updated
        xml_conf = etree.fromstring(drive_maps_xml.strip())
        drives = xml_conf.findall('Drive')
        props = drives[0].find('Properties')
        props.attrib['action'] = 'D'
        ret = stage_file(xml_path,
                         etree.tostring(xml_conf, encoding='unicode'))
        self.assertTrue(ret, 'Could not create the target %s' % xml_path)

        # Process all gpos, intentionally skipping the privilege drop
        ext.process_group_policy([], gpos)
        # Dump the fake crontab setup for testing
        p = Popen(['crontab', '-l'], stdout=PIPE)
        crontab, _ = p.communicate()
        self.assertNotIn(entry+b'\n', crontab,
            'The old crontab entry was not removed')
        entry = entry + b' --unmount'
        self.assertIn(entry, crontab,
            'The crontab entry was not installed')

        # Remove policy
        gp_db = store.get_gplog(os.environ.get('DC_USERNAME'))
        del_gpos = get_deleted_gpos_list(gp_db, [])
        ext.process_group_policy(del_gpos, [])
        # Dump the fake crontab setup for testing
        p = Popen(['crontab', '-l'], stdout=PIPE)
        crontab, _ = p.communicate()
        self.assertNotIn(entry, crontab,
                         'Unapply failed to cleanup crontab entry')

        # Unstage the Drives.xml
        unstage_file(xml_path)

        # Modify the policy to set 'run once', ensure there is no cron entry
        xml_conf = etree.fromstring(drive_maps_xml.strip())
        drives = xml_conf.findall('Drive')
        filters = etree.SubElement(drives[0], 'Filters')
        etree.SubElement(filters, 'FilterRunOnce')
        ret = stage_file(xml_path,
                         etree.tostring(xml_conf, encoding='unicode'))
        self.assertTrue(ret, 'Could not create the target %s' % xml_path)

        # Process all gpos, intentionally skipping the privilege drop
        ext.process_group_policy([], gpos)
        # Dump the fake crontab setup for testing
        p = Popen(['crontab', '-l'], stdout=PIPE)
        crontab, _ = p.communicate()
        entry = b'@hourly gio mount smb://example.com/test'
        self.assertNotIn(entry, crontab,
            'The crontab entry was added despite run-once request')

        # Remove policy
        gp_db = store.get_gplog(os.environ.get('DC_USERNAME'))
        del_gpos = get_deleted_gpos_list(gp_db, [])
        ext.process_group_policy(del_gpos, [])

        # Unstage the Drives.xml
        unstage_file(xml_path)

    def test_expand_pref_variables(self):
        cache_path = self.lp.cache_path(os.path.join('gpo_cache'))
        gpt_path = 'TEST'
        username = 'test_uname'
        test_vars = { 'AppDataDir': os.path.expanduser('~/.config'),
                      'ComputerName': self.lp.get('netbios name'),
                      'DesktopDir': os.path.expanduser('~/Desktop'),
                      'DomainName': self.lp.get('realm'),
                      'GptPath': os.path.join(cache_path,
                                              check_safe_path(gpt_path).upper()),
                      'LogonDomain': self.lp.get('realm'),
                      'LogonUser': username,
                      'SystemDrive': '/',
                      'TempDir': '/tmp'
        }
        for exp_var, val in test_vars.items():
            self.assertEqual(expand_pref_variables('%%%s%%' % exp_var,
                                                   gpt_path,
                                                   self.lp,
                                                   username),
                             val, 'Failed to expand variable %s' % exp_var)
        # With the time variables, we can't test for an exact time, so let's do
        # simple checks instead.
        time_vars = ['DateTime', 'DateTimeEx', 'LocalTime',
                     'LocalTimeEx', 'TimeStamp']
        for time_var in time_vars:
            self.assertNotEqual(expand_pref_variables('%%%s%%' % time_var,
                                                      gpt_path,
                                                      self.lp,
                                                      username),
                                None, 'Failed to expand variable %s' % time_var)

        # Here we test to ensure undefined preference variables cause an error.
        # The reason for testing these is to ensure we don't apply nonsense
        # policies when they can't be defined. Also, these tests will fail if
        # one of these is implemented in the future (forcing us to write a test
        # anytime these are implemented).
        undef_vars = ['BinaryComputerSid',
                      'BinaryUserSid',
                      'CommonAppdataDir',
                      'CommonDesktopDir',
                      'CommonFavoritesDir',
                      'CommonProgramsDir',
                      'CommonStartUpDir',
                      'CurrentProccessId',
                      'CurrentThreadId',
                      'FavoritesDir',
                      'GphPath',
                      'GroupPolicyVersion',
                      'LastDriveMapped',
                      'LastError',
                      'LastErrorText',
                      'LdapComputerSid',
                      'LdapUserSid',
                      'LogonServer',
                      'LogonUserSid',
                      'MacAddress',
                      'NetPlacesDir',
                      'OsVersion',
                      'ProgramFilesDir',
                      'ProgramsDir',
                      'RecentDocumentsDir',
                      'ResultCode',
                      'ResultText',
                      'ReversedComputerSid',
                      'ReversedUserSid',
                      'SendToDir',
                      'StartMenuDir',
                      'StartUpDir',
                      'SystemDir',
                      'TraceFile',
                      'WindowsDir'
        ]
        for undef_var in undef_vars:
            try:
                expand_pref_variables('%%%s%%' % undef_var, gpt_path, self.lp)
            except NameError:
                pass
            else:
                self.fail('Undefined variable %s caused no error' % undef_var)

    def test_parser_roundtrip_empty_multi_sz(self):
        with TemporaryDirectory() as dname:
            reg_pol_xml = os.path.join(dname, 'REGISTRY.POL.XML')

            parser = GPPolParser()
            try:
                parser.load_xml(etree.fromstring(empty_multi_sz_reg_pol.strip()))
            except Exception as e:
                self.fail(str(e))
            parser.write_xml(reg_pol_xml)

            with open(reg_pol_xml, 'r') as f:
                pol_xml_data = f.read()

            # Strip whitespace characters due to indentation differences
            expected_xml_data = re.sub(r"\s+", "", empty_multi_sz_reg_pol.decode(), flags=re.UNICODE)
            actual_xml_data = re.sub(r"\s+", "", pol_xml_data, flags=re.UNICODE)
            self.assertEqual(expected_xml_data, actual_xml_data, 'XML data mismatch')

    def test_parser_roundtrip_multiple_values_multi_sz(self):
        with TemporaryDirectory() as dname:
            reg_pol_xml = os.path.join(dname, 'REGISTRY.POL.XML')

            parser = GPPolParser()
            try:
                parser.load_xml(etree.fromstring(multiple_values_multi_sz_reg_pol.strip()))
            except Exception as e:
                self.fail(str(e))
            parser.write_xml(reg_pol_xml)

            with open(reg_pol_xml, 'r') as f:
                pol_xml_data = f.read()

            # Strip whitespace characters due to indentation differences
            expected_xml_data = re.sub(r"\s+", "", multiple_values_multi_sz_reg_pol.decode(), flags=re.UNICODE)
            actual_xml_data = re.sub(r"\s+", "", pol_xml_data, flags=re.UNICODE)
            self.assertEqual(expected_xml_data, actual_xml_data, 'XML data mismatch')

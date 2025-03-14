# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett 2012
#
# based on time.py:
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
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
#

import os, pwd, grp
import ldb
import samba
from samba.tests.samba_tool.base import SambaToolCmdTest
import shutil
from samba.netcmd.gpo import get_gpo_dn, get_gpo_info
from samba.param import LoadParm
from samba.tests.gpo import stage_file, unstage_file
from samba.dcerpc import preg
from samba.ndr import ndr_pack, ndr_unpack
from samba.common import get_string
from configparser import ConfigParser
import xml.etree.ElementTree as etree
from tempfile import NamedTemporaryFile
import re
from samba.gp.gpclass import check_guid
from samba.gp_parse.gp_ini import GPTIniParser

gpo_load_json = \
b"""
[
    {
        "keyname": "Software\\\\Policies\\\\Mozilla\\\\Firefox\\\\Homepage",
        "valuename": "StartPage",
        "class": "USER",
        "type": "REG_SZ",
        "data": "homepage"
    },
    {
        "keyname": "Software\\\\Policies\\\\Mozilla\\\\Firefox\\\\Homepage",
        "valuename": "URL",
        "class": "USER",
        "type": 1,
        "data": "samba.org"
    },
    {
        "keyname": "Software\\\\Microsoft\\\\Internet Explorer\\\\Toolbar",
        "valuename": "IEToolbar",
        "class": "USER",
        "type": "REG_BINARY",
        "data": [0]
    },
    {
        "keyname": "Software\\\\Policies\\\\Microsoft\\\\InputPersonalization",
        "valuename": "RestrictImplicitTextCollection",
        "class": "USER",
        "type": "REG_DWORD",
        "data": 1
    },
    {
        "keyname": "Software\\\\Policies\\\\Mozilla\\\\Firefox",
        "valuename": "ExtensionSettings",
        "class": "MACHINE",
        "type": "REG_MULTI_SZ",
        "data": [
            "{",
            "   \\"key\\": \\"value\\"",
            "}"
        ]
    }
]
"""

gpo_remove_json = \
b"""
[
    {
        "keyname": "Software\\\\Policies\\\\Mozilla\\\\Firefox\\\\Homepage",
        "valuename": "StartPage",
        "class": "USER"
    },
    {
        "keyname": "Software\\\\Policies\\\\Mozilla\\\\Firefox\\\\Homepage",
        "valuename": "URL",
        "class": "USER"
    },
    {
        "keyname": "Software\\\\Microsoft\\\\Internet Explorer\\\\Toolbar",
        "valuename": "IEToolbar",
        "class": "USER"
    },
    {
        "keyname": "Software\\\\Policies\\\\Microsoft\\\\InputPersonalization",
        "valuename": "RestrictImplicitTextCollection",
        "class": "USER"
    },
    {
        "keyname": "Software\\\\Policies\\\\Mozilla\\\\Firefox",
        "valuename": "ExtensionSettings",
        "class": "MACHINE"
    }
]
"""

def gpt_ini_version(gpo_guid):
    lp = LoadParm()
    lp.load(os.environ['SERVERCONFFILE'])
    local_path = lp.get('path', 'sysvol')
    GPT_INI = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                           gpo_guid, 'GPT.INI')
    if os.path.exists(GPT_INI):
        with open(GPT_INI, 'rb') as f:
            data = f.read()
        parser = GPTIniParser()
        parser.parse(data)
        if parser.ini_conf.has_option('General', 'Version'):
            version = int(parser.ini_conf.get('General',
                                              'Version').encode('utf-8'))
        else:
            version = 0
    else:
        version = 0
    return version

# These are new GUIDs, not used elsewhere, made up for the use of testing the
# adding of extension GUIDs in `samba-tool gpo load`.
ext_guids = ['{123d2b56-7b14-4516-bbc4-763d29d57654}',
             '{d000e91b-e70f-481b-9549-58de7929bcee}']

source_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../.."))
provision_path = os.path.join(source_path, "source4/selftest/provisions/")

def has_difference(path1, path2, binary=True, xml=True, sortlines=False):
    """Use this function to determine if the GPO backup differs from another.

    xml=True checks whether any xml files are equal
    binary=True checks whether any .SAMBABACKUP files are equal
    """
    if os.path.isfile(path1):
        if sortlines:
            file1 = open(path1).readlines()
            file1.sort()
            file2 = open(path1).readlines()
            file2.sort()
            if file1 != file2:
                return path1

        elif open(path1).read() != open(path2).read():
            return path1

        return None

    l_dirs = [ path1 ]
    r_dirs = [ path2 ]
    while l_dirs:
        l_dir = l_dirs.pop()
        r_dir = r_dirs.pop()

        dirlist = os.listdir(l_dir)
        dirlist_other = os.listdir(r_dir)

        dirlist.sort()
        dirlist_other.sort()
        if dirlist != dirlist_other:
            return dirlist

        for e in dirlist:
            l_name = os.path.join(l_dir, e)
            r_name = os.path.join(r_dir, e)

            if os.path.isdir(l_name):
                l_dirs.append(l_name)
                r_dirs.append(r_name)
            else:
                if (l_name.endswith('.xml') and xml or
                    l_name.endswith('.SAMBABACKUP') and binary):
                    with open(l_name, "rb") as f1, open(r_name, "rb") as f2:
                        if f1.read() != f2.read():
                            return l_name

    return None


class GpoCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool time subcommands"""

    gpo_name = "testgpo"

    # This exists in the source tree to be restored
    backup_gpo_guid = "{1E1DC8EA-390C-4800-B327-98B56A0AEA5D}"

    def test_gpo_list(self):
        """Run gpo list against the server and make sure it looks accurate"""
        (result, out, err) = self.runsubcmd("gpo", "listall", "-H", "ldap://%s" % os.environ["SERVER"])
        self.assertCmdSuccess(result, out, err, "Ensuring gpo listall ran successfully")

    def test_fetchfail(self):
        """Run against a non-existent GPO, and make sure it fails (this hard-coded UUID is very unlikely to exist"""
        (result, out, err) = self.runsubcmd("gpo", "fetch", "c25cac17-a02a-4151-835d-fae17446ee43", "-H", "ldap://%s" % os.environ["SERVER"])
        self.assertCmdFail(result, "check for result code")

    def test_fetch(self):
        """Run against a real GPO, and make sure it passes"""
        (result, out, err) = self.runsubcmd("gpo", "fetch", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"], "--tmpdir", self.tempdir)
        self.assertCmdSuccess(result, out, err, "Ensuring gpo fetched successfully")
        shutil.rmtree(os.path.join(self.tempdir, "policy"))

    def test_show(self):
        """Show a real GPO, and make sure it passes"""
        (result, out, err) = self.runsubcmd("gpo", "show", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"])
        self.assertCmdSuccess(result, out, err, "Ensuring gpo fetched successfully")

    def test_show_as_admin(self):
        """Show a real GPO, and make sure it passes"""
        (result, out, err) = self.runsubcmd("gpo", "show", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"], "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Ensuring gpo fetched successfully")

    def test_aclcheck(self):
        """Check all the GPOs on the remote server have correct ACLs"""
        (result, out, err) = self.runsubcmd("gpo", "aclcheck", "-H", "ldap://%s" % os.environ["SERVER"], "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Ensuring gpo checked successfully")

    def test_getlink_empty(self):
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
                                   "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                 os.environ["DC_PASSWORD"]))

        container_dn = 'OU=gpo_test_link,%s' % self.samdb.get_default_basedn()

        self.samdb.add({
            'dn': container_dn,
            'objectClass': 'organizationalUnit'
        })

        (result, out, err) = self.runsubcmd("gpo", "getlink", container_dn,
                                            "-H", "ldap://%s" % os.environ["SERVER"],
                                            "-U%s%%%s" % (os.environ["USERNAME"],
                                                          os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Ensuring gpo link fetched successfully")

        # Microsoft appears to allow an empty space character after deletion of
        # a GPO. We should be able to handle this.
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, container_dn)
        m['gPLink'] = ldb.MessageElement(' ', ldb.FLAG_MOD_REPLACE, 'gPLink')
        self.samdb.modify(m)

        (result, out, err) = self.runsubcmd("gpo", "getlink", container_dn,
                                            "-H", "ldap://%s" % os.environ["SERVER"],
                                            "-U%s%%%s" % (os.environ["USERNAME"],
                                                          os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Ensuring gpo link fetched successfully")

        self.samdb.delete(container_dn)

    def test_backup_restore_compare_binary(self):
        """Restore from a static backup and compare the binary contents"""

        if not os.path.exists(provision_path):
            self.skipTest('Test requires provision data not available in '
                          + 'release tarball')

        static_path = os.path.join(self.backup_path, 'policy',
                                   self.backup_gpo_guid)

        temp_path = os.path.join(self.tempdir, 'temp')
        os.mkdir(temp_path)

        new_path = os.path.join(self.tempdir, 'new')
        os.mkdir(new_path)

        gpo_guid = None
        try:
            (result, out, err) = self.runsubcmd("gpo", "restore", "BACKUP_RESTORE1",
                                                static_path,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"], "--tmpdir",
                                                temp_path, "--entities",
                                                self.entity_file, "-U%s%%%s" %
                                                (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]),
                                                "--restore-metadata")

            self.assertCmdSuccess(result, out, err,
                                  "Ensure gpo restore successful")

            gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]

            (result, out, err) = self.runsubcmd("gpo", "backup", gpo_guid,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"],
                                                "--tmpdir", new_path)

            self.assertCmdSuccess(result, out, err, "Ensuring gpo fetched successfully")

            # Compare the directories
            self.assertIsNone(has_difference(os.path.join(new_path, 'policy',
                                                          gpo_guid),
                                             static_path, binary=True,
                                             xml=False))
        finally:
            if gpo_guid:
                (result, out, err) = self.runsubcmd("gpo", "del", gpo_guid,
                                                    "-H", "ldap://%s" %
                                                    os.environ["SERVER"],
                                                    "-U%s%%%s" %
                                                    (os.environ["USERNAME"],
                                                     os.environ["PASSWORD"]))
                self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")

            shutil.rmtree(temp_path)
            shutil.rmtree(new_path)

    def test_backup_restore_no_entities_compare_binary(self):
        """Restore from a static backup (and use no entity file, resulting in
        copy-restore fallback), and compare the binary contents"""

        if not os.path.exists(provision_path):
            self.skipTest('Test requires provision data not available in '
                          + 'release tarball')

        static_path = os.path.join(self.backup_path, 'policy',
                                   self.backup_gpo_guid)

        temp_path = os.path.join(self.tempdir, 'temp')
        os.mkdir(temp_path)

        new_path = os.path.join(self.tempdir, 'new')
        os.mkdir(new_path)

        gpo_guid = None
        gpo_guid1 = None
        gpo_guid2 = None
        try:
            (result, out, err) = self.runsubcmd("gpo", "restore", "BACKUP_RESTORE1",
                                                static_path,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"], "--tmpdir",
                                                temp_path, "--entities",
                                                self.entity_file, "-U%s%%%s" %
                                                (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]),
                                                "--restore-metadata")

            self.assertCmdSuccess(result, out, err,
                                  "Ensure gpo restore successful")

            gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]
            gpo_guid1 = gpo_guid

            # Do not output entities file
            (result, out, err) = self.runsubcmd("gpo", "backup", gpo_guid,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"],
                                                "--tmpdir", new_path,
                                                "--generalize")

            self.assertCmdSuccess(result, out, err, "Ensuring gpo fetched successfully")

            # Do not use an entities file
            (result, out, err) = self.runsubcmd("gpo", "restore", "BACKUP_RESTORE2",
                                                os.path.join(new_path, 'policy', gpo_guid1),
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"], "--tmpdir",
                                                temp_path, "-U%s%%%s" %
                                                (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]),
                                                "--restore-metadata")

            self.assertCmdSuccess(result, out, err,
                                  "Ensure gpo restore successful")

            gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]
            gpo_guid2 = gpo_guid

            self.assertCmdSuccess(result, out, err, "Ensuring gpo restored successfully")

            (result, out, err) = self.runsubcmd("gpo", "backup", gpo_guid,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"],
                                                "--tmpdir", new_path)

            # Compare the directories
            self.assertIsNone(has_difference(os.path.join(new_path, 'policy',
                                                          gpo_guid1),
                                             os.path.join(new_path, 'policy',
                                                          gpo_guid2),
                                             binary=True, xml=False))
        finally:
            if gpo_guid1:
                (result, out, err) = self.runsubcmd("gpo", "del", gpo_guid1,
                                                    "-H", "ldap://%s" %
                                                    os.environ["SERVER"],
                                                    "-U%s%%%s" %
                                                    (os.environ["USERNAME"],
                                                     os.environ["PASSWORD"]))
                self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")

            if gpo_guid2:
                (result, out, err) = self.runsubcmd("gpo", "del", gpo_guid2,
                                                    "-H", "ldap://%s" %
                                                    os.environ["SERVER"],
                                                    "-U%s%%%s" %
                                                    (os.environ["USERNAME"],
                                                     os.environ["PASSWORD"]))
                self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")

            shutil.rmtree(temp_path)
            shutil.rmtree(new_path)

    def test_backup_restore_backup_compare_XML(self):
        """Restore from a static backup and backup to compare XML"""

        if not os.path.exists(provision_path):
            self.skipTest('Test requires provision data not available in '
                          + 'release tarball')

        static_path = os.path.join(self.backup_path, 'policy',
                                   self.backup_gpo_guid)

        temp_path = os.path.join(self.tempdir, 'temp')
        os.mkdir(temp_path)

        new_path = os.path.join(self.tempdir, 'new')
        os.mkdir(new_path)

        gpo_guid = None
        gpo_guid1 = None
        gpo_guid2 = None
        try:
            (result, out, err) = self.runsubcmd("gpo", "restore", "BACKUP_RESTORE1",
                                                static_path,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"], "--tmpdir",
                                                temp_path, "--entities",
                                                self.entity_file, "-U%s%%%s" %
                                                (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]),
                                                "--restore-metadata")

            self.assertCmdSuccess(result, out, err,
                                  "Ensure gpo restore successful")

            gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]
            gpo_guid1 = gpo_guid

            (result, out, err) = self.runsubcmd("gpo", "backup", gpo_guid,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"],
                                                "--tmpdir", new_path)

            self.assertCmdSuccess(result, out, err, "Ensuring gpo fetched successfully")

            (result, out, err) = self.runsubcmd("gpo", "restore", "BACKUP_RESTORE2",
                                                os.path.join(new_path, 'policy', gpo_guid1),
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"], "--tmpdir",
                                                temp_path, "--entities",
                                                self.entity_file, "-U%s%%%s" %
                                                (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]),
                                                "--restore-metadata")

            self.assertCmdSuccess(result, out, err,
                                  "Ensure gpo restore successful")

            gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]
            gpo_guid2 = gpo_guid

            self.assertCmdSuccess(result, out, err, "Ensuring gpo restored successfully")

            (result, out, err) = self.runsubcmd("gpo", "backup", gpo_guid,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"],
                                                "--tmpdir", new_path)

            # Compare the directories
            self.assertIsNone(has_difference(os.path.join(new_path, 'policy',
                                                          gpo_guid1),
                                             os.path.join(new_path, 'policy',
                                                          gpo_guid2),
                                             binary=True, xml=True))
        finally:
            if gpo_guid1:
                (result, out, err) = self.runsubcmd("gpo", "del", gpo_guid1,
                                                    "-H", "ldap://%s" %
                                                    os.environ["SERVER"],
                                                    "-U%s%%%s" %
                                                    (os.environ["USERNAME"],
                                                     os.environ["PASSWORD"]))
                self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")

            if gpo_guid2:
                (result, out, err) = self.runsubcmd("gpo", "del", gpo_guid2,
                                                    "-H", "ldap://%s" %
                                                    os.environ["SERVER"],
                                                    "-U%s%%%s" %
                                                    (os.environ["USERNAME"],
                                                     os.environ["PASSWORD"]))
                self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")

            shutil.rmtree(temp_path)
            shutil.rmtree(new_path)

    def test_backup_restore_generalize(self):
        """Restore from a static backup with different entities, generalize it
        again, and compare the XML"""

        if not os.path.exists(provision_path):
            self.skipTest('Test requires provision data not available in '
                          + 'release tarball')

        static_path = os.path.join(self.backup_path, 'policy',
                                   self.backup_gpo_guid)

        temp_path = os.path.join(self.tempdir, 'temp')
        os.mkdir(temp_path)

        new_path = os.path.join(self.tempdir, 'new')
        os.mkdir(new_path)

        alt_entity_file = os.path.join(new_path, 'entities')
        with open(alt_entity_file, 'wb') as f:
            f.write(b'''<!ENTITY SAMBA__NETWORK_PATH__82419dafed126a07d6b96c66fc943735__ "\\\\samdom.example.com">
<!ENTITY SAMBA__NETWORK_PATH__0484cd41ded45a0728333a9c5e5ef619__ "\\\\samdom">
<!ENTITY SAMBA____SDDL_ACL____4ce8277be3f630300cbcf80a80e21cf4__ "D:PAR(A;CI;KA;;;BA)(A;CIIO;KA;;;CO)(A;CI;KA;;;SY)(A;CI;KR;;;S-1-16-0)">
<!ENTITY SAMBA____USER_ID_____d0970f5a1e19cb803f916c203d5c39c4__ "*S-1-5-113">
<!ENTITY SAMBA____USER_ID_____7b7bc2512ee1fedcd76bdc68926d4f7b__ "Administrator">
<!ENTITY SAMBA____USER_ID_____a3069f5a7a6530293ad8df6abd32af3d__ "Foobaz">
<!ENTITY SAMBA____USER_ID_____fdf60b2473b319c8c341de5f62479a7d__ "*S-1-5-32-545">
<!ENTITY SAMBA____USER_ID_____adb831a7fdd83dd1e2a309ce7591dff8__ "Guest">
<!ENTITY SAMBA____USER_ID_____9fa835214b4fc8b6102c991f7d97c2f8__ "*S-1-5-32-547">
<!ENTITY SAMBA____USER_ID_____bf8caafa94a19a6262bad2e8b6d4bce6__ "*S-1-5-32-546">
<!ENTITY SAMBA____USER_ID_____a45da96d0bf6575970f2d27af22be28a__ "System">
<!ENTITY SAMBA____USER_ID_____171d33a63ebd67f856552940ed491ad3__ "s-1-5-32-545">
<!ENTITY SAMBA____USER_ID_____7140932fff16ce85cc64d3caab588d0d__ "s-1-1-0">
''')

        gen_entity_file = os.path.join(temp_path, 'entities')

        gpo_guid = None
        try:
            (result, out, err) = self.runsubcmd("gpo", "restore", "BACKUP_RESTORE1",
                                                static_path,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"], "--tmpdir",
                                                temp_path, "--entities",
                                                alt_entity_file, "-U%s%%%s" %
                                                (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]),
                                                "--restore-metadata")

            self.assertCmdSuccess(result, out, err, "Ensuring gpo restored successfully")

            gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]

            (result, out, err) = self.runsubcmd("gpo", "backup", gpo_guid,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"],
                                                "--tmpdir", new_path,
                                                "--generalize", "--entities",
                                                gen_entity_file)

            self.assertCmdSuccess(result, out, err, "Ensuring gpo fetched successfully")

            # Assert entity files are identical (except for line order)
            self.assertIsNone(has_difference(alt_entity_file,
                                             gen_entity_file,
                                             sortlines=True))

            # Compare the directories (XML)
            self.assertIsNone(has_difference(os.path.join(new_path, 'policy',
                                                          gpo_guid),
                                             static_path, binary=False,
                                             xml=True))
        finally:
            if gpo_guid:
                (result, out, err) = self.runsubcmd("gpo", "del", gpo_guid,
                                                    "-H", "ldap://%s" %
                                                    os.environ["SERVER"],
                                                    "-U%s%%%s" %
                                                    (os.environ["USERNAME"],
                                                     os.environ["PASSWORD"]))
                self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")

            shutil.rmtree(temp_path)
            shutil.rmtree(new_path)

    def test_backup_with_extension_attributes(self):
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
                                   "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                 os.environ["DC_PASSWORD"]))

        temp_path = os.path.join(self.tempdir, 'temp')
        os.mkdir(temp_path)

        extensions = {
            # Taken from "source4/setup/provision_group_policy.ldif" on domain
            'gPCMachineExtensionNames': '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]',
            'gPCUserExtensionNames': '[{3060E8D0-7020-11D2-842D-00C04FA372D4}{3060E8CE-7020-11D2-842D-00C04FA372D4}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{0F6B957E-509E-11D1-A7CC-0000F87571E3}]'
        }

        gpo_dn = get_gpo_dn(self.samdb, self.gpo_guid)
        for ext in extensions:
            data = extensions[ext]

            m = ldb.Message()
            m.dn = gpo_dn
            m[ext] = ldb.MessageElement(data, ldb.FLAG_MOD_REPLACE, ext)

            self.samdb.modify(m)

        try:
            (result, out, err) = self.runsubcmd("gpo", "backup", self.gpo_guid,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"],
                                                "--tmpdir", temp_path)

            self.assertCmdSuccess(result, out, err, "Ensuring gpo fetched successfully")

            guid = "{%s}" % out.split("{")[1].split("}")[0]

            temp_path = os.path.join(temp_path, 'policy', guid)

            (result, out, err) = self.runsubcmd("gpo", "restore", "RESTORE_EXT",
                                                temp_path,
                                                "-H", "ldap://%s" %
                                                os.environ["SERVER"], "--tmpdir",
                                                self.tempdir, "-U%s%%%s" %
                                                (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]),
                                                "--restore-metadata")

            self.assertCmdSuccess(result, out, err, "Ensuring gpo restored successfully")

            gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]

            msg = get_gpo_info(self.samdb, gpo_guid)
            self.assertEqual(len(msg), 1)

            for ext in extensions:
                self.assertTrue(ext in msg[0])
                self.assertEqual(extensions[ext], str(msg[0][ext][0]))

        finally:
            if gpo_guid:
                (result, out, err) = self.runsubcmd("gpo", "del", gpo_guid,
                                                    "-H", "ldap://%s" %
                                                    os.environ["SERVER"],
                                                    "-U%s%%%s" %
                                                    (os.environ["USERNAME"],
                                                     os.environ["PASSWORD"]))
                self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")

            shutil.rmtree(os.path.join(self.tempdir, "policy"))
            shutil.rmtree(os.path.join(self.tempdir, 'temp'))

    def test_admx_load(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        admx_path = os.path.join(local_path, os.environ['REALM'].lower(),
                                 'Policies', 'PolicyDefinitions')
        (result, out, err) = self.runsubcmd("gpo", "admxload",
                                            "-H", "ldap://%s" %
                                            os.environ["SERVER"],
                                            "--admx-dir=%s" %
                                            os.path.join(source_path,
                                                         'libgpo/admx'),
                                            "-U%s%%%s" %
                                            (os.environ["USERNAME"],
                                            os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Filling PolicyDefinitions failed')
        self.assertTrue(os.path.exists(admx_path),
                        'PolicyDefinitions was not created')
        self.assertTrue(os.path.exists(os.path.join(admx_path, 'samba.admx')),
                        'Filling PolicyDefinitions failed')
        shutil.rmtree(admx_path)

    def test_smb_conf_set(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        reg_pol = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/Registry.pol')

        policy = 'apply group policies'
        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "smb_conf",
                                                 "set"), self.gpo_guid,
                                                 policy, "yes",
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to set apply group policies')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        self.assertTrue(os.path.exists(reg_pol),
                        'The Registry.pol does not exist')
        with open(reg_pol, 'rb') as f:
            reg_data = ndr_unpack(preg.file, f.read())
        ret = any([get_string(e.valuename) == policy and e.data == 1
            for e in reg_data.entries])
        self.assertTrue(ret, 'The sudoers entry was not added')

        before_vers = after_vers
        # Ensure an empty set command deletes the entry
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "smb_conf",
                                                 "set"), self.gpo_guid,
                                                 policy, "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to unset apply group policies')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')
        with open(reg_pol, 'rb') as f:
            reg_data = ndr_unpack(preg.file, f.read())
        ret = not any([get_string(e.valuename) == policy and e.data == 1
            for e in reg_data.entries])
        self.assertTrue(ret, 'The sudoers entry was not removed')

    def test_smb_conf_list(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        reg_pol = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/Registry.pol')

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e = preg.entry()
        e.keyname = b'Software\\Policies\\Samba\\smb_conf'
        e.valuename = b'apply group policies'
        e.type = 4
        e.data = 1
        stage.num_entries = 1
        stage.entries = [e]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "smb_conf",
                                                 "list"), self.gpo_guid,
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn('%s = True' % e.valuename, out, 'The test entry was not found!')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_security_set(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        inf_pol = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
            self.gpo_guid, 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf')

        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "security",
                                                 "set"), self.gpo_guid,
                                                 'MaxTicketAge', '10',
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to set MaxTicketAge')
        self.assertTrue(os.path.exists(inf_pol),
                        '%s was not created' % inf_pol)
        inf_pol_contents = open(inf_pol, 'r').read()
        self.assertIn('MaxTicketAge = 10', inf_pol_contents,
                      'The test entry was not found!')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        before_vers = after_vers
        # Ensure an empty set command deletes the entry
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "security",
                                                 "set"), self.gpo_guid,
                                                 'MaxTicketAge',
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to unset MaxTicketAge')
        with open(inf_pol, 'r') as f:
            inf_pol_contents = f.read()
        self.assertNotIn('MaxTicketAge = 10', inf_pol_contents,
                      'The test entry was still found!')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

    def test_security_list(self):
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "security",
                                                 "set"), self.gpo_guid,
                                                 'MaxTicketAge', '10',
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to set MaxTicketAge')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "security",
                                                 "list"), self.gpo_guid,
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn('MaxTicketAge = 10', out, 'The test entry was not found!')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "security",
                                                 "set"), self.gpo_guid,
                                                 'MaxTicketAge',
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to unset MaxTicketAge')

    def test_security_nonempty_sections(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        gpt_inf = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/Microsoft/Windows NT',
                               'SecEdit/GptTmpl.inf')

        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "security",
                                                 "set"), self.gpo_guid,
                                                 'MaxTicketAge', '10',
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to set MaxTicketAge')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "security",
                                                 "set"), self.gpo_guid,
                                                 'MaxTicketAge',
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err,
                              'Failed to unset MaxTicketAge')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        inf_data = ConfigParser(interpolation=None)
        inf_data.read(gpt_inf)

        self.assertFalse(inf_data.has_section('Kerberos Policy'))

    def test_sudoers_add(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        reg_pol = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/Registry.pol')

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e = preg.entry()
        e.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Sudo Rights'
        e.valuename = b'Software\\Policies\\Samba\\Unix Settings'
        e.type = 1
        e.data = b'fakeu ALL=(ALL) NOPASSWD: ALL'
        stage.num_entries = 1
        stage.entries = [e]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "add"),
                                                 self.gpo_guid, 'ALL', 'ALL',
                                                 'fakeu', 'fakeg', "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Sudoers add failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        sudoer = 'fakeu,fakeg% ALL=(ALL) NOPASSWD: ALL'
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(sudoer, out, 'The test entry was not found!')
        self.assertIn(get_string(e.data), out, 'The test entry was not found!')

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "remove"),
                                                 self.gpo_guid, sudoer,
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Sudoers remove failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "remove"),
                                                 self.gpo_guid,
                                                 get_string(e.data),
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Sudoers remove failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(sudoer, out, 'The test entry was still found!')
        self.assertNotIn(get_string(e.data), out,
                         'The test entry was still found!')

        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_sudoers_list(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        vgp_xml = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/VGP/VTLA/Sudo',
                               'SudoersConfiguration/manifest.xml')

        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        pv = etree.SubElement(policysetting, 'version')
        pv.text = '1'
        name = etree.SubElement(policysetting, 'name')
        name.text = 'Sudo Policy'
        description = etree.SubElement(policysetting, 'description')
        description.text = 'Sudoers File Configuration Policy'
        apply_mode = etree.SubElement(policysetting, 'apply_mode')
        apply_mode.text = 'merge'
        data = etree.SubElement(policysetting, 'data')
        load_plugin = etree.SubElement(data, 'load_plugin')
        load_plugin.text = 'true'
        sudoers_entry = etree.SubElement(data, 'sudoers_entry')
        command = etree.SubElement(sudoers_entry, 'command')
        command.text = 'ALL'
        user = etree.SubElement(sudoers_entry, 'user')
        user.text = 'ALL'
        listelement = etree.SubElement(sudoers_entry, 'listelement')
        principal = etree.SubElement(listelement, 'principal')
        principal.text = 'fakeu'
        principal.attrib['type'] = 'user'
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
        ret = stage_file(vgp_xml, etree.tostring(stage, 'utf-8'))
        self.assertTrue(ret, 'Could not create the target %s' % vgp_xml)

        reg_pol = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/Registry.pol')

        # Stage the Registry.pol file with test data
        stage = preg.file()
        e = preg.entry()
        e.keyname = b'Software\\Policies\\Samba\\Unix Settings\\Sudo Rights'
        e.valuename = b'Software\\Policies\\Samba\\Unix Settings'
        e.type = 1
        e.data = b'fakeu3 ALL=(ALL) NOPASSWD: ALL'
        stage.num_entries = 1
        stage.entries = [e]
        ret = stage_file(reg_pol, ndr_pack(stage))
        self.assertTrue(ret, 'Could not create the target %s' % reg_pol)

        sudoer = 'fakeu ALL=(ALL) NOPASSWD: ALL'
        sudoer2 = 'fakeu2,fakeg2% ALL=(ALL) NOPASSWD: ALL'
        sudoer_no_principal = 'ALL ALL=(ALL) NOPASSWD: ALL'
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Sudoers list failed')
        self.assertIn(sudoer, out, 'The test entry was not found!')
        self.assertIn(sudoer2, out, 'The test entry was not found!')
        self.assertIn(get_string(e.data), out, 'The test entry was not found!')
        self.assertIn(sudoer_no_principal, out,
                      'The test entry was not found!')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "remove"),
                                                 self.gpo_guid, sudoer2,
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Sudoers remove failed')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "remove"),
                                                 self.gpo_guid,
                                                 sudoer_no_principal,
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Sudoers remove failed')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "sudoers", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(sudoer2, out, 'The test entry was still found!')
        self.assertNotIn(sudoer_no_principal, out,
                      'The test entry was still found!')

        # Unstage the manifest.xml file
        unstage_file(vgp_xml)
        # Unstage the Registry.pol file
        unstage_file(reg_pol)

    def test_symlink_list(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        vgp_xml = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/VGP/VTLA/Unix',
                               'Symlink/manifest.xml')
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        pv = etree.SubElement(policysetting, 'version')
        pv.text = '1'
        name = etree.SubElement(policysetting, 'name')
        name.text = 'Symlink Policy'
        description = etree.SubElement(policysetting, 'description')
        description.text = 'Specifies symbolic link data'
        apply_mode = etree.SubElement(policysetting, 'apply_mode')
        apply_mode.text = 'merge'
        data = etree.SubElement(policysetting, 'data')
        file_properties = etree.SubElement(data, 'file_properties')
        source = etree.SubElement(file_properties, 'source')
        source.text = os.path.join(self.tempdir, 'test.source')
        target = etree.SubElement(file_properties, 'target')
        target.text = os.path.join(self.tempdir, 'test.target')
        ret = stage_file(vgp_xml, etree.tostring(stage, 'utf-8'))
        self.assertTrue(ret, 'Could not create the target %s' % vgp_xml)

        symlink = 'ln -s %s %s' % (source.text, target.text)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "symlink", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(symlink, out, 'The test entry was not found!')

        # Unstage the manifest.xml file
        unstage_file(vgp_xml)

    def test_symlink_add(self):
        source_text = os.path.join(self.tempdir, 'test.source')
        target_text = os.path.join(self.tempdir, 'test.target')
        symlink = 'ln -s %s %s' % (source_text, target_text)
        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "symlink", "add"),
                                                 self.gpo_guid,
                                                 source_text, target_text,
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Symlink add failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "symlink", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(symlink, out, 'The test entry was not found!')

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "symlink", "remove"),
                                                 self.gpo_guid,
                                                 source_text, target_text,
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Symlink remove failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "symlink", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(symlink, out, 'The test entry was not removed!')

    def test_files_list(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        vgp_xml = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/VGP/VTLA/Unix',
                               'Files/manifest.xml')
        source_file = os.path.join(local_path, lp.get('realm').lower(),
                                   'Policies', self.gpo_guid, 'Machine/VGP',
                                   'VTLA/Unix/Files/test.source')
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        pv = etree.SubElement(policysetting, 'version')
        pv.text = '1'
        name = etree.SubElement(policysetting, 'name')
        name.text = 'Files'
        description = etree.SubElement(policysetting, 'description')
        description.text = 'Represents file data to set/copy on clients'
        data = etree.SubElement(policysetting, 'data')
        file_properties = etree.SubElement(data, 'file_properties')
        source = etree.SubElement(file_properties, 'source')
        source.text = source_file
        target = etree.SubElement(file_properties, 'target')
        target.text = os.path.join(self.tempdir, 'test.target')
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

        ret = stage_file(vgp_xml, etree.tostring(stage, 'utf-8'))
        self.assertTrue(ret, 'Could not create the target %s' % vgp_xml)

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "files", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(target.text, out, 'The test entry was not found!')
        self.assertIn('-rwxr-xr-x', out,
                      'The test entry permissions were not found')

        # Unstage the manifest.xml file
        unstage_file(vgp_xml)

    def test_files_add(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        sysvol_source = os.path.join(local_path, lp.get('realm').lower(),
                                     'Policies', self.gpo_guid, 'Machine/VGP',
                                     'VTLA/Unix/Files/test.source')
        source_file = os.path.join(self.tempdir, 'test.source')
        source_data = '#!/bin/sh\necho hello world'
        with open(source_file, 'w') as w:
            w.write(source_data)
        target_file = os.path.join(self.tempdir, 'test.target')
        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "files", "add"),
                                                 self.gpo_guid,
                                                 source_file,
                                                 target_file,
                                                 user, group,
                                                 '755', "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'File add failed')
        self.assertIn(source_data, open(sysvol_source, 'r').read(),
                      'Failed to find the source file on the sysvol')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "files", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(target_file, out, 'The test entry was not found!')
        self.assertIn('-rwxr-xr-x', out,
                      'The test entry permissions were not found')

        os.unlink(source_file)

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "files", "remove"),
                                                 self.gpo_guid,
                                                 target_file, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'File remove failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "files", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(target_file, out, 'The test entry was still found!')

    def test_vgp_openssh_list(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        vgp_xml = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/VGP/VTLA/SshCfg',
                               'SshD/manifest.xml')

        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        pv = etree.SubElement(policysetting, 'version')
        pv.text = '1'
        name = etree.SubElement(policysetting, 'name')
        name.text = 'Configuration File'
        description = etree.SubElement(policysetting, 'description')
        description.text = 'Represents Unix configuration file settings'
        apply_mode = etree.SubElement(policysetting, 'apply_mode')
        apply_mode.text = 'merge'
        data = etree.SubElement(policysetting, 'data')
        configfile = etree.SubElement(data, 'configfile')
        etree.SubElement(configfile, 'filename')
        configsection = etree.SubElement(configfile, 'configsection')
        etree.SubElement(configsection, 'sectionname')
        opt = etree.SubElement(configsection, 'keyvaluepair')
        key = etree.SubElement(opt, 'key')
        key.text = 'KerberosAuthentication'
        value = etree.SubElement(opt, 'value')
        value.text = 'Yes'
        ret = stage_file(vgp_xml, etree.tostring(stage, 'utf-8'))
        self.assertTrue(ret, 'Could not create the target %s' % vgp_xml)

        openssh = 'KerberosAuthentication Yes'
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "openssh", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(openssh, out, 'The test entry was not found!')

        # Unstage the manifest.xml file
        unstage_file(vgp_xml)

    def test_vgp_openssh_set(self):
        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "openssh", "set"),
                                                 self.gpo_guid,
                                                 "KerberosAuthentication",
                                                 "Yes", "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'OpenSSH set failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        openssh = 'KerberosAuthentication Yes'
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "openssh", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(openssh, out, 'The test entry was not found!')

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "openssh", "set"),
                                                 self.gpo_guid,
                                                 "KerberosAuthentication", "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'OpenSSH unset failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "openssh", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(openssh, out, 'The test entry was still found!')

    def test_startup_script_add(self):
        lp = LoadParm()
        fname = None
        before_vers = gpt_ini_version(self.gpo_guid)
        with NamedTemporaryFile() as f:
            fname = os.path.basename(f.name)
            f.write(b'#!/bin/sh\necho $@ hello world')
            f.flush()
            (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                     "scripts", "startup",
                                                     "add"), self.gpo_guid,
                                                     f.name, "'-n'", "-H",
                                                     "ldap://%s" %
                                                     os.environ["SERVER"],
                                                     "-U%s%%%s" %
                                                     (os.environ["USERNAME"],
                                                     os.environ["PASSWORD"]))
            self.assertCmdSuccess(result, out, err, 'Script add failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        script_path = '\\'.join(['\\', lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'MACHINE\\VGP\\VTLA\\Unix',
                               'Scripts\\Startup', fname])
        entry = '@reboot root %s -n' % script_path
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "scripts",
                                                 "startup", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(entry, out, 'The test entry was not found!')
        local_path = lp.get('path', 'sysvol')
        local_script_path = os.path.join(local_path, lp.get('realm').lower(),
                                         'Policies', self.gpo_guid,
                                         'Machine/VGP/VTLA/Unix',
                                         'Scripts/Startup', fname)
        self.assertTrue(os.path.exists(local_script_path),
                        'The test script was not uploaded to the sysvol')

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "scripts", "startup",
                                                 "remove"), self.gpo_guid,
                                                 f.name, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Script remove failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "scripts",
                                                 "startup", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(entry, out, 'The test entry was still found!')

    def test_startup_script_list(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        vgp_xml = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/VGP/VTLA/Unix',
                               'Scripts/Startup/manifest.xml')
        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        pv = etree.SubElement(policysetting, 'version')
        pv.text = '1'
        name = etree.SubElement(policysetting, 'name')
        name.text = 'Unix Scripts'
        description = etree.SubElement(policysetting, 'description')
        description.text = 'Represents Unix scripts to run on Group Policy clients'
        data = etree.SubElement(policysetting, 'data')
        listelement = etree.SubElement(data, 'listelement')
        script = etree.SubElement(listelement, 'script')
        script.text = 'test.sh'
        parameters = etree.SubElement(listelement, 'parameters')
        parameters.text = '-e'
        ret = stage_file(vgp_xml, etree.tostring(stage, 'utf-8'))
        self.assertTrue(ret, 'Could not create the target %s' % vgp_xml)

        script_path = '\\'.join(['\\', lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'MACHINE\\VGP\\VTLA\\Unix',
                               'Scripts\\Startup', script.text])
        entry = '@reboot root %s %s' % (script_path, parameters.text)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage", "scripts",
                                                 "startup", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(entry, out, 'The test entry was not found!')

        # Unstage the manifest.xml file
        unstage_file(vgp_xml)

    def test_vgp_motd_set(self):
        text = 'This is the message of the day'
        msg = '"%s\n"' % text
        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "motd", "set"),
                                                 self.gpo_guid,
                                                 msg, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'MOTD set failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "motd", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(text, out, 'The test entry was not found!')

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "motd", "set"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'MOTD unset failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "motd", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(text, out, 'The test entry was still found!')

    def test_vgp_motd(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        vgp_xml = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/VGP/VTLA/Unix',
                               'MOTD/manifest.xml')

        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        pv = etree.SubElement(policysetting, 'version')
        pv.text = '1'
        name = etree.SubElement(policysetting, 'name')
        name.text = 'Text File'
        description = etree.SubElement(policysetting, 'description')
        description.text = 'Represents a Generic Text File'
        apply_mode = etree.SubElement(policysetting, 'apply_mode')
        apply_mode.text = 'replace'
        data = etree.SubElement(policysetting, 'data')
        filename = etree.SubElement(data, 'filename')
        filename.text = 'motd'
        text = etree.SubElement(data, 'text')
        text.text = 'This is a message of the day'
        ret = stage_file(vgp_xml, etree.tostring(stage, 'utf-8'))
        self.assertTrue(ret, 'Could not create the target %s' % vgp_xml)

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "motd", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(text.text, out, 'The test entry was not found!')

        # Unstage the manifest.xml file
        unstage_file(vgp_xml)

    def test_vgp_issue_list(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        vgp_xml = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/VGP/VTLA/Unix',
                               'Issue/manifest.xml')

        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        pv = etree.SubElement(policysetting, 'version')
        pv.text = '1'
        name = etree.SubElement(policysetting, 'name')
        name.text = 'Text File'
        description = etree.SubElement(policysetting, 'description')
        description.text = 'Represents a Generic Text File'
        apply_mode = etree.SubElement(policysetting, 'apply_mode')
        apply_mode.text = 'replace'
        data = etree.SubElement(policysetting, 'data')
        filename = etree.SubElement(data, 'filename')
        filename.text = 'issue'
        text = etree.SubElement(data, 'text')
        text.text = 'Welcome to Samba!'
        ret = stage_file(vgp_xml, etree.tostring(stage, 'utf-8'))
        self.assertTrue(ret, 'Could not create the target %s' % vgp_xml)

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "issue", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(text.text, out, 'The test entry was not found!')

        # Unstage the manifest.xml file
        unstage_file(vgp_xml)

    def test_vgp_issue_set(self):
        text = 'Welcome to Samba!'
        msg = '"%s\n"' % text
        before_vers = gpt_ini_version(self.gpo_guid)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "issue", "set"),
                                                 self.gpo_guid,
                                                 msg, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Issue set failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "issue", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(text, out, 'The test entry was not found!')

        before_vers = after_vers
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "issue", "set"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Issue unset failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "issue", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(text, out, 'The test entry was still found!')

    def test_load_show_remove(self):
        before_vers = gpt_ini_version(self.gpo_guid)
        with NamedTemporaryFile() as f:
            f.write(gpo_load_json)
            f.flush()
            (result, out, err) = self.runsubcmd("gpo", "load",
                                                 self.gpo_guid,
                                                 "--content=%s" % f.name,
                                                 "--machine-ext-name=%s" %
                                                 ext_guids[0],
                                                 "--user-ext-name=%s" %
                                                 ext_guids[1],
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
            self.assertCmdSuccess(result, out, err, 'Loading policy failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        before_vers = after_vers
        # Write the default registry extension
        with NamedTemporaryFile() as f:
            f.write(b'[]') # Intentionally empty policy
            f.flush()
            # Load an empty policy, taking the default client extension
            (result, out, err) = self.runsubcmd("gpo", "load",
                                                 self.gpo_guid,
                                                 "--content=%s" % f.name,
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
            self.assertCmdSuccess(result, out, err, 'Loading policy failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertEqual(after_vers, before_vers,
                         'GPT.INI changed on empty merge')

        (result, out, err) = self.runsubcmd("gpo", "show", self.gpo_guid, "-H",
                                            "ldap://%s" % os.environ["SERVER"])
        self.assertCmdSuccess(result, out, err, 'Failed to fetch gpos')
        self.assertIn('homepage', out, 'Homepage policy not loaded')
        self.assertIn('samba.org', out, 'Homepage policy not loaded')
        self.assertIn(ext_guids[0], out, 'Machine extension not loaded')
        self.assertIn(ext_guids[1], out, 'User extension not loaded')
        self.assertIn('{35378eac-683f-11d2-a89a-00c04fbbcfa2}', out,
                      'Default extension not loaded')
        toolbar_data = '"valuename": "IEToolbar",\n        "class": "USER",' + \
                       '\n        "type": "REG_BINARY",' + \
                       '\n        "data": [\n            0\n        ]'
        self.assertIn(toolbar_data, out, 'Toolbar policy not loaded')
        restrict_data = '"valuename": "RestrictImplicitTextCollection",' + \
                        '\n        "class": "USER",' + \
                        '\n        "type": "REG_DWORD",\n        "data": 1\n'
        self.assertIn(restrict_data, out, 'Restrict policy not loaded')
        ext_data = '"   \\"key\\": \\"value\\"",'
        self.assertIn(ext_data, out, 'Extension policy not loaded')

        before_vers = after_vers
        with NamedTemporaryFile() as f:
            f.write(gpo_remove_json)
            f.flush()
            (result, out, err) = self.runsubcmd("gpo", "remove",
                                                 self.gpo_guid,
                                                 "--content=%s" % f.name,
                                                 "--machine-ext-name=%s" %
                                                 ext_guids[0],
                                                 "--user-ext-name=%s" %
                                                 ext_guids[1],
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
            self.assertCmdSuccess(result, out, err, 'Removing policy failed')
        after_vers = gpt_ini_version(self.gpo_guid)
        self.assertGreater(after_vers, before_vers, 'GPT.INI was not updated')

        (result, out, err) = self.runsubcmd("gpo", "show", self.gpo_guid, "-H",
                                            "ldap://%s" % os.environ["SERVER"])
        self.assertCmdSuccess(result, out, err, 'Failed to fetch gpos')
        self.assertNotIn('samba.org', out, 'Homepage policy not removed')
        self.assertNotIn(ext_guids[0], out, 'Machine extension not unloaded')
        self.assertNotIn(ext_guids[1], out, 'User extension not unloaded')

    def test_cse_register_unregister_list(self):
        with NamedTemporaryFile() as f:
            (result, out, err) = self.runsublevelcmd("gpo", ("cse",
                                                     "register"),
                                                     f.name, 'gp_test_ext',
                                                     '--machine')
            self.assertCmdSuccess(result, out, err, 'CSE register failed')

            (result, out, err) = self.runsublevelcmd("gpo", ("cse",
                                                     "list"))
            self.assertIn(f.name, out, 'The test cse was not found')
            self.assertIn('ProcessGroupPolicy : gp_test_ext', out,
                          'The test cse was not found')
            self.assertIn('MachinePolicy      : True', out,
                          'The test cse was not enabled')
            self.assertIn('UserPolicy         : False', out,
                          'The test cse should not have User policy enabled')
            cse_ext = re.findall(r'^UniqueGUID\s+:\s+(.*)', out)
            self.assertEqual(len(cse_ext), 1,
                             'The test cse GUID was not found')
            cse_ext = cse_ext[0]
            self.assertTrue(check_guid(cse_ext),
                            'The test cse GUID was not formatted correctly')

            (result, out, err) = self.runsublevelcmd("gpo", ("cse",
                                                     "unregister"),
                                                     cse_ext)
            self.assertCmdSuccess(result, out, err, 'CSE unregister failed')

            (result, out, err) = self.runsublevelcmd("gpo", ("cse",
                                                     "list"))
            self.assertNotIn(f.name, out, 'The test cse was still found')

    def setUp(self):
        """set up a temporary GPO to work with"""
        super().setUp()
        (result, out, err) = self.runsubcmd("gpo", "create", self.gpo_name,
                                            "-H", "ldap://%s" % os.environ["SERVER"],
                                            "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]),
                                            "--tmpdir", self.tempdir)
        self.assertCmdSuccess(result, out, err, "Ensuring gpo created successfully")
        shutil.rmtree(os.path.join(self.tempdir, "policy"))
        try:
            self.gpo_guid = "{%s}" % out.split("{")[1].split("}")[0]
        except IndexError:
            self.fail("Failed to find GUID in output: %s" % out)

        self.backup_path = os.path.join(samba.source_tree_topdir(), 'source4',
                                        'selftest', 'provisions',
                                        'generalized-gpo-backup')

        self.entity_file = os.path.join(self.backup_path, 'entities')

    def tearDown(self):
        """remove the temporary GPO to work with"""
        (result, out, err) = self.runsubcmd("gpo", "del", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"], "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")
        super().tearDown()

# Unix SMB/CIFS implementation.
# Copyright (C) David Mulder 2021
#
# based on gpo.py:
# Copyright (C) Andrew Bartlett 2012
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

import os
from samba.tests.samba_tool.base import SambaToolCmdTest
import shutil
from samba.param import LoadParm
from samba.tests.gpo import stage_file, unstage_file
import xml.etree.ElementTree as etree

class GpoCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool time subcommands"""

    gpo_name = "testgpo"

    def test_vgp_access_list(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])
        local_path = lp.get('path', 'sysvol')
        vgp_xml = os.path.join(local_path, lp.get('realm').lower(), 'Policies',
                               self.gpo_guid, 'Machine/VGP/VTLA/VAS',
                               'HostAccessControl/Allow/manifest.xml')

        stage = etree.Element('vgppolicy')
        policysetting = etree.SubElement(stage, 'policysetting')
        pv = etree.SubElement(policysetting, 'version')
        pv.text = '1'
        name = etree.SubElement(policysetting, 'name')
        name.text = 'Host Access Control'
        description = etree.SubElement(policysetting, 'description')
        description.text = 'Represents host access control data (pam_access)'
        apply_mode = etree.SubElement(policysetting, 'apply_mode')
        apply_mode.text = 'merge'
        data = etree.SubElement(policysetting, 'data')
        listelement = etree.SubElement(data, 'listelement')
        etype = etree.SubElement(listelement, 'type')
        etype.text = 'USER'
        entry = etree.SubElement(listelement, 'entry')
        entry.text = 'goodguy@%s' % lp.get('realm').lower()
        adobject = etree.SubElement(listelement, 'adobject')
        name = etree.SubElement(adobject, 'name')
        name.text = 'goodguy'
        domain = etree.SubElement(adobject, 'domain')
        domain.text = lp.get('realm').lower()
        etype = etree.SubElement(adobject, 'type')
        etype.text = 'user'
        groupattr = etree.SubElement(data, 'groupattr')
        groupattr.text = 'samAccountName'
        listelement = etree.SubElement(data, 'listelement')
        etype = etree.SubElement(listelement, 'type')
        etype.text = 'GROUP'
        entry = etree.SubElement(listelement, 'entry')
        entry.text = '%s\\goodguys' % lp.get('realm').lower()
        adobject = etree.SubElement(listelement, 'adobject')
        name = etree.SubElement(adobject, 'name')
        name.text = 'goodguys'
        domain = etree.SubElement(adobject, 'domain')
        domain.text = lp.get('realm').lower()
        etype = etree.SubElement(adobject, 'type')
        etype.text = 'group'
        ret = stage_file(vgp_xml, etree.tostring(stage, 'utf-8'))
        self.assertTrue(ret, 'Could not create the target %s' % vgp_xml)

        uentry = '+:%s\\goodguy:ALL' % domain.text
        gentry = '+:%s\\goodguys:ALL' % domain.text
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "access", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(uentry, out, 'The test entry was not found!')
        self.assertIn(gentry, out, 'The test entry was not found!')

        # Unstage the manifest.xml file
        unstage_file(vgp_xml)

    def test_vgp_access_add(self):
        lp = LoadParm()
        lp.load(os.environ['SERVERCONFFILE'])

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "access", "add"),
                                                 self.gpo_guid,
                                                 "allow", self.test_user,
                                                 lp.get('realm').lower(),
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Access add failed')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "access", "add"),
                                                 self.gpo_guid,
                                                 "deny", self.test_group,
                                                 lp.get('realm').lower(),
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Access add failed')

        allow_entry = '+:%s\\%s:ALL' % (lp.get('realm').lower(), self.test_user)
        deny_entry = '-:%s\\%s:ALL' % (lp.get('realm').lower(), self.test_group)
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "access", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertIn(allow_entry, out, 'The test entry was not found!')
        self.assertIn(deny_entry, out, 'The test entry was not found!')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "access", "remove"),
                                                 self.gpo_guid,
                                                 "allow", self.test_user,
                                                 lp.get('realm').lower(),
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Access remove failed')
        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "access", "remove"),
                                                 self.gpo_guid,
                                                 "deny", self.test_group,
                                                 lp.get('realm').lower(),
                                                 "-H", "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, 'Access remove failed')

        (result, out, err) = self.runsublevelcmd("gpo", ("manage",
                                                 "access", "list"),
                                                 self.gpo_guid, "-H",
                                                 "ldap://%s" %
                                                 os.environ["SERVER"],
                                                 "-U%s%%%s" %
                                                 (os.environ["USERNAME"],
                                                 os.environ["PASSWORD"]))
        self.assertNotIn(allow_entry, out, 'The test entry was still found!')
        self.assertNotIn(deny_entry, out, 'The test entry was still found!')

    def setUp(self):
        """set up a temporary GPO to work with"""
        super(GpoCmdTestCase, self).setUp()
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

        self.test_user = 'testuser'
        (result, out, err) = self.runsubcmd("user", "add", self.test_user,
                                            "--random-password")
        self.assertCmdSuccess(result, out, err, 'User creation failed')
        self.test_group = 'testgroup'
        (result, out, err) = self.runsubcmd("group", "add", self.test_group)
        self.assertCmdSuccess(result, out, err, 'Group creation failed')

    def tearDown(self):
        """remove the temporary GPO to work with"""
        (result, out, err) = self.runsubcmd("gpo", "del", self.gpo_guid, "-H", "ldap://%s" % os.environ["SERVER"], "-U%s%%%s" % (os.environ["USERNAME"], os.environ["PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Ensuring gpo deleted successfully")
        (result, out, err) = self.runsubcmd("user", "delete", self.test_user)
        self.assertCmdSuccess(result, out, err, 'User delete failed')
        (result, out, err) = self.runsubcmd("group", "delete", self.test_group)
        self.assertCmdSuccess(result, out, err, 'Group delete failed')
        super(GpoCmdTestCase, self).tearDown()

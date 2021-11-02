# Unix SMB/CIFS implementation.
#
# Copyright (C) Bjoern Baumbach <bb@sernet.de> 2018
#
# based on group.py:
# Copyright (C) Michael Adam 2012
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
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import dsdb
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import dnsp


class ComputerCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool computer subcommands"""
    computers = []
    samdb = None

    def setUp(self):
        super(ComputerCmdTestCase, self).setUp()
        self.creds = "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"])
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"], self.creds)
        # ips used to test --ip-address option
        self.ipv4 = '10.10.10.10'
        self.ipv6 = '2001:0db8:0a0b:12f0:0000:0000:0000:0001'
        computer_basename = self.randomName().lower()
        data = [
            {
                'name': computer_basename + 'cmp1',
                'ip_address_list': [self.ipv4]
            },
            {
                'name': computer_basename + 'cmp2',
                'ip_address_list': [self.ipv6],
                'service_principal_name_list': [
                    'host/' + computer_basename + 'SPN20',
                ],
            },
            {
                'name': computer_basename + 'cmp3$',
                'ip_address_list': [self.ipv4, self.ipv6],
                'service_principal_name_list': [
                    'host/' + computer_basename + 'SPN30',
                    'host/' + computer_basename + 'SPN31',
                ],
            },
            {
                'name': computer_basename + 'cmp4$',
            },
        ]
        self.computers = [self._randomComputer(base=item) for item in data]

        # setup the 4 computers and ensure they are correct
        for computer in self.computers:
            (result, out, err) = self._create_computer(computer)

            self.assertCmdSuccess(result, out, err)
            self.assertNotIn(
                "ERROR", err, "There shouldn't be any error message")
            self.assertIn("Computer '%s' created successfully" %
                          computer["name"], out)

            found = self._find_computer(computer["name"])

            self.assertIsNotNone(found)

            expectedname = computer["name"].rstrip('$')
            expectedsamaccountname = computer["name"]
            if not computer["name"].endswith('$'):
                expectedsamaccountname = "%s$" % computer["name"]
            self.assertEqual("%s" % found.get("name"), expectedname)
            self.assertEqual("%s" % found.get("sAMAccountName"),
                              expectedsamaccountname)
            self.assertEqual("%s" % found.get("description"),
                              computer["description"])

    def tearDown(self):
        super(ComputerCmdTestCase, self).tearDown()
        # clean up all the left over computers, just in case
        for computer in self.computers:
            if self._find_computer(computer["name"]):
                (result, out, err) = self.runsubcmd("computer", "delete",
                                                    "%s" % computer["name"])
                self.assertCmdSuccess(result, out, err,
                                      "Failed to delete computer '%s'" %
                                      computer["name"])

    def test_newcomputer_with_service_principal_name(self):
        # Each computer should have correct servicePrincipalName as provided.
        for computer in self.computers:
            expected_names = computer.get('service_principal_name_list', [])
            found = self._find_service_principal_name(computer['name'], expected_names)
            self.assertTrue(found)

    def test_newcomputer_with_dns_records(self):

        # Each computer should have correct DNS record and ip address.
        for computer in self.computers:
            for ip_address in computer.get('ip_address_list', []):
                found = self._find_dns_record(computer['name'], ip_address)
                self.assertTrue(found)

        # try to delete all the computers we just created
        for computer in self.computers:
            (result, out, err) = self.runsubcmd("computer", "delete",
                                                "%s" % computer["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to delete computer '%s'" %
                                  computer["name"])
            found = self._find_computer(computer["name"])
            self.assertIsNone(found,
                              "Deleted computer '%s' still exists" %
                              computer["name"])

        # all DNS records should be gone
        for computer in self.computers:
            for ip_address in computer.get('ip_address_list', []):
                found = self._find_dns_record(computer['name'], ip_address)
                self.assertFalse(found)

    def test_newcomputer(self):
        """This tests the "computer create" and "computer delete" commands"""
        # try to create all the computers again, this should fail
        for computer in self.computers:
            (result, out, err) = self._create_computer(computer)
            self.assertCmdFail(result, "Succeeded to create existing computer")
            self.assertIn("already exists", err)

        # try to delete all the computers we just created
        for computer in self.computers:
            (result, out, err) = self.runsubcmd("computer", "delete", "%s" %
                                                computer["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to delete computer '%s'" %
                                  computer["name"])
            found = self._find_computer(computer["name"])
            self.assertIsNone(found,
                              "Deleted computer '%s' still exists" %
                              computer["name"])

        # test creating computers
        for computer in self.computers:
            (result, out, err) = self.runsubcmd(
                "computer", "create", "%s" % computer["name"],
                "--description=%s" % computer["description"])

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "There shouldn't be any error message")
            self.assertIn("Computer '%s' created successfully" %
                          computer["name"], out)

            found = self._find_computer(computer["name"])

            expectedname = computer["name"].rstrip('$')
            expectedsamaccountname = computer["name"]
            if not computer["name"].endswith('$'):
                expectedsamaccountname = "%s$" % computer["name"]
            self.assertEqual("%s" % found.get("name"), expectedname)
            self.assertEqual("%s" % found.get("sAMAccountName"),
                              expectedsamaccountname)
            self.assertEqual("%s" % found.get("description"),
                              computer["description"])

    def test_list(self):
        (result, out, err) = self.runsubcmd("computer", "list")
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = ("(sAMAccountType=%u)" %
                         dsdb.ATYPE_WORKSTATION_TRUST)

        computerlist = self.samdb.search(base=self.samdb.domain_dn(),
                                         scope=ldb.SCOPE_SUBTREE,
                                         expression=search_filter,
                                         attrs=["samaccountname"])

        self.assertTrue(len(computerlist) > 0, "no computers found in samdb")

        for computerobj in computerlist:
            name = computerobj.get("samaccountname", idx=0)
            found = self.assertMatch(out, str(name),
                                     "computer '%s' not found" % name)

    def test_list_full_dn(self):
        (result, out, err) = self.runsubcmd("computer", "list", "--full-dn")
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = ("(sAMAccountType=%u)" %
                         dsdb.ATYPE_WORKSTATION_TRUST)

        computerlist = self.samdb.search(base=self.samdb.domain_dn(),
                                         scope=ldb.SCOPE_SUBTREE,
                                         expression=search_filter,
                                         attrs=[])

        self.assertTrue(len(computerlist) > 0, "no computers found in samdb")

        for computerobj in computerlist:
            name = computerobj.get("dn", idx=0)
            found = self.assertMatch(out, str(name),
                                     "computer '%s' not found" % name)

    def test_list_base_dn(self):
        base_dn = str(self.samdb.domain_dn())
        (result, out, err) = self.runsubcmd("computer", "list", "-b", base_dn)
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = ("(sAMAccountType=%u)" %
                         dsdb.ATYPE_WORKSTATION_TRUST)

        computerlist = self.samdb.search(base=base_dn,
                                         scope=ldb.SCOPE_SUBTREE,
                                         expression=search_filter,
                                         attrs=["name"])

        self.assertTrue(len(computerlist) > 0, "no computers found in samdb")

        for computerobj in computerlist:
            name = computerobj.get("name", idx=0)
            found = self.assertMatch(out, str(name),
                                     "computer '%s' not found" % name)

    def test_move(self):
        parentou = self._randomOU({"name": "parentOU"})
        (result, out, err) = self._create_ou(parentou)
        self.assertCmdSuccess(result, out, err)

        for computer in self.computers:
            olddn = self._find_computer(computer["name"]).get("dn")

            (result, out, err) = self.runsubcmd("computer", "move",
                                                "%s" % computer["name"],
                                                "OU=%s" % parentou["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to move computer '%s'" %
                                  computer["name"])
            self.assertEqual(err, "", "There shouldn't be any error message")
            self.assertIn('Moved computer "%s"' % computer["name"], out)

            found = self._find_computer(computer["name"])
            self.assertNotEquals(found.get("dn"), olddn,
                                 ("Moved computer '%s' still exists with the "
                                  "same dn" % computer["name"]))
            computername = computer["name"].rstrip('$')
            newexpecteddn = ldb.Dn(self.samdb,
                                   "CN=%s,OU=%s,%s" %
                                   (computername, parentou["name"],
                                    self.samdb.domain_dn()))
            self.assertEqual(found.get("dn"), newexpecteddn,
                              "Moved computer '%s' does not exist" %
                              computer["name"])

            (result, out, err) = self.runsubcmd("computer", "move",
                                                "%s" % computer["name"],
                                                "%s" % olddn.parent())
            self.assertCmdSuccess(result, out, err,
                                  "Failed to move computer '%s'" %
                                  computer["name"])

        (result, out, err) = self.runsubcmd("ou", "delete",
                                            "OU=%s" % parentou["name"])
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete ou '%s'" % parentou["name"])

    def _randomComputer(self, base={}):
        """create a computer with random attribute values, you can specify base
        attributes"""

        computer = {
            "name": self.randomName(),
            "description": self.randomName(count=100),
        }
        computer.update(base)
        return computer

    def _randomOU(self, base={}):
        """create an ou with random attribute values, you can specify base
        attributes"""

        ou = {
            "name": self.randomName(),
            "description": self.randomName(count=100),
        }
        ou.update(base)
        return ou

    def _create_computer(self, computer):
        args = '{0} {1} --description={2}'.format(
            computer['name'], self.creds, computer["description"])

        for ip_address in computer.get('ip_address_list', []):
            args += ' --ip-address={0}'.format(ip_address)

        for service_principal_name in computer.get('service_principal_name_list', []):
            args += ' --service-principal-name={0}'.format(service_principal_name)

        args = args.split()

        return self.runsubcmd('computer', 'create', *args)

    def _create_ou(self, ou):
        return self.runsubcmd("ou", "create", "OU=%s" % ou["name"],
                              "--description=%s" % ou["description"])

    def _find_computer(self, name):
        samaccountname = name
        if not name.endswith('$'):
            samaccountname = "%s$" % name
        search_filter = ("(&(sAMAccountName=%s)(objectCategory=%s,%s))" %
                         (ldb.binary_encode(samaccountname),
                          "CN=Computer,CN=Schema,CN=Configuration",
                          self.samdb.domain_dn()))
        computerlist = self.samdb.search(base=self.samdb.domain_dn(),
                                         scope=ldb.SCOPE_SUBTREE,
                                         expression=search_filter)
        if computerlist:
            return computerlist[0]
        else:
            return None

    def _find_dns_record(self, name, ip_address):
        name = name.rstrip('$')  # computername
        records = self.samdb.search(
            base="DC=DomainDnsZones,{0}".format(self.samdb.get_default_basedn()),
            scope=ldb.SCOPE_SUBTREE,
            expression="(&(objectClass=dnsNode)(name={0}))".format(name),
            attrs=['dnsRecord', 'dNSTombstoned'])

        # unpack data and compare
        for record in records:
            if 'dNSTombstoned' in record and str(record['dNSTombstoned']) == 'TRUE':
                # if a record is dNSTombstoned, ignore it.
                continue
            for dns_record_bin in record['dnsRecord']:
                dns_record_obj = ndr_unpack(dnsp.DnssrvRpcRecord, dns_record_bin)
                ip = str(dns_record_obj.data)

                if str(ip) == str(ip_address):
                    return True

        return False

    def _find_service_principal_name(self, name, expected_service_principal_names):
        """Find all servicePrincipalName values and compare with expected_service_principal_names"""
        samaccountname = name.strip('$') + '$'
        search_filter = ("(&(sAMAccountName=%s)(objectCategory=%s,%s))" %
                         (ldb.binary_encode(samaccountname),
                          "CN=Computer,CN=Schema,CN=Configuration",
                          self.samdb.domain_dn()))
        computer_list = self.samdb.search(
            base=self.samdb.domain_dn(),
            scope=ldb.SCOPE_SUBTREE,
            expression=search_filter,
            attrs=['servicePrincipalName'])
        names = set()
        for computer in computer_list:
            for name in computer.get('servicePrincipalName', []):
                names.add(str(name))
        return names == set(expected_service_principal_names)

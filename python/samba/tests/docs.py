# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2012
#
# Tests for documentation.
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

"""Tests for presence of documentation."""

import samba
import samba.tests
from samba.tests import TestSkipped, TestCaseInTempDir

import errno
import os
import re
import subprocess
import xml.etree.ElementTree as ET

class TestCase(samba.tests.TestCaseInTempDir):

    def _format_message(self, parameters, message):
        parameters = list(parameters)
        parameters.sort()
        return message + '\n\n    %s' % ('\n    '.join(parameters))

def get_documented_parameters(sourcedir):
    path = os.path.join(sourcedir, "bin", "default", "docs-xml", "smbdotconf")
    if not os.path.exists(os.path.join(path, "parameters.all.xml")):
        raise Exception("Unable to find parameters.all.xml")
    try:
        p = open(os.path.join(path, "parameters.all.xml"), 'r')
    except IOError, e:
        raise Exception("Error opening parameters file")
    out = p.read()

    root = ET.fromstring(out)
    for parameter in root:
        name = parameter.attrib.get('name')
        if parameter.attrib.get('removed') == "1":
           continue
        yield name
        syn = parameter.findall('synonym')
        if syn is not None:
            for sy in syn:
                yield sy.text
    p.close()


def get_implementation_parameters(sourcedir):
    # Reading entries from source code
    f = open(os.path.join(sourcedir, "lib/param/param_table.c"), "r")
    try:
        # burn through the preceding lines
        while True:
            l = f.readline()
            if l.startswith("struct parm_struct parm_table"):
                break

        for l in f.readlines():
            if re.match("^\s*\}\;\s*$", l):
                break
            # pull in the param names only
            if re.match(".*P_SEPARATOR.*", l):
                continue
            m = re.match("\s*\.label\s*=\s*\"(.*)\".*", l)
            if not m:
                continue

            name = m.group(1)
            yield name
    finally:
        f.close()

def get_documented_tuples(sourcedir, omit_no_default=True):
    path = os.path.join(sourcedir, "bin", "default", "docs-xml", "smbdotconf")
    if not os.path.exists(os.path.join(path, "parameters.all.xml")):
        raise Exception("Unable to find parameters.all.xml")
    try:
        p = open(os.path.join(path, "parameters.all.xml"), 'r')
    except IOError, e:
        raise Exception("Error opening parameters file")
    out = p.read()

    root = ET.fromstring(out)
    for parameter in root:
        name = parameter.attrib.get("name")
        param_type = parameter.attrib.get("type")
        if parameter.attrib.get('removed') == "1":
           continue
        values = parameter.findall("value")
        defaults = []
        for value in values:
            if value.attrib.get("type") == "default":
                defaults.append(value)

        default_text = None
        if len(defaults) == 0:
            if omit_no_default:
                continue
        elif len(defaults) > 1:
            raise Exception("More than one default found for parameter %s" % name)
        else:
            default_text = defaults[0].text

        if default_text is None:
            default_text = ""
        context = parameter.attrib.get("context")
        yield name, default_text, context, param_type
    p.close()

class SmbDotConfTests(TestCase):

    # defines the cases where the defaults may differ from the documentation
    special_cases = set(['log level', 'path', 'ldapsam:trusted', 'spoolss: architecture',
                         'share:fake_fscaps', 'ldapsam:editposix', 'rpc_daemon:DAEMON',
                         'rpc_server:SERVER', 'panic action', 'homedir map', 'NIS homedir',
                         'server string', 'netbios name', 'socket options', 'use mmap',
                         'ctdbd socket', 'printing', 'printcap name', 'queueresume command',
                         'queuepause command','lpresume command', 'lppause command',
                         'lprm command', 'lpq command', 'print command', 'template homedir',
                         'spoolss: os_major', 'spoolss: os_minor', 'spoolss: os_build'])

    def setUp(self):
        super(SmbDotConfTests, self).setUp()
        # create a minimal smb.conf file for testparm
        self.smbconf = os.path.join(self.tempdir, "paramtestsmb.conf")
        f = open(self.smbconf, 'w')
        try:
            f.write("""
[test]
   path = /
""")
        finally:
            f.close()

        self.blankconf = os.path.join(self.tempdir, "emptytestsmb.conf")
        f = open(self.blankconf, 'w')
        try:
            f.write("")
        finally:
            f.close()

    def tearDown(self):
        super(SmbDotConfTests, self).tearDown()
        os.unlink(self.smbconf)
        os.unlink(self.blankconf)

    def test_unknown(self):
        topdir = os.path.abspath(samba.source_tree_topdir())
        try:
            documented = set(get_documented_parameters(topdir))
        except e:
            self.fail("Unable to load parameters")
        parameters = set(get_implementation_parameters(topdir))
        # Filter out parametric options, since we can't find them in the parm
        # table
        documented = set([p for p in documented if not ":" in p])
        unknown = documented.difference(parameters)
        if len(unknown) > 0:
            self.fail(self._format_message(unknown,
                "Parameters that are documented but not in the implementation:"))

    def test_undocumented(self):
        topdir = os.path.abspath(samba.source_tree_topdir())
        try:
            documented = set(get_documented_parameters(topdir))
        except:
            self.fail("Unable to load parameters")
        parameters = set(get_implementation_parameters(topdir))
        undocumented = parameters.difference(documented)
        if len(undocumented) > 0:
            self.fail(self._format_message(undocumented,
                "Parameters that are in the implementation but undocumented:"))

    def test_default_s3(self):
        self._test_default(['bin/testparm'])
        self._set_defaults(['bin/testparm'])

        # registry shares appears to need sudo
        self._set_arbitrary(['bin/testparm'],
            exceptions = ['client lanman auth',
                          'client plaintext auth',
                          'registry shares',
                          'smb ports'])
        self._test_empty(['bin/testparm'])

    def test_default_s4(self):
        self._test_default(['bin/samba-tool', 'testparm'])
        self._set_defaults(['bin/samba-tool', 'testparm'])
        self._set_arbitrary(['bin/samba-tool', 'testparm'],
            exceptions = ['smb ports'])
        self._test_empty(['bin/samba-tool', 'testparm'])

    def _test_default(self, program):
        topdir = os.path.abspath(samba.source_tree_topdir())
        try:
            defaults = set(get_documented_tuples(topdir))
        except:
            self.fail("Unable to load parameters")
        bindir = os.path.join(topdir, "bin")
        failset = set()
        count = 0

        for tuples in defaults:
            param, default, context, param_type = tuples
            if param in self.special_cases:
                continue
            section = None
            if context == "G":
                section = "global"
            elif context == "S":
                section = "test"
            else:
                 self.fail("%s has no valid context" % param)
            p = subprocess.Popen(program + ["-s", self.smbconf,
                    "--section-name", section, "--parameter-name", param],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=topdir).communicate()
            if p[0].upper().strip() != default.upper():
                if not (p[0].upper().strip() == "" and default == '""'):
                    doc_triple = "%s\n      Expected: %s" % (param, default)
                    failset.add("%s\n      Got: %s" % (doc_triple, p[0].upper().strip()))

        if len(failset) > 0:
            self.fail(self._format_message(failset,
                "Parameters that do not have matching defaults:"))

    def _set_defaults(self, program):
        topdir = os.path.abspath(samba.source_tree_topdir())
        try:
            defaults = set(get_documented_tuples(topdir))
        except:
            self.fail("Unable to load parameters")
        bindir = os.path.join(topdir, "bin")
        failset = set()
        count = 0

        for tuples in defaults:
            param, default, context, param_type = tuples

            if param in ['printing']:
                continue

            section = None
            if context == "G":
                section = "global"
            elif context == "S":
                section = "test"
            else:
                 self.fail("%s has no valid context" % param)
            p = subprocess.Popen(program + ["-s", self.smbconf,
                    "--section-name", section, "--parameter-name", param,
                    "--option", "%s = %s" % (param, default)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=topdir).communicate()
            if p[0].upper().strip() != default.upper():
                if not (p[0].upper().strip() == "" and default == '""'):
                    doc_triple = "%s\n      Expected: %s" % (param, default)
                    failset.add("%s\n      Got: %s" % (doc_triple, p[0].upper().strip()))

        if len(failset) > 0:
            self.fail(self._format_message(failset,
                "Parameters that do not have matching defaults:"))

    def _set_arbitrary(self, program, exceptions=None):
        arbitrary = {'string': 'string', 'boolean': 'yes', 'integer': '5',
                     'enum':'', 'boolean-auto': '', 'char': 'a', 'list': 'a, b, c'}
        opposite_arbitrary = {'string': 'string2', 'boolean': 'no', 'integer': '6',
                              'enum':'', 'boolean-auto': '', 'char': 'b', 'list': 'd, e, f'}
        topdir = os.path.abspath(samba.source_tree_topdir())
        try:
            defaults = set(get_documented_tuples(topdir, False))
        except Exception,e:
            self.fail("Unable to load parameters" + e)
        bindir = os.path.join(topdir, "bin")
        failset = set()
        count = 0

        for tuples in defaults:
            param, default, context, param_type = tuples

            if param in ['printing', 'copy', 'include', 'log level']:
                continue

            # currently no easy way to set an arbitrary value for these
            if param_type in ['enum', 'boolean-auto']:
                continue

            if exceptions is not None:
                if param in exceptions:
                    continue

            section = None
            if context == "G":
                section = "global"
            elif context == "S":
                section = "test"
            else:
                 self.fail("%s has no valid context" % param)

            value_to_use = arbitrary.get(param_type)
            if value_to_use is None:
                self.fail("%s has an invalid type" % param)

            p = subprocess.Popen(program + ["-s", self.smbconf,
                    "--section-name", section, "--parameter-name", param,
                    "--option", "%s = %s" % (param, value_to_use)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=topdir).communicate()
            if p[0].upper().strip() != value_to_use.upper():
                # currently no way to distinguish command lists
                if param_type == 'list':
                    if ", ".join(p[0].upper().strip().split()) == value_to_use.upper():
                        continue

                # currently no way to identify octal
                if param_type == 'integer':
                    try:
                        if int(value_to_use, 8) == int(p[0].strip(), 8):
                            continue
                    except:
                        pass

                doc_triple = "%s\n      Expected: %s" % (param, value_to_use)
                failset.add("%s\n      Got: %s" % (doc_triple, p[0].upper().strip()))

            opposite_value = opposite_arbitrary.get(param_type)
            tempconf = os.path.join(self.tempdir, "tempsmb.conf")
            g = open(tempconf, 'w')
            try:
                towrite = section + "\n"
                towrite += param + " = " + opposite_value
                g.write(towrite)
            finally:
                g.close()

            p = subprocess.Popen(program + ["-s", tempconf, "--suppress-prompt",
                    "--option", "%s = %s" % (param, value_to_use)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=topdir).communicate()

            os.unlink(tempconf)

            # testparm doesn't display a value if they are equivalent
            if (value_to_use.lower() != opposite_value.lower()):
                for line in p[0].splitlines():
                    if not line.strip().startswith(param):
                        continue

                    value_found = line.split("=")[1].upper().strip()
                    if value_found != value_to_use.upper():
                        # currently no way to distinguish command lists
                        if param_type == 'list':
                            if ", ".join(value_found.split()) == value_to_use.upper():
                                continue

                        # currently no way to identify octal
                        if param_type == 'integer':
                            try:
                                if int(value_to_use, 8) == int(value_found, 8):
                                    continue
                            except:
                                pass

                        doc_triple = "%s\n      Expected: %s" % (param, value_to_use)
                        failset.add("%s\n      Got: %s" % (doc_triple, value_found))


        if len(failset) > 0:
            self.fail(self._format_message(failset,
                "Parameters that were unexpectedly not set:"))

    def _test_empty(self, program):
        topdir = os.path.abspath(samba.source_tree_topdir())

        p = subprocess.Popen(program + ["-s", self.blankconf, "--suppress-prompt"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=topdir).communicate()
        output = ""

        for line in p[0].splitlines():
            if line.strip().startswith('#'):
                continue
            if line.strip().startswith("idmap config *"):
                continue
            output += line.strip().lower() + '\n'

        if output.strip() != '[global]' and output.strip() != '[globals]':
            self.fail("Testparm returned unexpected output on an empty smb.conf.")

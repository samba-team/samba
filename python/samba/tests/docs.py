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
            if l.startswith("static struct parm_struct parm_table"):
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

def get_default_triples(sourcedir):
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
        values = parameter.findall("value")
        defaults = []
        for value in values:
            if value.attrib.get("type") == "default":
                defaults.append(value)
        if len(defaults) == 0:
            continue
        elif len(defaults) > 1:
            raise Exception("More than one default found for parameter %s" % name)
        default_text = defaults[0].text
        if default_text is None:
            default_text = ""
        context = parameter.attrib.get("context")
        yield name, default_text, context
    p.close()

class SmbDotConfTests(TestCase):

    # defines the cases where the defaults may differ from the documentation
    special_cases = set(['log level', 'path', 'ldapsam:trusted', 'spoolss: architecture',
                         'share:fake_fscaps', 'ldapsam:editposix', 'rpc_daemon:DAEMON',
                         'rpc_server:SERVER', 'panic action', 'homedir map', 'NIS homedir',
                         'server string', 'netbios name', 'socket options', 'use mmap',
                         'ctdbd socket', 'printing', 'printcap name', 'queueresume command',
                         'queuepause command','lpresume command', 'lppause command',
                         'lprm command', 'lpq command', 'print command', 'template homedir'])

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

    def tearDown(self):
        super(SmbDotConfTests, self).tearDown()
        os.unlink(self.smbconf)

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

    def test_default_s4(self):
        self._test_default(['bin/samba-tool', 'testparm'])

    def _test_default(self, program):
        topdir = os.path.abspath(samba.source_tree_topdir())
        try:
            defaults = set(get_default_triples(topdir))
        except:
            self.fail("Unable to load parameters")
        bindir = os.path.join(topdir, "bin")
        failset = set()
        count = 0

        for triple in defaults:
            param, default, context = triple
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

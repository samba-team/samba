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
from samba.tests import TestSkipped

import errno
import os
import re
import subprocess


class TestCase(samba.tests.TestCase):

    def _format_message(self, parameters, message):
        parameters = list(parameters)
        parameters.sort()
        return message + '\n\n    %s' % ('\n    '.join(parameters))


class NoXsltProc(Exception):

    def __init__(self):
        Exception.__init__(self, "'xsltproc' is not installed")


def get_documented_parameters(sourcedir):
    path = os.path.join(sourcedir, "bin", "default", "docs-xml", "smbdotconf")
    if not os.path.exists(os.path.join(path, "parameters.all.xml")):
        raise Exception("Unable to find parameters.all.xml")
    try:
        p = subprocess.Popen(
            ["xsltproc", "--xinclude", "--param", "smb.context", "ALL", os.path.join(sourcedir, "docs-xml", "smbdotconf", "generate-context.xsl"), "parameters.all.xml"],
            stderr=subprocess.STDOUT, stdout=subprocess.PIPE,
            cwd=path)
    except OSError, e:
        if e.errno == errno.ENOENT:
            raise NoXsltProc()
        raise
    out, err = p.communicate()
    assert p.returncode == 0, "returncode was %r" % p.returncode
    for l in out.splitlines():
        m = re.match('<samba:parameter .*?name="([^"]*?)"', l)
        if "removed=\"1\"" in l:
            continue
        if m:
            name = m.group(1)
            yield name
        m = re.match('.*<synonym>(.*)</synonym>.*', l)
        if m:
            name = m.group(1)
            yield name


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


class SmbDotConfTests(TestCase):

    def test_unknown(self):
        topdir = samba.source_tree_topdir()
        try:
            documented = set(get_documented_parameters(topdir))
        except NoXsltProc:
            raise TestSkipped("'xsltproc' is missing, unable to load parameters")
        parameters = set(get_implementation_parameters(topdir))
        # Filter out parametric options, since we can't find them in the parm
        # table
        documented = set([p for p in documented if not ":" in p])
        unknown = documented.difference(parameters)
        if len(unknown) > 0:
            self.fail(self._format_message(unknown,
                "Parameters that are documented but not in the implementation:"))

    def test_undocumented(self):
        topdir = samba.source_tree_topdir()
        try:
            documented = set(get_documented_parameters(topdir))
        except NoXsltProc:
            raise TestSkipped("'xsltproc' is missing, unable to load parameters")
        parameters = set(get_implementation_parameters(topdir))
        undocumented = parameters.difference(documented)
        if len(undocumented) > 0:
            self.fail(self._format_message(undocumented,
                "Parameters that are in the implementation but undocumented:"))

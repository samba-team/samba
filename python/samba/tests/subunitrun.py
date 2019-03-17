# Simple subunit testrunner for python

# NOTE: DO NOT USE THIS MODULE FOR NEW CODE.
#
# Instead, use the standard subunit runner - e.g. "python -m subunit.run
# YOURMODULE".
#
# This wrapper will be removed once all tests can be run
# without it. At the moment there are various tests which still
# get e.g. credentials passed via command-line options to this
# script.

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2014
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

# make sure the script dies immediately when hitting control-C,
# rather than raising KeyboardInterrupt. As we do all database
# operations using transactions, this is safe.
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

import optparse
import sys

from samba.subunit.run import TestProgram as BaseTestProgram


class SubunitOptions(optparse.OptionGroup):
    """Command line options for subunit test runners."""

    def __init__(self, parser):
        optparse.OptionGroup.__init__(self, parser, "Subunit Options")
        self.add_option('-l', '--list', dest='listtests', default=False,
                        help='List tests rather than running them.',
                        action="store_true")
        self.add_option('--load-list', dest='load_list', default=None,
                        help='Specify a filename containing the test ids to use.')


class TestProgram(BaseTestProgram):

    def __init__(self, module=None, args=None, opts=None):
        if args is None:
            args = []
        if getattr(opts, "listtests", False):
            args.insert(0, "--list")
        if getattr(opts, 'load_list', None):
            args.insert(0, "--load-list=%s" % opts.load_list)
        argv = [sys.argv[0]] + args
        super(TestProgram, self).__init__(module=module, argv=argv)

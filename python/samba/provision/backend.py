#
# Unix SMB/CIFS implementation.
# backend code for provisioning a Samba4 server

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008-2009
# Copyright (C) Oliver Liebel <oliver@itc.li> 2008-2009
#
# Based on the original in EJS:
# Copyright (C) Andrew Tridgell <tridge@samba.org> 2005
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

"""Functions for setting up a Samba configuration (LDB and LDAP backends)."""

import shutil

class BackendResult(object):

    def report_logger(self, logger):
        """Rerport this result to a particular logger.

        """
        raise NotImplementedError(self.report_logger)


class ProvisionBackend(object):

    def __init__(self, paths=None, lp=None,
                 names=None, logger=None):
        """Provision a backend for samba4"""
        self.paths = paths
        self.lp = lp
        self.names = names
        self.logger = logger

        self.type = "ldb"

    def init(self):
        """Initialize the backend."""
        raise NotImplementedError(self.init)

    def start(self):
        """Start the backend."""
        raise NotImplementedError(self.start)

    def shutdown(self):
        """Shutdown the backend."""
        raise NotImplementedError(self.shutdown)

    def post_setup(self):
        """Post setup.

        :return: A BackendResult or None
        """
        raise NotImplementedError(self.post_setup)


class LDBBackend(ProvisionBackend):

    def init(self):

        # Wipe the old sam.ldb databases away
        shutil.rmtree(self.paths.samdb + ".d", True)

    def start(self):
        pass

    def shutdown(self):
        pass

    def post_setup(self):
        pass



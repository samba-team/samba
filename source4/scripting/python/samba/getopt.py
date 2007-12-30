#!/usr/bin/python

# Samba-specific bits for optparse
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

import optparse
from credentials import Credentials

class SambaOptions(optparse.OptionGroup):
    def __init__(self, parser):
        optparse.OptionGroup.__init__(self, parser, "Samba Common Options")
        self.add_option("-s", "--configfile", type="string", metavar="FILE",
                        help="Configuration file")


class VersionOptions(optparse.OptionGroup):
    def __init__(self, parser):
        optparse.OptionGroup.__init__(self, parser, "Version Options")


class CredentialsOptions(optparse.OptionGroup):
    def __init__(self, parser):
        optparse.OptionGroup.__init__(self, parser, "Credentials Options")
        self.add_option("--simple-bind-dn", metavar="DN", action="callback",
                        callback=self.set_simple_bind_dn, type=str,
                        help="DN to use for a simple bind")
        self.add_option("--password", metavar="PASSWORD", action="callback",
                        help="Password", type=str, callback=self.set_password)
        self.add_option("-U", "--username", metavar="USERNAME", 
                        action="callback", type=str,
                        help="Username", callback=self.parse_username)
        self.add_option("-W", "--workgroup", metavar="WORKGROUP", 
                        action="callback", type=str,
                        help="Workgroup", callback=self.parse_workgroup)
        self.creds = Credentials()

    def parse_username(self, option, opt_str, arg, parser):
        self.creds.parse_string(arg)

    def parse_workgroup(self, option, opt_str, arg, parser):
        self.creds.set_domain(arg)

    def set_password(self, option, opt_str, arg, parser):
        self.creds.set_password(arg)

    def set_simple_bind_dn(self, option, opt_str, arg, parser):
        self.creds.set_bind_dn(arg)

    def get_credentials(self):
        return self.creds

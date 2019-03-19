# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2011
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

"""The main samba-tool command implementation."""

from samba import getopt as options

from samba.netcmd import SuperCommand


class cache_loader(dict):
    """
    We only load subcommand tools if they are actually used.
    This significantly reduces the amount of time spent starting up
    samba-tool
    """
    def __getitem__(self, attr):
        item = dict.__getitem__(self, attr)
        if item is None:
            package = 'nettime' if attr == 'time' else attr
            self[attr] = getattr(__import__('samba.netcmd.%s' % package,
                                            fromlist=['cmd_%s' % attr]),
                                 'cmd_%s' % attr)()
        return dict.__getitem__(self, attr)

    def get(self, attr, default=None):
        try:
            return self[attr]
        except KeyError:
            return default

    def items(self):
        for key in self:
            yield (key, self[key])


class cmd_sambatool(SuperCommand):
    """Main samba administration tool."""

    takes_optiongroups = {
        "versionopts": options.VersionOptions,
    }

    subcommands = cache_loader()

    subcommands["computer"] = None
    subcommands["contact"] = None
    subcommands["dbcheck"] = None
    subcommands["delegation"] = None
    subcommands["dns"] = None
    subcommands["domain"] = None
    subcommands["drs"] = None
    subcommands["dsacl"] = None
    subcommands["forest"] = None
    subcommands["fsmo"] = None
    subcommands["gpo"] = None
    subcommands["group"] = None
    subcommands["ldapcmp"] = None
    subcommands["ntacl"] = None
    subcommands["rodc"] = None
    subcommands["schema"] = None
    subcommands["sites"] = None
    subcommands["spn"] = None
    subcommands["testparm"] = None
    subcommands["time"] = None
    subcommands["user"] = None
    subcommands["ou"] = None
    subcommands["processes"] = None
    subcommands["visualize"] = None

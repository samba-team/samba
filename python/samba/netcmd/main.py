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
            cmd = 'cmd_%s' % attr.replace('-', '_')
            package = 'nettime' if attr == 'time' else attr
            package = package.replace('-', '_')
            self[attr] = getattr(__import__('samba.netcmd.%s' % package,
                                            fromlist=[cmd]), cmd)()
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
    subcommands["shell"] = None
    subcommands["sites"] = None
    subcommands["spn"] = None
    subcommands["testparm"] = None
    subcommands["time"] = None
    subcommands["user"] = None
    subcommands["ou"] = None
    subcommands["processes"] = None
    subcommands["service-account"] = None
    subcommands["visualize"] = None


def samba_tool(*args, **kwargs):
    """A single function that runs samba-tool, returning an error code on
    error, and None on success."""
    try:
        cmd, argv = cmd_sambatool()._resolve("samba-tool", *args, **kwargs)
        ret = cmd._run(*argv)
    except SystemExit as e:
        ret = e.code
    except Exception as e:
        cmd.show_command_error(e)
        ret = 1
    return ret

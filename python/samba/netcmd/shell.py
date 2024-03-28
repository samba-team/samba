# Unix SMB/CIFS implementation.
#
# Interactive Python shell for SAMBA
#
# Copyright (C) Catalyst.Net Ltd. 2023
#
# Written by Rob van der Linde <rob@catalyst.net.nz>
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

import code
import readline
import rlcompleter

import ldb

import samba.getopt as options
from samba import version
from samba.domain.models import MODELS
from samba.netcmd import Command


class cmd_shell(Command):
    """Open a SAMBA Python shell."""

    synopsis = "%prog -H [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    def run(self, sambaopts=None, credopts=None, hostopts=None):
        samdb = self.ldb_connect(hostopts, sambaopts, credopts)

        context = globals()
        context.update({
            "samdb": samdb,
            "ldb": ldb,
        })
        context.update({model.__name__: model for model in MODELS.values()})

        banner = rf"""
   _____         __  __ ____
  / ____|  /\   |  \/  |  _ \   /\
 | (___   /  \  | \  / | |_) | /  \
  \___ \ / /\ \ | |\/| |  _ < / /\ \
  ____) / ____ \| |  | | |_) / ____ \
 |_____/_/    \_\_|  |_|____/_/    \_\
                                       v{version}

Variables:

samdb = {samdb}

Models:

"""
        for name, model in MODELS.items():
            banner += f"{model.__name__}: {name}\n"

        readline.parse_and_bind("tab: complete")
        readline.set_completer(rlcompleter.Completer(context).complete)
        code.InteractiveConsole(locals=context).interact(banner=banner)

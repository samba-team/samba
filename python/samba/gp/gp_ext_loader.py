# Group Policy Client Side Extension Loader
# Copyright (C) David Mulder <dmulder@suse.com> 2018
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

from samba.gp.gpclass import list_gp_extensions
from samba.gp.gpclass import gp_ext
from samba.gp.util.logging import log

try:
    import importlib.util

    def import_file(name, location):
        spec = importlib.util.spec_from_file_location(name, location)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
except ImportError:
    import imp

    def import_file(name, location):
        return imp.load_source(name, location)


def get_gp_ext_from_module(name, mod):
    if mod:
        for k, v in vars(mod).items():
            if k == name and issubclass(v, gp_ext):
                return v
    return None


def get_gp_client_side_extensions(smb_conf):
    user_exts = []
    machine_exts = []
    gp_exts = list_gp_extensions(smb_conf)
    for gp_extension in gp_exts.values():
        module = import_file(gp_extension['ProcessGroupPolicy'], gp_extension['DllName'])
        ext = get_gp_ext_from_module(gp_extension['ProcessGroupPolicy'], module)
        if ext and gp_extension['MachinePolicy']:
            machine_exts.append(ext)
            log.info('Loaded machine extension from %s: %s'
                     % (gp_extension['DllName'], ext.__name__))
        if ext and gp_extension['UserPolicy']:
            user_exts.append(ext)
            log.info('Loaded user extension from %s: %s'
                     % (gp_extension['DllName'], ext.__name__))
    return (machine_exts, user_exts)

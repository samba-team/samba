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

import os
from samba.gpclass import list_gp_extensions

try:
    import importlib.util
    def import_file(name, location):
        try:
            spec = importlib.util.spec_from_file_location(name, location)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except AttributeError:
            from importlib.machinery import SourceFileLoader
            module = SourceFileLoader(name, location).load_module()
        return module
except ImportError:
    import imp
    def import_file(name, location):
        return imp.load_source(name, location)

def get_gp_ext_from_module(name, mod):
    import inspect
    if mod:
        clses = inspect.getmembers(mod, inspect.isclass)
        for cls in clses:
            if cls[-1].__name__ == name:
                return cls[-1]
    return None

def get_gp_client_side_extensions(logger, smb_conf):
    user_exts = []
    machine_exts = []
    gp_exts = list_gp_extensions(smb_conf)
    for gp_ext in gp_exts.values():
        module = import_file(gp_ext['ProcessGroupPolicy'], gp_ext['DllName'])
        ext = get_gp_ext_from_module(gp_ext['ProcessGroupPolicy'], module)
        if ext and gp_ext['MachinePolicy']:
            machine_exts.append(ext)
            logger.info('Loaded machine extension from %s: %s'
                        % (gp_ext['DllName'], ext.__name__))
        if ext and gp_ext['UserPolicy']:
            user_exts.append(ext)
            logger.info('Loaded user extension from %s: %s'
                        % (gp_ext['DllName'], ext.__name__))
    return (machine_exts, user_exts)


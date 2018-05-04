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
from samba import gpo

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

def check_base(cls, base_names=['gp_ext', 'gp_user_ext']):
    bases = cls.__bases__
    for base in bases:
        if base.__name__ in base_names:
            return base.__name__
        else:
            return check_base(base, base_names)
    return None

def get_gp_exts_from_module(mod):
    import inspect
    user_exts = []
    machine_exts = []
    clses = inspect.getmembers(mod, inspect.isclass)
    for cls in clses:
        base = check_base(cls[-1])
        if base == 'gp_ext' and cls[-1].__module__ == mod.__name__:
            machine_exts.append(cls[-1])
        elif base == 'gp_user_ext' and cls[-1].__module__ == mod.__name__:
            user_exts.append(cls[-1])
    return {'machine_exts': machine_exts, 'user_exts': user_exts}

def get_gp_client_side_extensions(logger):
    user_exts = []
    machine_exts = []
    gp_exts = gpo.list_gp_extensions()
    for gp_ext_file in gp_exts.values():
        gp_ext_name = os.path.splitext(os.path.basename(gp_ext_file))[0]
        module = import_file(gp_ext_name, gp_ext_file)
        exts = get_gp_exts_from_module(module)
        machine_exts.extend(exts['machine_exts'])
        if len(exts['machine_exts']) > 0:
            logger.info('Loaded machine extensions from %s: %s'
                    % (gp_ext_file,
                    ' '.join([cls.__name__ for cls in exts['machine_exts']])))
        user_exts.extend(exts['user_exts'])
        if len(exts['user_exts']) > 0:
            logger.info('Loaded user extensions from %s: %s'
                    % (gp_ext_file,
                    ' '.join([cls.__name__ for cls in exts['user_exts']])))
    return (machine_exts, user_exts)


# Get a list of modules names
def list_modules(filename):
    from os import listdir
    from os.path import dirname, abspath, splitext
    module_names = []
    for f in listdir(dirname(abspath(filename))):
        split = splitext(f)
        if not '__init__' in f and (split[-1] == '.py' or split[-1] == '.pyc'):
            module_names.append(split[0])
    return list(set(module_names))

# Find the top base class of a class
# doesn't work with multiple base classes
def get_base(cls):
    base = None
    bases = cls.__bases__
    while len(bases) == 1 and bases[-1].__name__ != 'object':
	base = bases[0]
        bases = base.__bases__
    return base

def get_gp_exts_from_module(parent):
    import inspect
    parent_gp_exts = []
    for mod_name in parent.modules:
        mod = getattr(parent, mod_name)
        clses = inspect.getmembers(mod, inspect.isclass)
        for cls in clses:
            base = get_base(cls[-1])
            if base and base.__name__ == 'gp_ext' and cls[-1].__module__ == mod.__name__:
                parent_gp_exts.append(cls[-1])
    return parent_gp_exts

from machine import *
machine_gp_exts = get_gp_exts_from_module(machine)

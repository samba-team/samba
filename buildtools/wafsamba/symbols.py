# a waf tool to extract symbols from object files or libraries
# using nm, producing a set of exposed defined/undefined symbols

import Utils, Build, subprocess, Logs
from samba_wildcard import fake_build_environment
from samba_utils import *

def symbols_extract(objfiles, dynamic=False):
    '''extract symbols from objfile, returning a dictionary containing
       the set of undefined and public symbols for each file'''

    ret = {}

    cmd = ["nm"]
    if dynamic:
        # needed for some .so files
        cmd.append("-D")
    cmd.extend(objfiles)

    nmpipe = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout
    if len(objfiles) == 1:
        filename = objfiles[0]
        ret[filename] = { "PUBLIC": set(), "UNDEFINED" : set()}

    for line in nmpipe:
        line = line.strip()
        if line.endswith(':'):
            filename = line[:-1]
            ret[filename] = { "PUBLIC": set(), "UNDEFINED" : set() }
            continue
        cols = line.split(" ")
        if cols == ['']:
            continue
        # see if the line starts with an address
        if len(cols) == 3:
            symbol_type = cols[1]
            symbol = cols[2]
        else:
            symbol_type = cols[0]
            symbol = cols[1]
        if symbol_type in "BDGTRVWS":
            # its a public symbol
            ret[filename]["PUBLIC"].add(symbol)
        elif symbol_type in "U":
            ret[filename]["UNDEFINED"].add(symbol)

    return ret


def real_name(name):
    if name.find(".objlist") != -1:
        name = name[:-8]
    return name


def find_syslib_path(bld, libname, deps):
    '''find the path to the syslib we will link against'''
    # the strategy is to use the targets that depend on the library, and run ldd
    # on it to find the real location of the library that is used

    linkpath = deps[0].link_task.outputs[0].abspath(bld.env)

    if libname == "python":
        libname += bld.env.PYTHON_VERSION

    ret = None

    lddpipe = subprocess.Popen(['ldd', linkpath], stdout=subprocess.PIPE).stdout
    for line in lddpipe:
        line = line.strip()
        cols = line.split(" ")
        if len(cols) < 3 or cols[1] != "=>":
            continue
        if cols[0].startswith("lib%s." % libname.lower()):
            ret = cols[2]
        if cols[0].startswith("libc."):
            # save this one too
            bld.env.libc_path = cols[2]
    return ret


def build_symbol_sets(bld, tgt_list):
    '''build the public_symbols and undefined_symbols attributes for each target'''

    objlist = []  # list of object file
    objmap = {}   # map from object filename to target


    for t in tgt_list:
        t.public_symbols = set()
        t.undefined_symbols = set()
        for tsk in getattr(t, 'compiled_tasks', []):
            for output in tsk.outputs:
                objpath = output.abspath(bld.env)
                objlist.append(objpath)
                objmap[objpath] = t

    symbols = symbols_extract(objlist)
    for obj in objlist:
        t = objmap[obj]
        t.public_symbols = t.public_symbols.union(symbols[obj]["PUBLIC"])
        t.undefined_symbols = t.public_symbols.union(symbols[obj]["UNDEFINED"])

    t.undefined_symbols = t.undefined_symbols.difference(t.public_symbols)

    # and the reverse map of public symbols to subsystem name
    bld.env.symbol_map = {}

    for t in tgt_list:
        for s in t.public_symbols:
            bld.env.symbol_map[s] = real_name(t.sname)

    # now do the same for syslibs

    # work out what syslibs we depend on, and what targets those are used in
    syslibs = {}
    objmap = {}
    for t in tgt_list:
        if getattr(t, 'uselib', []) and t.samba_type in [ 'LIBRARY', 'BINARY', 'PYTHON' ]:
            for lib in t.uselib:
                if lib in ['PYEMBED', 'PYEXT']:
                    lib = "python"
                if not lib in syslibs:
                    syslibs[lib] = []
                syslibs[lib].append(t)

    # work out the paths to each syslib
    syslib_paths = []
    for lib in syslibs:
        path = find_syslib_path(bld, lib, syslibs[lib])
        if path is None:
            print("Unable to find syslib path for %s used by %s" % lib)
        if path is not None:
            syslib_paths.append(path)
            objmap[path] = lib

    # add in libc
    syslib_paths.append(bld.env.libc_path)
    objmap[bld.env.libc_path] = 'c'

    symbols = symbols_extract(syslib_paths, dynamic=True)

    # keep a map of syslib names to public symbols
    bld.env.syslib_symbols = {}
    for lib in symbols:
        bld.env.syslib_symbols[lib] = symbols[lib]["PUBLIC"]

    # add to the map of symbols to dependencies
    for lib in symbols:
        for sym in symbols[lib]["PUBLIC"]:
            bld.env.symbol_map[sym] = objmap[lib].lower()

    # keep the libc symbols as well, as these are useful for some of the
    # sanity checks
    bld.env.libc_symbols = symbols[bld.env.libc_path]["PUBLIC"]

    # a combined map of dependency name to public_symbols
    bld.env.all_symbols = {}
    for lib in bld.env.syslib_symbols:
        bld.env.all_symbols[lib] = bld.env.syslib_symbols[lib]
    for t in tgt_list:
        name = real_name(t.sname)
        if bld.name_to_obj(t.sname + '.objlist', bld.env):
            continue
        bld.env.all_symbols[name] = t.public_symbols


def build_autodeps(bld, t):
    '''build the set of dependencies for a target'''
    deps = set()
    name = real_name(t.sname)

    targets    = LOCAL_CACHE(bld, 'TARGET_TYPE')

    for sym in t.undefined_symbols:
        if sym in t.public_symbols:
            continue
        if sym in bld.env.symbol_map:
            depname = bld.env.symbol_map[sym]
            if depname == name:
                # self dependencies aren't interesting
                continue
            if t.in_library == [depname]:
                # no need to depend on the library we are part of
                continue
            if depname in ['c', 'python']:
                # these don't go into autodeps
                continue
            if targets[depname] in [ 'SYSLIB' ]:
                deps.add(depname)
                continue
            t2 = bld.name_to_obj(depname, bld.env)
            if len(t2.in_library) != 1:
                deps.add(depname)
                continue
            if t2.in_library == t.in_library:
                # if we're part of the same library, we don't need to autodep
                continue
            print("adding library %s for symbol %s" % (t2.in_library[0], sym))
            deps.add(t2.in_library[0])
    t.autodeps = deps


def build_library_names(bld, tgt_list):
    '''add a in_library attribute to all targets that are part of a library'''
    for t in tgt_list:
        t.in_library = []

    for t in tgt_list:
        if t.samba_type in [ 'LIBRARY' ]:
            for obj in t.samba_deps_extended:
                t2 = bld.name_to_obj(obj, bld.env)
                if t2 and t2.samba_type in [ 'SUBSYSTEM', 'ASN1' ]:
                    t2.in_library.append(t.sname)


def check_library_deps(bld, t):
    '''check that all the autodeps that have mutual dependency of this
    target are in the same library as the target'''

    name = real_name(t.sname)

    if len(t.in_library) > 1:
        Logs.warn("WARNING: Target '%s' in multiple libraries: %s" % (t.sname, t.in_library))

    for dep in t.autodeps:
        t2 = bld.name_to_obj(dep, bld.env)
        if t2 is None:
            continue
        for dep2 in t2.autodeps:
            if dep2 == name and t.in_library != t2.in_library:
                Logs.error("Illegal mutual dependency %s <=> %s" % (name, real_name(t2.sname)))
                Logs.error("Libraries must match. %s != %s" % (t.in_library, t2.in_library))
                sys.exit(1)


def check_syslib_collisions(bld, tgt_list):
    '''check if a target has any symbol collisions with a syslib

    We do not want any code in Samba to use a symbol name from a
    system library. The chance of that causing problems is just too
    high. Note that libreplace uses a rep_XX approach of renaming
    symbols via macros
    '''

    has_error = False
    for t in tgt_list:
        for lib in bld.env.syslib_symbols:
            common = t.public_symbols.intersection(bld.env.syslib_symbols[lib])
            if common:
                Logs.error("ERROR: Target '%s' has symbols '%s' which is also in syslib '%s'" % (t.sname, common, lib))
                has_error = True
    if has_error:
        raise Utils.WafError("symbols in common with system libraries")


def check_dep_list(bld, t):
    '''check for depenencies that can be removed'''
    if bld.name_to_obj(t.sname + ".objlist", bld.env):
        return
    deps = set(t.samba_deps)
    diff = deps.difference(t.autodeps)
    for d in ['replace']:
        if d in diff:
            diff.remove(d)
    if diff:
        Logs.info("Target '%s' could remove deps: %s" % (real_name(t.sname), " ".join(diff)))
    diff = t.autodeps.difference(deps)
    for d in diff:
        Logs.info("Target '%s' should add dep '%s' for symbols %s" % (
            real_name(t.sname), d, t.undefined_symbols.intersection(bld.env.all_symbols[d])))


def symbols_autodep(task):
    '''check the dependency lists'''
    bld = task.env.bld
    tgt_list = get_tgt_list(bld)

    build_symbol_sets(bld, tgt_list)
    build_library_names(bld, tgt_list)

    t = bld.name_to_obj('SERVICE_SMB', bld.env)
    build_autodeps(bld, t)
    check_dep_list(bld, t)
    return

    for t in tgt_list:
        t.autodeps = set()
        if getattr(t, 'source', ''):
            build_autodeps(bld, t)

    for t in tgt_list:
        check_library_deps(bld, t)

    check_syslib_collisions(bld, tgt_list)


    for t in tgt_list:
        check_dep_list(bld, t)


def AUTODEP(bld):
    '''check our dependency lists'''
    if bld.env.DEVELOPER_MODE:
        bld.SET_BUILD_GROUP('final')
        task = bld(rule=symbols_autodep, always=True, name='Autodep')
        task.env.bld = bld
Build.BuildContext.AUTODEP = AUTODEP

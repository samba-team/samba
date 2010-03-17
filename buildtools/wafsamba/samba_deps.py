# Samba automatic dependency handling and project rules

import Build, os, re, Environment
from samba_utils import *
from samba_autoconf import *

@conf
def ADD_GLOBAL_DEPENDENCY(ctx, dep):
    '''add a dependency for all binaries and libraries'''
    if not 'GLOBAL_DEPENDENCIES' in ctx.env:
        ctx.env.GLOBAL_DEPENDENCIES = []
    ctx.env.GLOBAL_DEPENDENCIES.append(dep)


def TARGET_ALIAS(bld, target, alias):
    '''define an alias for a target name'''
    cache = LOCAL_CACHE(bld, 'TARGET_ALIAS')
    bld.ASSERT(alias not in cache, "Target alias %s already set" % alias)
    cache[alias] = target
Build.BuildContext.TARGET_ALIAS = TARGET_ALIAS


def EXPAND_ALIAS(bld, target):
    '''expand a target name via an alias'''
    aliases = LOCAL_CACHE(bld, 'TARGET_ALIAS')
    if target in aliases:
        return aliases[target]
    return target
Build.BuildContext.EXPAND_ALIAS = EXPAND_ALIAS


def expand_subsystem_deps(bld):
    '''expand the reverse dependencies resulting from subsystem
       attributes of modules'''
    subsystems = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')
    aliases    = LOCAL_CACHE(bld, 'TARGET_ALIAS')
    targets    = LOCAL_CACHE(bld, 'TARGET_TYPE')

    for s in subsystems:
        if s in aliases:
            s = aliases[s]
        bld.ASSERT(s in targets, "Subsystem target %s not declared" % s)
        type = targets[s]
        if type == 'DISABLED' or type == 'EMPTY':
            continue

        t = bld.name_to_obj(s, bld.env)
        bld.ASSERT(t is not None, "Subsystem target %s not found" % s)
        for d in subsystems[s]:
            type = targets[d['TARGET']]
            if type != 'DISABLED' and type != 'EMPTY':
                t.samba_deps_extended.append(d['TARGET'])
                t2 = bld.name_to_obj(d['TARGET'], bld.env)
                t2.samba_includes_extended.extend(t.samba_includes_extended)
                t2.samba_deps_extended.extend(t.samba_deps_extended)
        t.samba_deps_extended = unique_list(t.samba_deps_extended)



def build_dependencies(self):
    '''This builds the dependency list for a target. It runs after all the targets are declared

    The reason this is not just done in the SAMBA_*() rules is that we have no way of knowing
    the full dependency list for a target until we have all of the targets declared.
    '''

    # we only should add extra library and object deps on libraries and binaries
    if not self.samba_type in ['LIBRARY', 'BINARY', 'PYTHON']:
        return

    # we need to link against:

    #  1) any direct system libs
    #  2) any indirect system libs that come from subsystem dependencies
    #  3) any direct local libs
    #  4) any indirect local libs that come from subsystem dependencies
    #  5) any direct objects
    #  6) any indirect objects that come from subsystem dependencies

    self.uselib        = list(self.final_syslibs)
    self.uselib_local  = list(self.final_libs)
    self.add_objects   = list(self.final_objects)

    debug('deps: computed dependencies for target %s: uselib=%s uselib_local=%s add_objects=%s',
          self.sname, self.uselib, self.uselib_local, self.add_objects)



def build_includes(self):
    '''This builds the right set of includes for a target.

    One tricky part of this is that the includes= attribute for a
    target needs to use paths which are relative to that targets
    declaration directory (which we can get at via t.path).

    The way this works is the includes list gets added as
    samba_includes in the main build task declaration. Then this
    function runs after all of the tasks are declared, and it
    processes the samba_includes attribute to produce a includes=
    attribute
    '''

    if getattr(self, 'samba_includes', None) is None:
        return

    bld = self.bld

    inc_deps = self.includes_objects

    includes = []

    # maybe add local includes
    if getattr(self, 'local_include', True) == True and getattr(self, 'local_include_first', True):
        includes.append('.')

    includes.extend(self.samba_includes_extended)

    if 'EXTRA_INCLUDES' in bld.env:
        includes.extend(bld.env['EXTRA_INCLUDES'])

    includes.append('#')

    inc_set = set()
    inc_abs = []

    for d in inc_deps:
        t = bld.name_to_obj(d, bld.env)
        bld.ASSERT(t is not None, "Unable to find dependency %s for %s" % (d, self.sname))
        inclist = getattr(t, 'samba_includes_extended', [])
        if getattr(t, 'local_include', True) == True:
            inclist.append('.')
        if inclist == []:
            continue
        tpath = t.samba_abspath
        for inc in inclist:
            npath = tpath + '/' + inc
            if not npath in inc_set:
                inc_abs.append(npath)
                inc_set.add(npath)

    mypath = self.path.abspath(bld.env)
    for inc in inc_abs:
        relpath = os_path_relpath(inc, mypath)
        includes.append(relpath)

    if getattr(self, 'local_include', True) == True and not getattr(self, 'local_include_first', True):
        includes.append('.')

    self.includes = unique_list(includes)
    debug('deps: includes for target %s: includes=%s',
          self.sname, self.includes)



def add_init_functions(self):
    '''This builds the right set of init functions'''

    bld = self.bld

    subsystems = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')

    modules = []
    if self.sname in subsystems:
        modules.append(self.sname)

    m = getattr(self, 'samba_modules', None)
    if m is not None:
        modules.extend(TO_LIST(m))

    m = getattr(self, 'samba_subsystem', None)
    if m is not None:
        modules.append(m)

    if modules == []:
        return

    sentinal = getattr(self, 'init_function_sentinal', 'NULL')

    cflags = getattr(self, 'samba_cflags', [])[:]
    for m in modules:
        bld.ASSERT(m in subsystems,
                   "No init_function defined for module '%s' in target '%s'" % (m, self.sname))
        init_fn_list = []
        for d in subsystems[m]:
            init_fn_list.append(d['INIT_FUNCTION'])
        cflags.append('-DSTATIC_%s_MODULES=%s' % (m, ','.join(init_fn_list) + ',' + sentinal))
    self.ccflags = cflags



def check_duplicate_sources(bld, tgt_list):
    '''see if we are compiling the same source file into multiple
    subsystem targets for the same library or binary'''

    debug('deps: checking for duplicate sources')

    targets = LOCAL_CACHE(bld, 'TARGET_TYPE')

    for t in tgt_list:
        if not targets[t.sname] in [ 'LIBRARY', 'BINARY', 'PYTHON' ]:
            continue

        sources = []
        for obj in t.add_objects:
            t2 = t.bld.name_to_obj(obj, bld.env)
            obj_sources = getattr(t2, 'source', '')
            if obj_sources == '': continue
            tpath = os_path_relpath(t2.path.abspath(bld.env), t.env['BUILD_DIRECTORY'] + '/default')
            obj_sources = bld.SUBDIR(tpath, obj_sources)
            sources.append( { 'dep':obj, 'src':set(TO_LIST(obj_sources)) } )
            #debug('deps: dependency expansion for target %s add_object %s: %s',
            #      t.sname, obj, obj_sources)
            for s in sources:
                for s2 in sources:
                    if s['dep'] == s2['dep']: continue
                    common = s['src'].intersection(s2['src'])
                    if common:
                        bld.ASSERT(False,
                                   "Target %s has duplicate source files in %s and %s : %s" % (t.sname,
                                                                                               s['dep'], s2['dep'],
                                                                                               common))

def check_orpaned_targets(bld, tgt_list):
    '''check if any build targets are orphaned'''

    target_dict = LOCAL_CACHE(bld, 'TARGET_TYPE')

    debug('deps: checking for orphaned targets')

    for t in tgt_list:
        if getattr(t, 'samba_used', False) == True:
            continue
        type = target_dict[t.sname]
        if not type in ['BINARY', 'LIBRARY', 'MODULE', 'ET', 'PYTHON']:
            if re.search('^PIDL_', t.sname) is None:
                print "Target %s of type %s is unused by any other target" % (t.sname, type)


def show_final_deps(bld, tgt_list):
    '''show the final dependencies for all targets'''

    targets = LOCAL_CACHE(bld, 'TARGET_TYPE')

    for t in tgt_list:
        if not targets[t.sname] in ['LIBRARY', 'BINARY', 'PYTHON']:
            continue
        debug('deps: final dependencies for target %s: uselib=%s uselib_local=%s add_objects=%s',
              t.sname, t.uselib, t.uselib_local, t.add_objects)


def add_samba_attributes(bld, tgt_list):
    '''ensure a target has a the required samba attributes'''

    targets = LOCAL_CACHE(bld, 'TARGET_TYPE')

    for t in tgt_list:
        if t.name != '':
            t.sname = t.name
        else:
            t.sname = t.target
        t.samba_type = targets[t.sname]
        t.samba_abspath = t.path.abspath(bld.env)
        t.samba_deps_extended = t.samba_deps[:]
        t.samba_includes_extended = TO_LIST(t.samba_includes)[:]
        t.ccflags = getattr(t, 'samba_cflags', '')

def build_direct_deps(bld, tgt_list):
    '''build the direct_objects and direct_libs sets for each target'''

    targets  = LOCAL_CACHE(bld, 'TARGET_TYPE')
    global_deps = bld.env.GLOBAL_DEPENDENCIES

    for t in tgt_list:
        t.direct_objects = set()
        t.direct_libs = set()
        t.direct_syslibs = set()
        deps = t.samba_deps_extended
        deps.extend(global_deps)
        for d in deps:
            d = EXPAND_ALIAS(bld, d)
            if not d in targets:
                print "Unknown dependency %s in %s" % (d, t.sname)
                raise
            if targets[d] in [ 'EMPTY', 'DISABLED' ]:
                continue
            if targets[d] == 'SYSLIB':
                t.direct_syslibs.add(d)
                continue
            t2 = bld.name_to_obj(d, bld.env)
            if t2 is None:
                print "no task %s type %s" % (d, targets[d])
            if t2.samba_type in [ 'LIBRARY', 'MODULE' ]:
                t.direct_libs.add(d)
            elif t2.samba_type in [ 'SUBSYSTEM', 'ASN1', 'PYTHON' ]:
                t.direct_objects.add(d)
    debug('deps: built direct dependencies')



def indirect_libs(bld, t, chain):
    '''recursively calculate the indirect library dependencies for a target

    An indirect library is a library that results from a dependency on
    a subsystem
    '''

    ret = getattr(t, 'indirect_libs', None)
    if ret is not None:
        return ret

    ret = set()
    for obj in t.direct_objects:
        if obj in chain:
            continue
        chain.add(obj)
        t2 = bld.name_to_obj(obj, bld.env)
        r2 = indirect_libs(bld, t2, chain)
        chain.remove(obj)
        ret = ret.union(t2.direct_libs)
        ret = ret.union(r2)

    for obj in t.indirect_objects:
        if obj in chain:
            continue
        chain.add(obj)
        t2 = bld.name_to_obj(obj, bld.env)
        r2 = indirect_libs(bld, t2, chain)
        chain.remove(obj)
        ret = ret.union(t2.direct_libs)
        ret = ret.union(r2)

    t.indirect_libs = ret

    return ret


def indirect_syslibs(bld, t, chain):
    '''recursively calculate the indirect system library dependencies for a target

    An indirect syslib results from a subsystem dependency
    '''

    ret = getattr(t, 'indirect_syslibs', None)
    if ret is not None:
        return ret
    ret = set()
    for obj in t.direct_objects:
        if obj in chain:
            continue
        chain.add(obj)
        t2 = bld.name_to_obj(obj, bld.env)
        r2 = indirect_syslibs(bld, t2, chain)
        chain.remove(obj)
        ret = ret.union(t2.direct_syslibs)
        ret = ret.union(r2)

    t.indirect_syslibs = ret
    return ret


def indirect_objects(bld, t, chain):
    '''recursively calculate the indirect object dependencies for a target

    indirect objects are the set of objects from expanding the
    subsystem dependencies
    '''

    ret = getattr(t, 'indirect_objects', None)
    if ret is not None: return ret

    ret = set()
    for lib in t.direct_objects:
        if lib in chain:
            continue
        chain.add(lib)
        t2 = bld.name_to_obj(lib, bld.env)
        r2 = indirect_objects(bld, t2, chain)
        chain.remove(lib)
        ret = ret.union(t2.direct_objects)
        ret = ret.union(r2)

    t.indirect_objects = ret
    return ret


def expanded_targets(bld, t, chain):
    '''recursively calculate the expanded targets for a target

    expanded objects are the set of objects, libraries and syslibs
    from expanding the subsystem dependencies, library dependencies
    and syslib dependencies
    '''

    ret = getattr(t, 'expanded_targets', None)
    if ret is not None: return ret

    ret = t.direct_objects.copy()
    ret = ret.union(t.direct_libs)
    ret = ret.union(t.direct_syslibs)

    direct = ret.copy()

    for d in direct:
        if d in chain: continue
        chain.add(d)
        t2 = bld.name_to_obj(d, bld.env)
        if t2 is None: continue
        r2 = expanded_targets(bld, t2, chain)
        chain.remove(d)
        ret = ret.union(r2)

    if t.sname in ret:
        ret.remove(t.sname)

    t.expanded_targets = ret
    return ret


def expanded_targets2(bld, t, chain):
    '''recursively calculate the expanded targets for a target

    expanded objects are the set of objects from expanding the
    subsystem dependencies and library dependencies
    '''

    ret = getattr(t, 'expanded_targets2', None)
    if ret is not None: return ret

    ret = t.final_objects.copy()

    for attr in [ 'final_objects', 'final_libs' ]:
        f = getattr(t, attr, set())
        for d in f.copy():
            if d in chain:
                continue
            chain.add(d)
            t2 = bld.name_to_obj(d, bld.env)
            if t2 is None: continue
            r2 = expanded_targets2(bld, t2, chain)
            chain.remove(d)
            ret = ret.union(r2)

    if t.sname in ret:
        ret.remove(t.sname)

    t.expanded_targets2 = ret
    return ret


def includes_objects(bld, t, chain):
    '''recursively calculate the includes object dependencies for a target

    includes dependencies come from either library or object dependencies
    '''
    ret = getattr(t, 'includes_objects', None)
    if ret is not None:
        return ret

    ret = t.direct_objects.copy()
    ret = ret.union(t.direct_libs)

    for obj in t.direct_objects:
        if obj in chain:
            continue
        chain.add(obj)
        t2 = bld.name_to_obj(obj, bld.env)
        r2 = includes_objects(bld, t2, chain)
        chain.remove(obj)
        ret = ret.union(t2.direct_objects)
        ret = ret.union(r2)

    for lib in t.direct_libs:
        if lib in chain:
            continue
        chain.add(lib)
        t2 = bld.name_to_obj(lib, bld.env)
        r2 = includes_objects(bld, t2, chain)
        chain.remove(lib)
        ret = ret.union(t2.direct_objects)
        ret = ret.union(r2)

    t.includes_objects = ret
    return ret


def build_indirect_deps(bld, tgt_list):
    '''build the indirect_objects and indirect_libs sets for each target'''
    for t in tgt_list:
        indirect_objects(bld, t, set())
        indirect_libs(bld, t, set())
        indirect_syslibs(bld, t, set())
        includes_objects(bld, t, set())
        expanded_targets(bld, t, set())
    debug('deps: built indirect dependencies')


def re_expand2(bld, tgt_list):
    for t in tgt_list:
        t.expanded_targets2 = None
    for type in ['BINARY','LIBRARY','PYTHON']:
        for t in tgt_list:
            if t.samba_type == type:
                expanded_targets2(bld, t, set())
    for t in tgt_list:
        expanded_targets2(bld, t, set())


def calculate_final_deps(bld, tgt_list):
    '''calculate the final library and object dependencies'''
    for t in tgt_list:
        # start with the maximum possible list
        t.final_syslibs = t.direct_syslibs.union(t.indirect_syslibs)
        t.final_libs    = t.direct_libs.union(t.indirect_libs)
        t.final_objects = t.direct_objects.union(t.indirect_objects)

    for t in tgt_list:
        # don't depend on ourselves
        if t.sname in t.final_libs:
            t.final_libs.remove(t.sname)
        if t.sname in t.final_objects:
            t.final_objects.remove(t.sname)

    re_expand2(bld, tgt_list)

    loops = {}

    # find any library loops
    for t in tgt_list:
        if t.samba_type in ['LIBRARY', 'PYTHON']:
            for l in t.final_libs.copy():
                t2 = bld.name_to_obj(l, bld.env)
                if t.sname in t2.final_libs:
                    debug('deps: removing library loop %s<->%s', t.sname, l)
                    t2.final_libs.remove(t.sname)
                    loops[t2.sname] = t.sname;

    re_expand2(bld, tgt_list)

    for type in ['BINARY']:
        while True:
            changed = False
            for t in tgt_list:
                if t.samba_type != type: continue
                # if we will indirectly link to a target then we don't need it
                new = t.final_objects.copy()
                for l in t.final_libs:
                    t2 = bld.name_to_obj(l, bld.env)
                    dup = new.intersection(t2.expanded_targets2)
                    if dup:
                        debug('deps: removing dups from %s: %s also in %s %s',
                              t.sname, dup, t2.samba_type, l)
                        new = new.difference(dup)
                        changed = True
                if changed:
                    t.final_objects = new
                    break
            if not changed:
                break
    debug('deps: removed duplicate dependencies')


######################################################################
# this provides a way to save our dependency calculations between runs
savedeps_version = 1
savedeps_inputs  = ['samba_deps', 'samba_includes', 'local_include', 'local_include_first', 'samba_cflags']
savedeps_outputs = ['uselib', 'uselib_local', 'add_objects', 'includes', 'ccflags']
savedeps_caches  = ['GLOBAL_DEPENDENCIES', 'TARGET_ALIAS', 'TARGET_TYPE', 'INIT_FUNCTIONS']

def save_samba_deps(bld, tgt_list):
    '''save the dependency calculations between builds, to make
       further builds faster'''
    denv = Environment.Environment()

    denv.version = savedeps_version
    denv.savedeps_inputs = savedeps_inputs
    denv.savedeps_outputs = savedeps_outputs
    denv.input = {}
    denv.output = {}
    denv.caches = {}

    for c in savedeps_caches:
        denv.caches[c] = LOCAL_CACHE(bld, c)

    for t in tgt_list:
        # save all the input attributes for each target
        tdeps = {}
        for attr in savedeps_inputs:
            v = getattr(t, attr, None)
            if v is not None:
                tdeps[attr] = v
        if tdeps != {}:
            denv.input[t.sname] = tdeps

        # save all the output attributes for each target
        tdeps = {}
        for attr in savedeps_outputs:
            v = getattr(t, attr, None)
            if v is not None:
                tdeps[attr] = v
        if tdeps != {}:
            denv.output[t.sname] = tdeps

    depsfile = os.path.join(bld.bdir, "sambadeps")
    denv.store(depsfile)


def load_samba_deps(bld, tgt_list):
    '''load a previous set of build dependencies if possible'''
    depsfile = os.path.join(bld.bdir, "sambadeps")
    denv = Environment.Environment()
    try:
        debug('deps: checking saved dependencies')
        denv.load(depsfile)
        if (denv.version != savedeps_version or
            denv.savedeps_inputs != savedeps_inputs or
            denv.savedeps_outputs != savedeps_outputs):
            return False
    except:
        return False

    # check if caches are the same
    for c in savedeps_caches:
        if c not in denv.caches or denv.caches[c] != LOCAL_CACHE(bld, c):
            return False

    # check inputs are the same
    for t in tgt_list:
        tdeps = {}
        for attr in savedeps_inputs:
            v = getattr(t, attr, None)
            if v is not None:
                tdeps[attr] = v
        if t.sname in denv.input:
            olddeps = denv.input[t.sname]
        else:
            olddeps = {}
        if tdeps != olddeps:
            #print '%s: \ntdeps=%s \nodeps=%s' % (t.sname, tdeps, olddeps)
            return False

    # put outputs in place
    for t in tgt_list:
        if not t.sname in denv.output: continue
        tdeps = denv.output[t.sname]
        for a in tdeps:
            setattr(t, a, tdeps[a])

    debug('deps: loaded saved dependencies')
    return True


def check_project_rules(bld):
    '''check the project rules - ensuring the targets are sane'''

    targets = LOCAL_CACHE(bld, 'TARGET_TYPE')

    # build a list of task generators we are interested in
    tgt_list = []
    for tgt in targets:
        type = targets[tgt]
        if not type in ['SUBSYSTEM', 'MODULE', 'BINARY', 'LIBRARY', 'ASN1', 'PYTHON']:
            continue
        t = bld.name_to_obj(tgt, bld.env)
        tgt_list.append(t)

    add_samba_attributes(bld, tgt_list)

    if load_samba_deps(bld, tgt_list):
        return

    debug('deps: project rules checking started')

    expand_subsystem_deps(bld)
    build_direct_deps(bld, tgt_list)
    build_indirect_deps(bld, tgt_list)
    calculate_final_deps(bld, tgt_list)

    # run the various attribute generators
    for f in [ build_dependencies, build_includes, add_init_functions ]:
        debug('deps: project rules checking %s', f)
        for t in tgt_list: f(t)

    debug('deps: project rules stage1 completed')

    #check_orpaned_targets(bld, tgt_list)
    #check_duplicate_sources(bld, tgt_list)
    show_final_deps(bld, tgt_list)

    debug('deps: project rules checking completed - %u targets checked',
          len(tgt_list))

    save_samba_deps(bld, tgt_list)


def CHECK_PROJECT_RULES(bld):
    '''enable checking of project targets for sanity'''
    if bld.env.added_project_rules:
        return
    bld.env.added_project_rules = True
    bld.add_pre_fun(check_project_rules)
Build.BuildContext.CHECK_PROJECT_RULES = CHECK_PROJECT_RULES



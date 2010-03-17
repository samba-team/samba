# Samba automatic dependency handling

from TaskGen import taskgen, before
import Build, os, string, Utils, re
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


def expand_dependencies(bld, dep, chain, path):
    '''expand a dependency recursively
       return a triple of (uselib, uselib_local, add_objects)
    '''

    dep = EXPAND_ALIAS(bld, dep)

    t = bld.name_to_obj(dep, bld.env)

    # check for a cached list
    if t is not None:
        expanded = getattr(t, 'expanded_dependencies', None)
        if expanded is not None:
            return expanded

    target_dict = LOCAL_CACHE(bld, 'TARGET_TYPE')

    uselib_local = []
    uselib       = []
    add_objects  = []

    recurse = False

    bld.ASSERT(dep in target_dict, "Dependency %s not found in %s" % (dep, path))
    type = target_dict[dep]
    if type == 'SYSLIB':
        uselib.append(dep)
    elif type == 'LIBRARY':
        uselib_local.append(dep)
        recurse = True
    elif type == 'SUBSYSTEM':
        add_objects.append(dep)
        recurse = True
    elif type == 'MODULE':
        add_objects.append(dep)
        recurse = True
    elif type == 'PYTHON':
        add_objects.append(dep)
        recurse = True
    elif type == 'ASN1':
        add_objects.append(dep)
        recurse = True
    elif type == 'BINARY':
        pass
    elif type == 'EMPTY':
        pass
    elif type == 'DISABLED':
        debug('deps: Ignoring dependency on disabled target %s: %s' % (dep, path))
    else:
        bld.ASSERT(False, "Unknown target type %s for %s" % (type, dep))

    # for some types we have to build the list recursively
    if recurse:
        bld.ASSERT(t is not None, "Unable to find target %s" % dep)
        rec_deps = getattr(t, 'samba_deps', None)
        bld.ASSERT(rec_deps is not None, "Unable to find dependencies of target %s" % dep)
        for d2 in rec_deps:
            try:
                bld.ASSERT(d2 not in chain, "Circular dependency for %s: %s->%s" % (dep, path, d2))
            except:
                print "Removing dependency %s from target %s" % (d2, dep)
                rec_deps.remove(d2)
                continue
            c2 = chain.copy()
            c2[d2] = True
            (rec_uselib, rec_uselib_local,
             rec_add_objects) = expand_dependencies(bld, d2, c2, "%s->%s" % (path, d2))
            uselib.extend(rec_uselib)
            uselib_local.extend(rec_uselib_local)
            add_objects.extend(rec_add_objects)

    if t is not None:
        t.expanded_dependencies = (uselib, uselib_local, add_objects)

    return (uselib, uselib_local, add_objects)


def expand_deplist(self):
    '''return an expanded list of dependencies from the samba_deps attribute'''

    if not getattr(self, 'samba_deps', None):
        return ([], [], [])

    bld = self.bld
    deps = self.samba_deps

    uselib_local = []
    uselib       = []
    add_objects  = []

    for d in deps:
        (u, ul, ao) = expand_dependencies(bld, d, { self.name:True }, self.name)
        uselib.extend(u)
        uselib_local.extend(ul)
        add_objects.extend(ao)

    return (uselib, uselib_local, add_objects)



@feature('cc', 'cshlib', 'cprogram')
@before('apply_lib_vars', 'apply_verif', 'apply_objdeps', 'apply_obj_vars', 'apply_incpaths', 'build_includes')
@after('default_cc')
def build_dependencies(self):
    '''This builds the dependency list for a target. It runs after all the targets are declared

    The reason this is not just done in the SAMBA_*() rules is that we have no way of knowing
    the full dependency list for a target until we have all of the targets declared. So what we do is
    add a samba_deps attribute on the task generator when we declare it, then
    this rule runs after all the task generators are declared and maps the samba_deps attribute
    to a set of uselib, uselib_local and add_objects dependencies
    '''

    if getattr(self, 'build_dependencies_done', False):
        return
    self.build_dependencies_done = True

    if getattr(self, 'samba_deps', None) is None:
        return

    target_dict = LOCAL_CACHE(self.bld, 'TARGET_TYPE')

    # we only should add extra library and object deps on libraries and binaries
    type = target_dict[self.name]
    if type != 'LIBRARY' and type != 'BINARY':
        return

    (uselib, uselib_local, add_objects) = expand_deplist(self)

    if 'GLOBAL_DEPENDENCIES' in self.bld.env:
        add_objects.extend(self.bld.env.GLOBAL_DEPENDENCIES)

    self.uselib        = unique_list(uselib)
    self.uselib_local  = unique_list(uselib_local)
    self.add_objects   = unique_list(add_objects)

    debug('deps: dependency counts for %s: uselib=%u uselib_local=%u add_objects=%u' % (
        self.name, len(uselib), len(uselib_local), len(add_objects)))



@feature('cc', 'cshlib', 'cprogram')
@before('apply_lib_vars', 'apply_verif', 'apply_objdeps', 'apply_obj_vars', 'apply_incpaths', 'add_init_functions')
@after('build_dependencies')
def build_includes(self):
    '''This builds the right set of includes for a target.

    This is closely related to building the set of dependencies, and
    calls into the same expand_dependencies() function to do the work.

    One tricky part of this is that the includes= attribute for a
    target needs to use paths which are relative to that targets
    declaration directory (which we can get at via t.path).

    The way this works is the includes list gets added as
    samba_includes in the main build task declaration. Then this
    function runs after all of the tasks are declared, and it
    processes the samba_includes attribute to produce a includes=
    attribute
    '''

    if not getattr(self, 'build_dependencies_done', False):
        build_dependencies(self)
    if getattr(self, 'build_includes_done', False):
        return
    self.build_includes_done = True

    if getattr(self, 'samba_includes', None) is None:
        return

    bld = self.bld

    (uselib, uselib_local, add_objects) = expand_deplist(self)

    # get the list of all dependencies
    all_deps = []
#    all_deps.extend(uselib)
    all_deps.extend(uselib_local)
    all_deps.extend(add_objects)
    all_deps = unique_list(all_deps)

    includes = []

    # build a list of includes
    if getattr(self, 'local_include', True) == True and getattr(self, 'local_include_first', True):
        includes.append('.')

    includes.extend(TO_LIST(self.samba_includes))

    if 'EXTRA_INCLUDES' in bld.env:
        includes.extend(bld.env['EXTRA_INCLUDES'])

    includes.append('#')

    mypath = self.path.abspath(bld.env)

    for d in all_deps:
        t = bld.name_to_obj(d, bld.env)
        bld.ASSERT(t is not None, "Unable to find dependency %s for %s" % (d, self.name))
        t.samba_used = True
        samba_includes = getattr(t, 'samba_includes', None)
        inclist = TO_LIST(samba_includes)
        if getattr(t, 'local_include', True) == True:
            inclist.append('.')
        if inclist == []:
            continue
        tpath = t.path.abspath(bld.env)
        relpath = os.path.relpath(tpath, mypath)
        for inc in inclist:
            includes.append(os.path.normpath(os.path.join(relpath, inc)))

    if getattr(self, 'local_include', True) == True and not getattr(self, 'local_include_first', True):
        includes.append('.')

    self.includes = unique_list(includes)
    debug('deps: Target %s has includes=%s all_deps=%s' % (self.name, self.includes, all_deps))


@feature('cc', 'cshlib', 'cprogram')
@before('apply_lib_vars', 'apply_verif', 'apply_objdeps', 'apply_obj_vars', 'apply_incpaths')
@after('build_includes')
def add_init_functions(self):
    '''This builds the right set of init functions'''

    if not getattr(self, 'build_includes_done', False):
        build_includes(self)
    if getattr(self, 'add_init_functions_done', False):
        return
    self.add_init_functions_done = True

    bld = self.bld

    subsystems = LOCAL_CACHE(bld, 'INIT_FUNCTIONS')

    modules = []
    if self.name in subsystems:
        modules.append(self.name)

    m = getattr(self, 'samba_modules', None)
    if m is not None:
        modules.extend(TO_LIST(m))

    m = getattr(self, 'samba_subsystem', None)
    if m is not None:
        modules.append(m)

    if modules == []:
        return

    cflags = getattr(self, 'ccflags', [])
    for m in modules:
        if not m in subsystems:
            print "subsystems: %s" % subsystems
        bld.ASSERT(m in subsystems,
                   "No init_function defined for module '%s' in target '%s'" % (m, self.name))
        cflags.append('-DSTATIC_%s_MODULES="%s"' % (m, ','.join(subsystems[m])))
    self.ccflags = cflags


def check_orpaned_targets(bld):
    '''check if any build targets are orphaned'''

    target_dict = LOCAL_CACHE(bld, 'TARGET_TYPE')

    # make sure all the earlier functions have run
    for t in bld.all_task_gen:
        if not t.name in target_dict:
            continue
        if not getattr(t, 'add_init_functions_done', False):
            add_init_functions(t)

    for t in bld.all_task_gen:
        if not t.name in target_dict:
            continue
        if getattr(t, 'samba_used', False) == True:
            continue
        type = target_dict[t.name]
        if type != 'BINARY' and type != 'LIBRARY' and type != 'MODULE':
            if re.search('^PIDL_', t.name) is None:
                print "Target %s of type %s is unused by any other target" % (t.name, type)


def CHECK_ORPANED_TARGETS(bld):
    bld.add_pre_fun(check_orpaned_targets)
Build.BuildContext.CHECK_ORPANED_TARGETS = CHECK_ORPANED_TARGETS


@feature('dfkj*')
def samba_post_process(self):
    '''samba specific post processing of task'''
    if getattr(self, 'meths', None) is None:
        return
    count = getattr(self, 'moved_to_end', 0)
    if count < 10:
        # there has got to be a better way!!
        self.moved_to_end = count + 1
        self.meths.append('samba_post_process')
        return

    samba_post = getattr(self, 'samba_post', None)
    if samba_post is None:
        return
    (tgt, cmd) = samba_post
    self.env.TARGET_DIRECTORY = self.path.abspath(self.env)
    #print "cmd=%s tgt=%s" % (cmd, tgt)
    cmd = Utils.subst_vars(cmd, self.env)
    tgt = Utils.subst_vars(tgt, self.env)
    if os.path.isfile(tgt):
        debug('deps: post processing for %s: %s' % (self.name, cmd))
        ret = os.system(cmd)
        self.bld.ASSERT(ret == 0, "Post processing for %s failed (%d): %s" % (self.name, ret, cmd))


##############################
# handle the creation of links for libraries and binaries
# note that we use a relative symlink path to allow the whole tree
# to me moved/copied elsewhere without breaking the links
t = Task.simple_task_type('symlink_lib', 'ln -sf ../${SRC} ${LINK_TARGET}', color='PINK',
                          ext_in='.bin')
t.quiet = True

@feature('symlink_lib')
@after('apply_link')
def symlink_lib(self):
    tsk = self.create_task('symlink_lib', self.link_task.outputs[0])

    # calculat the link target and put it in the environment
    soext=""
    vnum = getattr(self, 'vnum', None)
    if vnum is not None:
        soext = '.' + vnum.split('.')[0]

    libname = self.target
    tsk.env.LINK_TARGET = '%s/lib%s.so%s' % (LIB_PATH, libname, soext)
    debug('task_gen: LINK_TARGET for %s is %s', self.name, tsk.env.LINK_TARGET)


# for binaries we need to copy the executable to avoid the rpath changing
# in the local bin/ directory on install
t = Task.simple_task_type('copy_bin', 'rm -f ${BIN_TARGET} && cp ${SRC} ${BIN_TARGET}', color='PINK',
                          ext_in='.bin', shell=True)
t.quiet = True

@feature('copy_bin')
@after('apply_link')
def copy_bin(self):
    if Options.is_install:
        # we don't want to copy the install binary, as
        # that has the install rpath, not the build rpath
        # The rpath of the binaries in bin/default/foo/blah is different
        # during the install phase, as distros insist on not using rpath in installed binaries
        return
    tsk = self.create_task('copy_bin', self.link_task.outputs[0])

    tsk.env.BIN_TARGET = self.target
    debug('task_gen: BIN_TARGET for %s is %s', self.name, tsk.env.BIN_TARGET)



# This file contains waf optimisations for Samba

# most of these optimisations are possible because of the restricted build environment
# that Samba has. For example, Samba doesn't attempt to cope with Win32 paths during the
# build, and Samba doesn't need build varients

# overall this makes some build tasks quite a bit faster

import os
import Build, Utils, Node
from TaskGen import feature, after, before
import preproc

@feature('cc', 'cxx')
@after('apply_type_vars', 'apply_lib_vars', 'apply_core')
def apply_incpaths(self):
    lst = []

    try:
        kak = self.bld.kak
    except AttributeError:
        kak = self.bld.kak = {}

    # TODO move the uselib processing out of here
    for lib in self.to_list(self.uselib):
        for path in self.env['CPPPATH_' + lib]:
            if not path in lst:
                lst.append(path)
    if preproc.go_absolute:
        for path in preproc.standard_includes:
            if not path in lst:
                lst.append(path)

    for path in self.to_list(self.includes):
        if not path in lst:
            if preproc.go_absolute or path[0] != '/':  # os.path.isabs(path):
                lst.append(path)
            else:
                self.env.prepend_value('CPPPATH', path)

    for path in lst:
        node = None
        if path[0] == '/': # os.path.isabs(path):
            if preproc.go_absolute:
                node = self.bld.root.find_dir(path)
        elif path[0] == '#':
            node = self.bld.srcnode
            if len(path) > 1:
                try:
                    node = kak[path]
                except KeyError:
                    kak[path] = node = node.find_dir(path[1:])
        else:
            try:
                node = kak[(self.path.id, path)]
            except KeyError:
                kak[(self.path.id, path)] = node = self.path.find_dir(path)

        if node:
            self.env.append_value('INC_PATHS', node)

@feature('cc')
@after('apply_incpaths')
def apply_obj_vars_cc(self):
    """after apply_incpaths for INC_PATHS"""
    env = self.env
    app = env.append_unique
    cpppath_st = env['CPPPATH_ST']

    lss = env['_CCINCFLAGS']

    try:
         cac = self.bld.cac
    except AttributeError:
         cac = self.bld.cac = {}

    # local flags come first
    # set the user-defined includes paths
    for i in env['INC_PATHS']:

        try:
            lss.extend(cac[i.id])
        except KeyError:

            cac[i.id] = [cpppath_st % i.bldpath(env), cpppath_st % i.srcpath(env)]
            lss.extend(cac[i.id])

    env['_CCINCFLAGS'] = lss
    # set the library include paths
    for i in env['CPPPATH']:
        app('_CCINCFLAGS', cpppath_st % i)

import Node, Environment

def vari(self):
    return "default"
Environment.Environment.variant = vari

def variant(self, env):
    if not env: return 0
    elif self.id & 3 == Node.FILE: return 0
    else: return "default"
Node.Node.variant = variant


import TaskGen, Task

def create_task(self, name, src=None, tgt=None):
    task = Task.TaskBase.classes[name](self.env, generator=self)
    if src:
        task.set_inputs(src)
    if tgt:
        task.set_outputs(tgt)
    return task
TaskGen.task_gen.create_task = create_task

def hash_constraints(self):
    a = self.attr
    sum = hash((str(a('before', '')),
            str(a('after', '')),
            str(a('ext_in', '')),
            str(a('ext_out', '')),
            self.__class__.maxjobs))
    return sum
Task.TaskBase.hash_constraints = hash_constraints

def hash_env_vars(self, env, vars_lst):
    idx = str(id(env)) + str(vars_lst)
    try:
        return self.cache_sig_vars[idx]
    except KeyError:
        pass

    m = Utils.md5()
    m.update(''.join([str(env[a]) for a in vars_lst]))

    ret = self.cache_sig_vars[idx] = m.digest()
    return ret
Build.BuildContext.hash_env_vars = hash_env_vars


def store_fast(self, filename):
    file = open(filename, 'wb')
    data = self.get_merged_dict()
    try:
        Build.cPickle.dump(data, file, -1)
    finally:
        file.close()
Environment.Environment.store_fast = store_fast

def load_fast(self, filename):
    file = open(filename, 'rb')
    try:
        data = Build.cPickle.load(file)
    finally:
        file.close()
    self.table.update(data)
Environment.Environment.load_fast = load_fast

def is_this_a_static_lib(self, name):
    try:
        cache = self.cache_is_this_a_static_lib
    except AttributeError:
        cache = self.cache_is_this_a_static_lib = {}
    try:
        return cache[name]
    except KeyError:
        ret = cache[name] = 'cstaticlib' in self.bld.name_to_obj(name, self.env).features
        return ret
TaskGen.task_gen.is_this_a_static_lib = is_this_a_static_lib

def shared_ancestors(self):
    try:
        cache = self.cache_is_this_a_static_lib
    except AttributeError:
        cache = self.cache_is_this_a_static_lib = {}
    try:
        return cache[id(self)]
    except KeyError:

        ret = []
        if 'cshlib' in self.features: # or 'cprogram' in self.features:
            if getattr(self, 'uselib_local', None):
                lst = self.to_list(self.uselib_local)
                ret = [x for x in lst if not self.is_this_a_static_lib(x)]
        cache[id(self)] = ret
        return ret
TaskGen.task_gen.shared_ancestors = shared_ancestors

@feature('cc', 'cxx')
@after('apply_link', 'init_cc', 'init_cxx', 'apply_core')
def apply_lib_vars(self):
    """after apply_link because of 'link_task'
    after default_cc because of the attribute 'uselib'"""

    # after 'apply_core' in case if 'cc' if there is no link

    env = self.env
    app = env.append_value
    seen_libpaths = set([])

    # OPTIMIZATION 1: skip uselib variables already added (700ms)
    seen_uselib = set([])

    # 1. the case of the libs defined in the project (visit ancestors first)
    # the ancestors external libraries (uselib) will be prepended
    self.uselib = self.to_list(self.uselib)
    names = self.to_list(self.uselib_local)

    seen = set([])
    tmp = Utils.deque(names) # consume a copy of the list of names
    while tmp:
        lib_name = tmp.popleft()
        # visit dependencies only once
        if lib_name in seen:
            continue

        y = self.name_to_obj(lib_name)
        if not y:
            raise Utils.WafError('object %r was not found in uselib_local (required by %r)' % (lib_name, self.name))
        y.post()
        seen.add(lib_name)

        # OPTIMIZATION 2: pre-compute ancestors shared libraries (100ms)
        tmp.extend(y.shared_ancestors())

        # link task and flags
        if getattr(y, 'link_task', None):

            link_name = y.target[y.target.rfind('/') + 1:]
            if 'cstaticlib' in y.features:
                app('STATICLIB', link_name)
            elif 'cshlib' in y.features or 'cprogram' in y.features:
                # WARNING some linkers can link against programs
                app('LIB', link_name)

            # the order
            self.link_task.set_run_after(y.link_task)

            # for the recompilation
            dep_nodes = getattr(self.link_task, 'dep_nodes', [])
            self.link_task.dep_nodes = dep_nodes + y.link_task.outputs

            # OPTIMIZATION 3: reduce the amount of function calls
            # add the link path too
            par = y.link_task.outputs[0].parent
            if id(par) not in seen_libpaths:
                seen_libpaths.add(id(par))
                tmp_path = par.bldpath(self.env)
                if not tmp_path in env['LIBPATH']:
                    env.prepend_value('LIBPATH', tmp_path)


        # add ancestors uselib too - but only propagate those that have no staticlib
        for v in self.to_list(y.uselib):
            if v not in seen_uselib:
                seen_uselib.add(v)
                if not env['STATICLIB_' + v]:
                    if not v in self.uselib:
                        self.uselib.insert(0, v)

    # 2. the case of the libs defined outside
    for x in self.uselib:
        for v in self.p_flag_vars:
            val = self.env[v + '_' + x]
            if val:
                self.env.append_value(v, val)

@feature('cprogram', 'cshlib', 'cstaticlib')
@after('apply_lib_vars')
@before('apply_obj_vars')
def samba_before_apply_obj_vars(self):
    """before apply_obj_vars for uselib, this removes the standard pathes"""

    def is_standard_libpath(env, path):
        for _path in env.STANDARD_LIBPATH:
            if _path == os.path.normpath(path):
                return True
        return False

    v = self.env

    for i in v['RPATH']:
        if is_standard_libpath(v, i):
            v['RPATH'].remove(i)

    for i in v['LIBPATH']:
        if is_standard_libpath(v, i):
            v['LIBPATH'].remove(i)

@feature('cc')
@before('apply_incpaths', 'apply_obj_vars_cc')
def samba_stash_cppflags(self):
    """Fix broken waf ordering of CPPFLAGS"""

    self.env.SAVED_CPPFLAGS = self.env.CPPFLAGS
    self.env.CPPFLAGS = []

@feature('cc')
@after('apply_incpaths', 'apply_obj_vars_cc')
def samba_pop_cppflags(self):
    """append stashed user CPPFLAGS after our internally computed flags"""

    #
    # Note that we don't restore the values to 'CPPFLAGS',
    # but to _CCINCFLAGS instead.
    #
    # buildtools/wafadmin/Tools/cc.py defines the 'cc' task generator as
    # '${CC} ${CCFLAGS} ${CPPFLAGS} ${_CCINCFLAGS} ${_CCDEFFLAGS} ${CC_SRC_F}${SRC} ${CC_TGT_F}${TGT}'
    #
    # Our goal is to effectively invert the order of ${CPPFLAGS} and
    # ${_CCINCFLAGS}.
    self.env.append_value('_CCINCFLAGS', self.env.SAVED_CPPFLAGS)
    self.env.SAVED_CPPFLAGS = []

@feature('cprogram', 'cshlib', 'cstaticlib')
@before('apply_obj_vars', 'add_extra_flags')
def samba_stash_linkflags(self):
    """stash away LINKFLAGS in order to fix waf's broken ordering wrt or
    user LDFLAGS"""

    self.env.SAVE_LINKFLAGS = self.env.LINKFLAGS
    self.env.LINKFLAGS = []

@feature('cprogram', 'cshlib', 'cstaticlib')
@after('apply_obj_vars', 'add_extra_flags')
def samba_pop_linkflags(self):
    """after apply_obj_vars append saved LDFLAGS"""

    self.env.append_value('LINKFLAGS', self.env.SAVE_LINKFLAGS)
    self.env.SAVE_LINKFLAGS = []

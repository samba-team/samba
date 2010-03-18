# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, sys, Options, Utils
from TaskGen import feature, before
from Configure import conf
from Logs import debug
import shlex

# TODO: make this a --option
LIB_PATH="shared"


##########################################################
# create a node with a new name, based on an existing node
def NEW_NODE(node, name):
    ret = node.parent.find_or_declare([name])
    ASSERT(node, ret is not None, "Unable to find new target with name '%s' from '%s'" % (
            name, node.name))
    return ret


#############################################################
# set a value in a local cache
# return False if it's already set
def SET_TARGET_TYPE(ctx, target, value):
    cache = LOCAL_CACHE(ctx, 'TARGET_TYPE')
    if target in cache:
        ASSERT(ctx, cache[target] == value,
               "Target '%s' re-defined as %s - was %s" % (target, value, cache[target]))
        debug("task_gen: Skipping duplicate target %s (curdir=%s)" % (target, ctx.curdir))
        return False
    LOCAL_CACHE_SET(ctx, 'TARGET_TYPE', target, value)
    debug("task_gen: Target '%s' created of type '%s' in %s" % (target, value, ctx.curdir))
    return True

######################################################
# this is used as a decorator to make functions only
# run once. Based on the idea from
# http://stackoverflow.com/questions/815110/is-there-a-decorator-to-simply-cache-function-return-values
runonce_ret = {}
def runonce(function):
    def wrapper(*args):
        if args in runonce_ret:
            return runonce_ret[args]
        else:
            ret = function(*args)
            runonce_ret[args] = ret
            return ret
    return wrapper



def set_rpath(bld):
    '''setup the default rpath'''
    rpath = os.path.normpath('%s/%s' % (bld.env['BUILD_DIRECTORY'], LIB_PATH))
    bld.env.append_value('RPATH', '-Wl,-rpath=%s' % rpath)
Build.BuildContext.set_rpath = set_rpath

def install_rpath(bld):
    '''the rpath value for installation'''
    if bld.env['RPATH_ON_INSTALL']:
        return ['-Wl,-rpath=%s/lib' % bld.env.PREFIX]
    return []


#############################################################
# return a named build cache dictionary, used to store
# state inside the following functions
@conf
def LOCAL_CACHE(ctx, name):
    if name in ctx.env:
        return ctx.env[name]
    ctx.env[name] = {}
    return ctx.env[name]


#############################################################
# set a value in a local cache
@conf
def LOCAL_CACHE_SET(ctx, cachename, key, value):
    cache = LOCAL_CACHE(ctx, cachename)
    cache[key] = value

#############################################################
# a build assert call
@conf
def ASSERT(ctx, expression, msg):
    if not expression:
        sys.stderr.write("ERROR: %s\n" % msg)
        raise AssertionError
Build.BuildContext.ASSERT = ASSERT

################################################################
# create a list of files by pre-pending each with a subdir name
def SUBDIR(bld, subdir, list):
    ret = ''
    for l in TO_LIST(list):
        ret = ret + os.path.normpath(os.path.join(subdir, l)) + ' '
    return ret
Build.BuildContext.SUBDIR = SUBDIR

#######################################################
# d1 += d2
def dict_concat(d1, d2):
    for t in d2:
        if t not in d1:
            d1[t] = d2[t]

############################################################
# this overrides the 'waf -v' debug output to be in a nice
# unix like format instead of a python list.
# Thanks to ita on #waf for this
def exec_command(self, cmd, **kw):
    import Utils, Logs
    _cmd = cmd
    if isinstance(cmd, list):
        _cmd = ' '.join(cmd)
    debug('runner: %s' % _cmd)
    if self.log:
        self.log.write('%s\n' % cmd)
        kw['log'] = self.log
    try:
        if not kw.get('cwd', None):
            kw['cwd'] = self.cwd
    except AttributeError:
        self.cwd = kw['cwd'] = self.bldnode.abspath()
    return Utils.exec_command(cmd, **kw)
Build.BuildContext.exec_command = exec_command


##########################################################
# add a new top level command to waf
def ADD_COMMAND(opt, name, function):
    Utils.g_module.__dict__[name] = function
    opt.name = function
Options.Handler.ADD_COMMAND = ADD_COMMAND


@feature('cc', 'cshlib', 'cprogram')
@before('apply_core','exec_rule')
def process_depends_on(self):
    '''The new depends_on attribute for build rules
       allow us to specify a dependency on output from
       a source generation rule'''
    if getattr(self , 'depends_on', None):
        lst = self.to_list(self.depends_on)
        for x in lst:
            y = self.bld.name_to_obj(x, self.env)
            self.bld.ASSERT(y is not None, "Failed to find dependency %s of %s" % (x, self.name))
            y.post()
            if getattr(y, 'more_includes', None):
                  self.includes += " " + y.more_includes


#@feature('cprogram', 'cc', 'cshlib')
#@before('apply_core')
#def process_generated_dependencies(self):
#    '''Ensure that any dependent source generation happens
#       before any task that requires the output'''
#    if getattr(self , 'depends_on', None):
#        lst = self.to_list(self.depends_on)
#        for x in lst:
#            y = self.bld.name_to_obj(x, self.env)
#            y.post()


#import TaskGen, Task
#
#old_post_run = Task.Task.post_run
#def new_post_run(self):
#    self.cached = True
#    return old_post_run(self)
#
#for y in ['cc', 'cxx']:
#    TaskGen.classes[y].post_run = new_post_run

def ENABLE_MAGIC_ORDERING(bld):
    '''enable automatic build order constraint calculation
       see page 35 of the waf book'''
    print "NOT Enabling magic ordering"
    #bld.use_the_magic()
Build.BuildContext.ENABLE_MAGIC_ORDERING = ENABLE_MAGIC_ORDERING


os_path_relpath = getattr(os.path, 'relpath', None)
if os_path_relpath is None:
    # Python < 2.6 does not have os.path.relpath, provide a replacement
    # (imported from Python2.6.5~rc2)
    def os_path_relpath(path, start):
        """Return a relative version of a path"""
        start_list = os.path.abspath(start).split("/")
        path_list = os.path.abspath(path).split("/")

        # Work out how much of the filepath is shared by start and path.
        i = len(os.path.commonprefix([start_list, path_list]))

        rel_list = ['..'] * (len(start_list)-i) + path_list[i:]
        if not rel_list:
            return start
        return os.path.join(*rel_list)


# this is a useful way of debugging some of the rules in waf
from TaskGen import feature, after
@feature('dbg')
@after('apply_core', 'apply_obj_vars_cc')
def dbg(self):
	if self.target == 'HEIMDAL_HEIM_ASN1':
		print "@@@@@@@@@@@@@@2", self.includes, self.env._CCINCFLAGS

def unique_list(seq):
    '''return a uniquified list in the same order as the existing list'''
    seen = {}
    result = []
    for item in seq:
        if item in seen: continue
        seen[item] = True
        result.append(item)
    return result

def TO_LIST(str):
    '''Split a list, preserving quoted strings and existing lists'''
    if isinstance(str, list):
        return str
    lst = str.split()
    # the string may have had quotes in it, now we
    # check if we did have quotes, and use the slower shlex
    # if we need to
    for e in lst:
        if e[0] == '"':
            return shlex.split(str)
    return lst

@conf
def SUBST_ENV_VAR(ctx, varname):
    '''Substitute an environment variable for any embedded variables'''
    return Utils.subst_vars(ctx.env[varname], ctx.env)
Build.BuildContext.SUBST_ENV_VAR = SUBST_ENV_VAR


def ENFORCE_GROUP_ORDERING(bld):
    '''enforce group ordering for the project. This
       makes the group ordering apply only when you specify
       a target with --target'''
    if Options.options.compile_targets:
        @feature('*')
        def force_previous_groups(self):
            my_id = id(self)

            bld = self.bld
            stop = None
            for g in bld.task_manager.groups:
                for t in g.tasks_gen:
                    if id(t) == my_id:
                        stop = id(g)
                        break
                if stop is None:
                    return

                for g in bld.task_manager.groups:
                    if id(g) == stop:
                        break
                    for t in g.tasks_gen:
                        t.post()
Build.BuildContext.ENFORCE_GROUP_ORDERING = ENFORCE_GROUP_ORDERING

# @feature('cc')
# @before('apply_lib_vars')
# def process_objects(self):
#     if getattr(self, 'add_objects', None):
#         lst = self.to_list(self.add_objects)
#         for x in lst:
#             y = self.name_to_obj(x)
#             if not y:
#                 raise Utils.WafError('object %r was not found in uselib_local (required by add_objects %r)' % (x, self.name))
#             y.post()
#             self.env.append_unique('INC_PATHS', y.env.INC_PATHS)


def recursive_dirlist(dir, relbase):
    '''recursive directory list'''
    ret = []
    for f in os.listdir(dir):
        f2 = dir + '/' + f
        if os.path.isdir(f2):
            ret.extend(recursive_dirlist(f2, relbase))
        else:
            ret.append(os_path_relpath(f2, relbase))
    return ret


def mkdir_p(dir):
    '''like mkdir -p'''
    if os.path.isdir(dir):
        return
    mkdir_p(os.path.dirname(dir))
    os.mkdir(dir)

# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, sys, Options, Utils, Task, re
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
@conf
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


def GET_TARGET_TYPE(ctx, target):
    '''get target type from cache'''
    cache = LOCAL_CACHE(ctx, 'TARGET_TYPE')
    if not target in cache:
        return None
    return cache[target]


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


def ADD_LD_LIBRARY_PATH(path):
    '''add something to LD_LIBRARY_PATH'''
    if 'LD_LIBRARY_PATH' in os.environ:
        oldpath = os.environ['LD_LIBRARY_PATH']
    else:
        oldpath = ''
    newpath = oldpath.split(':')
    if not path in newpath:
        newpath.append(path)
        os.environ['LD_LIBRARY_PATH'] = ':'.join(newpath)

def install_rpath(bld):
    '''the rpath value for installation'''
    bld.env['RPATH'] = []
    bld.env['RPATH_ST'] = []
    if bld.env.RPATH_ON_INSTALL:
        return ['-Wl,-rpath=%s/lib' % bld.env.PREFIX]
    return []


def build_rpath(bld):
    '''the rpath value for build'''
    rpath = os.path.normpath('%s/%s' % (bld.env['BUILD_DIRECTORY'], LIB_PATH))
    bld.env['RPATH'] = []
    bld.env['RPATH_ST'] = []
    if bld.env.RPATH_ON_BUILD:
        return ['-Wl,-rpath=%s' % rpath]
    ADD_LD_LIBRARY_PATH(rpath)
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
    if str is None:
        return []
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


def subst_vars_error(string, env):
    '''substitute vars, throw an error if a variable is not defined'''
    lst = re.split('(\$\{\w+\})', string)
    out = []
    for v in lst:
        if re.match('\$\{\w+\}', v):
            vname = v[2:-1]
            if not vname in env:
                print "Failed to find variable %s in %s" % (vname, string)
                raise
            v = env[vname]
        out.append(v)
    return ''.join(out)

@conf
def SUBST_ENV_VAR(ctx, varname):
    '''Substitute an environment variable for any embedded variables'''
    return subst_vars_error(ctx.env[varname], ctx.env)
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

def SUBST_VARS_RECURSIVE(string, env):
    '''recursively expand variables'''
    if string is None:
        return string
    limit=100
    while (string.find('${') != -1 and limit > 0):
        string = subst_vars_error(string, env)
        limit -= 1
    return string

@conf
def EXPAND_VARIABLES(ctx, varstr, vars=None):
    '''expand variables from a user supplied dictionary

    This is most useful when you pass vars=locals() to expand
    all your local variables in strings
    '''

    if isinstance(varstr, list):
        ret = []
        for s in varstr:
            ret.append(EXPAND_VARIABLES(ctx, s, vars=vars))
        return ret

    import Environment
    env = Environment.Environment()
    ret = varstr
    # substitute on user supplied dict if avaiilable
    if vars is not None:
        for v in vars.keys():
            env[v] = vars[v]
        ret = SUBST_VARS_RECURSIVE(ret, env)

    # if anything left, subst on the environment as well
    if ret.find('${') != -1:
        ret = SUBST_VARS_RECURSIVE(ret, ctx.env)
    # make sure there is nothing left. Also check for the common
    # typo of $( instead of ${
    if ret.find('${') != -1 or ret.find('$(') != -1:
        print('Failed to substitute all variables in varstr=%s' % ret)
        raise
    return ret
Build.BuildContext.EXPAND_VARIABLES = EXPAND_VARIABLES


def RUN_COMMAND(cmd,
                env=None,
                shell=False):
    '''run a external command, return exit code or signal'''
    if env:
        cmd = SUBST_VARS_RECURSIVE(cmd, env)

    status = os.system(cmd)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return - os.WTERMSIG(status)
    print "Unknown exit reason %d for command: %s" (status, cmd)
    return -1


# make sure we have md5. some systems don't have it
try:
    from hashlib import md5
except:
    try:
        import md5
    except:
        import Constants
        Constants.SIG_NIL = hash('abcd')
        class replace_md5(object):
            def __init__(self):
                self.val = None
            def update(self, val):
                self.val = hash((self.val, val))
            def digest(self):
                return str(self.val)
            def hexdigest(self):
                return self.digest().encode('hex')
        def replace_h_file(filename):
            f = open(filename, 'rb')
            m = replace_md5()
            while (filename):
                filename = f.read(100000)
                m.update(filename)
            f.close()
            return m.digest()
        Utils.md5 = replace_md5
        Task.md5 = replace_md5
        Utils.h_file = replace_h_file


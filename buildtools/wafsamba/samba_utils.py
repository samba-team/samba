# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Logs, sys, Configure, Options, string, Task, Utils, optparse
from TaskGen import feature, before
from Configure import conf
from Logs import debug
from TaskGen import extension
import shlex

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
    assumed = LOCAL_CACHE(ctx, 'ASSUMED_TARGET')
    if target in assumed:
        #if assumed[target] != value:
        #    print "Target '%s' was assumed of type '%s' but is '%s'" % (target, assumed[target], value)
        ASSERT(ctx, assumed[target] == value,
               "Target '%s' was assumed of type '%s' but is '%s'" % (target, assumed[target], value))
    predeclared = LOCAL_CACHE(ctx, 'PREDECLARED_TARGET')
    if target in predeclared:
        ASSERT(ctx, predeclared[target] == value,
               "Target '%s' was predeclared of type '%s' but is '%s'" % (target, predeclared[target], value))
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



################################################################
# magic rpath handling
#
# we want a different rpath when installing and when building
# Note that this should really check if rpath is available on this platform
# and it should also honor an --enable-rpath option
def set_rpath(bld):
    if Options.is_install:
        if bld.env['RPATH_ON_INSTALL']:
            bld.env['RPATH'] = ['-Wl,-rpath=%s/lib' % bld.env.PREFIX]
        else:
            bld.env['RPATH'] = []
    else:
        rpath = os.path.normpath('%s/%s' % (bld.env['BUILD_DIRECTORY'], LIB_PATH))
        bld.env.append_value('RPATH', '-Wl,-rpath=%s' % rpath)
Build.BuildContext.set_rpath = set_rpath


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
    for l in to_list(list):
        ret = ret + subdir + '/' + l + ' '
    return ret
Build.BuildContext.SUBDIR = SUBDIR

##############################################
# remove .. elements from a path list
def NORMPATH(bld, ilist):
    return " ".join([os.path.normpath(p) for p in to_list(ilist)])
Build.BuildContext.NORMPATH = NORMPATH

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


@feature('*')
@before('apply_core','exec_rule')
def process_depends_on(self):
    '''The new depends_on attribute for build rules
       allow us to specify a dependency on output from
       a source generation rule'''
    if getattr(self , 'depends_on', None):
        lst = self.to_list(self.depends_on)
        for x in lst:
            y = self.bld.name_to_obj(x, self.env)
            y.post()

            if getattr(y, 'more_includes', None):
                  self.includes += " " + y.more_includes


#@feature('cprogram cc cshlib')
#@before('apply_core')
#def process_generated_dependencies(self):
#    '''Ensure that any dependent source generation happens
#       before any task that requires the output'''
#    if getattr(self , 'depends_on', None):
#        lst = self.to_list(self.depends_on)
#        for x in lst:
#            y = self.bld.name_to_obj(x, self.env)
#            y.post()


def FIND_TASKGEN(bld, name):
    '''find a waf task generator given a target name'''
    return bld.name_to_obj(name)
Build.BuildContext.FIND_TASKGEN = FIND_TASKGEN


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


def BUILD_PATH(bld, relpath):
    '''return a relative build path, given a relative path
       for example, if called in the source4/librpc directory, with the path
       gen_ndr/tables.c, then it will return default/source4/gen_ndr/tables.c
    '''

    ret = os.path.normpath(os.path.join(os.path.relpath(bld.curdir, bld.env.TOPDIR), relpath))
    ret = 'default/%s' % ret
    return ret
Build.BuildContext.BUILD_PATH = BUILD_PATH


# this is a useful way of debugging some of the rules in waf
from TaskGen import feature, after
@feature('dbg')
@after('apply_core', 'apply_obj_vars_cc')
def dbg(self):
	if self.target == 'HEIMDAL_HEIM_ASN1':
		print "@@@@@@@@@@@@@@2", self.includes, self.env._CCINCFLAGS


def to_list(str):
    '''Split a list, preserving quoted strings and existing lists'''
    if isinstance(str, list):
        return str
    return shlex.split(str)

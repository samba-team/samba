# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import Build, os, Logs, sys, Configure, Options, string, Task, Utils, optparse
from Configure import conf
from Logs import debug
from TaskGen import extension

LIB_PATH="shared"

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
    for l in list.split():
        ret = ret + subdir + '/' + l + ' '
    return ret
Build.BuildContext.SUBDIR = SUBDIR

##############################################
# remove .. elements from a path list
def NORMPATH(bld, ilist):
    return " ".join([os.path.normpath(p) for p in ilist.split(" ")])
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


#import TaskGen, Task
#
#old_post_run = Task.Task.post_run
#def new_post_run(self):
#    self.cached = True
#    return old_post_run(self)
#
#for y in ['cc', 'cxx']:
#    TaskGen.classes[y].post_run = new_post_run

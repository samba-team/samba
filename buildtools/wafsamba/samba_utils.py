# a waf tool to add autoconf-like macros to the configure section
# and for SAMBA_ macros for building libraries, binaries etc

import errno
import os, sys, re, fnmatch, shlex, inspect
from optparse import SUPPRESS_HELP
from waflib import Build, Options, Utils, Task, Logs, Configure, Errors, Context
from waflib import Scripting
from waflib.TaskGen import feature, before, after
from waflib.Configure import ConfigurationContext
from waflib.Logs import debug
from waflib import ConfigSet
from waflib.Build import CACHE_SUFFIX

# TODO: make this a --option
LIB_PATH="shared"


PY3 = sys.version_info[0] == 3

if PY3:

    # helper function to get a string from a variable that maybe 'str' or
    # 'bytes' if 'bytes' then it is decoded using 'utf8'. If 'str' is passed
    # it is returned unchanged
    # Using this function is PY2/PY3 code should ensure in most cases
    # the PY2 code runs unchanged in PY2 whereas the code in PY3 possibly
    # decodes the variable (see PY2 implementation of this function below)
    def get_string(bytesorstring):
        tmp = bytesorstring
        if isinstance(bytesorstring, bytes):
            tmp = bytesorstring.decode('utf8')
        elif not isinstance(bytesorstring, str):
            raise ValueError('Expected byte of string for %s:%s' % (type(bytesorstring), bytesorstring))
        return tmp

else:

    # Helper function to return string.
    # if 'str' or 'unicode' passed in they are returned unchanged
    # otherwise an exception is generated
    # Using this function is PY2/PY3 code should ensure in most cases
    # the PY2 code runs unchanged in PY2 whereas the code in PY3 possibly
    # decodes the variable (see PY3 implementation of this function above)
    def get_string(bytesorstring):
        tmp = bytesorstring
        if not(isinstance(bytesorstring, str) or isinstance(bytesorstring, unicode)):
            raise ValueError('Expected str or unicode for %s:%s' % (type(bytesorstring), bytesorstring))
        return tmp

# sigh, python octal constants are a mess
MODE_644 = int('644', 8)
MODE_744 = int('744', 8)
MODE_755 = int('755', 8)
MODE_777 = int('777', 8)

def conf(f):
    # override in order to propagate the argument "mandatory"
    def fun(*k, **kw):
        mandatory = True
        if 'mandatory' in kw:
            mandatory = kw['mandatory']
            del kw['mandatory']

        try:
            return f(*k, **kw)
        except Errors.ConfigurationError:
            if mandatory:
                raise

    fun.__name__ = f.__name__
    if 'mandatory' in inspect.getsource(f):
        fun = f

    setattr(Configure.ConfigurationContext, f.__name__, fun)
    setattr(Build.BuildContext, f.__name__, fun)
    return f
Configure.conf = conf
Configure.conftest = conf

@conf
def SET_TARGET_TYPE(ctx, target, value):
    '''set the target type of a target'''
    cache = LOCAL_CACHE(ctx, 'TARGET_TYPE')
    if target in cache and cache[target] != 'EMPTY':
        Logs.error("ERROR: Target '%s' in directory %s re-defined as %s - was %s" % (target, ctx.path.abspath(), value, cache[target]))
        sys.exit(1)
    LOCAL_CACHE_SET(ctx, 'TARGET_TYPE', target, value)
    debug("task_gen: Target '%s' created of type '%s' in %s" % (target, value, ctx.path.abspath()))
    return True


def GET_TARGET_TYPE(ctx, target):
    '''get target type from cache'''
    cache = LOCAL_CACHE(ctx, 'TARGET_TYPE')
    if not target in cache:
        return None
    return cache[target]


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


def needs_private_lib(bld, target):
    '''return True if a target links to a private library'''
    for lib in getattr(target, "final_libs", []):
        t = bld.get_tgen_by_name(lib)
        if t and getattr(t, 'private_library', False):
            return True
    return False


def install_rpath(target):
    '''the rpath value for installation'''
    bld = target.bld
    bld.env['RPATH'] = []
    ret = set()
    if bld.env.RPATH_ON_INSTALL:
        ret.add(bld.EXPAND_VARIABLES(bld.env.LIBDIR))
    if bld.env.RPATH_ON_INSTALL_PRIVATE and needs_private_lib(bld, target):
        ret.add(bld.EXPAND_VARIABLES(bld.env.PRIVATELIBDIR))
    return list(ret)


def build_rpath(bld):
    '''the rpath value for build'''
    rpaths = [os.path.normpath('%s/%s' % (bld.env.BUILD_DIRECTORY, d)) for d in ("shared", "shared/private")]
    bld.env['RPATH'] = []
    if bld.env.RPATH_ON_BUILD:
        return rpaths
    for rpath in rpaths:
        ADD_LD_LIBRARY_PATH(rpath)
    return []


@conf
def LOCAL_CACHE(ctx, name):
    '''return a named build cache dictionary, used to store
       state inside other functions'''
    if name in ctx.env:
        return ctx.env[name]
    ctx.env[name] = {}
    return ctx.env[name]


@conf
def LOCAL_CACHE_SET(ctx, cachename, key, value):
    '''set a value in a local cache'''
    cache = LOCAL_CACHE(ctx, cachename)
    cache[key] = value


@conf
def ASSERT(ctx, expression, msg):
    '''a build assert call'''
    if not expression:
        raise Errors.WafError("ERROR: %s\n" % msg)
Build.BuildContext.ASSERT = ASSERT


def SUBDIR(bld, subdir, list):
    '''create a list of files by pre-pending each with a subdir name'''
    ret = ''
    for l in TO_LIST(list):
        ret = ret + os.path.normpath(os.path.join(subdir, l)) + ' '
    return ret
Build.BuildContext.SUBDIR = SUBDIR


def dict_concat(d1, d2):
    '''concatenate two dictionaries d1 += d2'''
    for t in d2:
        if t not in d1:
            d1[t] = d2[t]

def ADD_COMMAND(opt, name, function):
    '''add a new top level command to waf'''
    Context.g_module.__dict__[name] = function
    opt.name = function
Options.OptionsContext.ADD_COMMAND = ADD_COMMAND


@feature('c', 'cc', 'cshlib', 'cprogram')
@before('apply_core','exec_rule')
def process_depends_on(self):
    '''The new depends_on attribute for build rules
       allow us to specify a dependency on output from
       a source generation rule'''
    if getattr(self , 'depends_on', None):
        lst = self.to_list(self.depends_on)
        for x in lst:
            y = self.bld.get_tgen_by_name(x)
            self.bld.ASSERT(y is not None, "Failed to find dependency %s of %s" % (x, self.name))
            y.post()
            if getattr(y, 'more_includes', None):
                  self.includes += " " + y.more_includes


def unique_list(seq):
    '''return a uniquified list in the same order as the existing list'''
    seen = {}
    result = []
    for item in seq:
        if item in seen: continue
        seen[item] = True
        result.append(item)
    return result


def TO_LIST(str, delimiter=None):
    '''Split a list, preserving quoted strings and existing lists'''
    if str is None:
        return []
    if isinstance(str, list):
        # we need to return a new independent list...
        return list(str)
    if len(str) == 0:
        return []
    lst = str.split(delimiter)
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
                raise KeyError("Failed to find variable %s in %s in env %s <%s>" % (vname, string, env.__class__, str(env)))
            v = env[vname]
            if isinstance(v, list):
                v = ' '.join(v)
        out.append(v)
    return ''.join(out)


@conf
def SUBST_ENV_VAR(ctx, varname):
    '''Substitute an environment variable for any embedded variables'''
    return subst_vars_error(ctx.env[varname], ctx.env)
Build.BuildContext.SUBST_ENV_VAR = SUBST_ENV_VAR


def recursive_dirlist(dir, relbase, pattern=None):
    '''recursive directory list'''
    ret = []
    for f in os.listdir(dir):
        f2 = dir + '/' + f
        if os.path.isdir(f2):
            ret.extend(recursive_dirlist(f2, relbase))
        else:
            if pattern and not fnmatch.fnmatch(f, pattern):
                continue
            ret.append(os.path.relpath(f2, relbase))
    return ret


def symlink(src, dst, force=True):
    """Can create symlink by force"""
    try:
        os.symlink(src, dst)
    except OSError as exc:
        if exc.errno == errno.EEXIST and force:
            os.remove(dst)
            os.symlink(src, dst)
        else:
            raise


def mkdir_p(dir):
    '''like mkdir -p'''
    if not dir:
        return
    if dir.endswith("/"):
        mkdir_p(dir[:-1])
        return
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

    if not isinstance(varstr, str):
        return varstr

    env = ConfigSet.ConfigSet()
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
        Logs.error('Failed to substitute all variables in varstr=%s' % ret)
        sys.exit(1)
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
    Logs.error("Unknown exit reason %d for command: %s" % (status, cmd))
    return -1


def RUN_PYTHON_TESTS(testfiles, pythonpath=None, extra_env=None):
    env = LOAD_ENVIRONMENT()
    if pythonpath is None:
        pythonpath = os.path.join(Context.g_module.out, 'python')
    result = 0
    for interp in env.python_interpreters:
        if not isinstance(interp, str):
            interp = ' '.join(interp)
        for testfile in testfiles:
            cmd = "PYTHONPATH=%s %s %s" % (pythonpath, interp, testfile)
            if extra_env:
                for key, value in extra_env.items():
                    cmd = "%s=%s %s" % (key, value, cmd)
            print('Running Python test with %s: %s' % (interp, testfile))
            ret = RUN_COMMAND(cmd)
            if ret:
                print('Python test failed: %s' % cmd)
                result = ret
    return result


# make sure we have md5. some systems don't have it
try:
    from hashlib import md5
    # Even if hashlib.md5 exists, it may be unusable.
    # Try to use MD5 function. In FIPS mode this will cause an exception
    # and we'll get to the replacement code
    foo = md5(b'abcd')
except:
    try:
        import md5
        # repeat the same check here, mere success of import is not enough.
        # Try to use MD5 function. In FIPS mode this will cause an exception
        foo = md5.md5(b'abcd')
    except:
        Context.SIG_NIL = hash('abcd')
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


def LOAD_ENVIRONMENT():
    '''load the configuration environment, allowing access to env vars
       from new commands'''
    env = ConfigSet.ConfigSet()
    try:
        p = os.path.join(Context.g_module.out, 'c4che/default'+CACHE_SUFFIX)
        env.load(p)
    except (OSError, IOError):
        pass
    return env


def IS_NEWER(bld, file1, file2):
    '''return True if file1 is newer than file2'''
    curdir = bld.path.abspath()
    t1 = os.stat(os.path.join(curdir, file1)).st_mtime
    t2 = os.stat(os.path.join(curdir, file2)).st_mtime
    return t1 > t2
Build.BuildContext.IS_NEWER = IS_NEWER


@conf
def RECURSE(ctx, directory):
    '''recurse into a directory, relative to the curdir or top level'''
    try:
        visited_dirs = ctx.visited_dirs
    except AttributeError:
        visited_dirs = ctx.visited_dirs = set()
    d = os.path.join(ctx.path.abspath(), directory)
    if os.path.exists(d):
        abspath = os.path.abspath(d)
    else:
        abspath = os.path.abspath(os.path.join(Context.g_module.top, directory))
    ctxclass = ctx.__class__.__name__
    key = ctxclass + ':' + abspath
    if key in visited_dirs:
        # already done it
        return
    visited_dirs.add(key)
    relpath = os.path.relpath(abspath, ctx.path.abspath())
    if ctxclass in ['tmp', 'OptionsContext', 'ConfigurationContext', 'BuildContext']:
        return ctx.recurse(relpath)
    if 'waflib.extras.compat15' in sys.modules:
        return ctx.recurse(relpath)
    Logs.error('Unknown RECURSE context class: {}'.format(ctxclass))
    raise
Options.OptionsContext.RECURSE = RECURSE
Build.BuildContext.RECURSE = RECURSE


def CHECK_MAKEFLAGS(options):
    '''check for MAKEFLAGS environment variable in case we are being
    called from a Makefile try to honor a few make command line flags'''
    if not 'WAF_MAKE' in os.environ:
        return
    makeflags = os.environ.get('MAKEFLAGS')
    if makeflags is None:
        makeflags = ""
    jobs_set = False
    jobs = None
    # we need to use shlex.split to cope with the escaping of spaces
    # in makeflags
    for opt in shlex.split(makeflags):
        # options can come either as -x or as x
        if opt[0:2] == 'V=':
            options.verbose = Logs.verbose = int(opt[2:])
            if Logs.verbose > 0:
                Logs.zones = ['runner']
            if Logs.verbose > 2:
                Logs.zones = ['*']
        elif opt[0].isupper() and opt.find('=') != -1:
            # this allows us to set waf options on the make command line
            # for example, if you do "make FOO=blah", then we set the
            # option 'FOO' in Options.options, to blah. If you look in wafsamba/wscript
            # you will see that the command line accessible options have their dest=
            # set to uppercase, to allow for passing of options from make in this way
            # this is also how "make test TESTS=testpattern" works, and
            # "make VERBOSE=1" as well as things like "make SYMBOLCHECK=1"
            loc = opt.find('=')
            setattr(options, opt[0:loc], opt[loc+1:])
        elif opt[0] != '-':
            for v in opt:
                if re.search(r'j[0-9]*$', v):
                    jobs_set = True
                    jobs = opt.strip('j')
                elif v == 'k':
                    options.keep = True
        elif re.search(r'-j[0-9]*$', opt):
            jobs_set = True
            jobs = opt.strip('-j')
        elif opt == '-k':
            options.keep = True
    if not jobs_set:
        # default to one job
        options.jobs = 1
    elif jobs_set and jobs:
        options.jobs = int(jobs)

waflib_options_parse_cmd_args = Options.OptionsContext.parse_cmd_args
def wafsamba_options_parse_cmd_args(self, _args=None, cwd=None, allow_unknown=False):
    (options, commands, envvars) = \
        waflib_options_parse_cmd_args(self,
                                      _args=_args,
                                      cwd=cwd,
                                      allow_unknown=allow_unknown)
    CHECK_MAKEFLAGS(options)
    if options.jobs == 1:
        #
        # waflib.Runner.Parallel processes jobs inline if the possible number
        # of jobs is just 1. But (at least in waf <= 2.0.12) it still calls
        # create a waflib.Runner.Spawner() which creates a single
        # waflib.Runner.Consumer() thread that tries to process jobs from the
        # queue.
        #
        # This has strange effects, which are not noticed typically,
        # but at least on AIX python has broken threading and fails
        # in random ways.
        #
        # So we just add a dummy Spawner class.
        class NoOpSpawner(object):
            def __init__(self, master):
                return
        from waflib import Runner
        Runner.Spawner = NoOpSpawner
    return options, commands, envvars
Options.OptionsContext.parse_cmd_args = wafsamba_options_parse_cmd_args

option_groups = {}

def option_group(opt, name):
    '''find or create an option group'''
    global option_groups
    if name in option_groups:
        return option_groups[name]
    gr = opt.add_option_group(name)
    option_groups[name] = gr
    return gr
Options.OptionsContext.option_group = option_group


def save_file(filename, contents, create_dir=False):
    '''save data to a file'''
    if create_dir:
        mkdir_p(os.path.dirname(filename))
    try:
        f = open(filename, 'w')
        f.write(contents)
        f.close()
    except:
        return False
    return True


def load_file(filename):
    '''return contents of a file'''
    try:
        f = open(filename, 'r')
        r = f.read()
        f.close()
    except:
        return None
    return r


def reconfigure(ctx):
    '''rerun configure if necessary'''
    if not os.path.exists(os.environ.get('WAFLOCK', '.lock-wscript')):
        raise Errors.WafError('configure has not been run')
    import samba_wildcard
    bld = samba_wildcard.fake_build_environment()
    Configure.autoconfig = True
    Scripting.check_configured(bld)


def map_shlib_extension(ctx, name, python=False):
    '''map a filename with a shared library extension of .so to the real shlib name'''
    if name is None:
        return None
    if name[-1:].isdigit():
        # some libraries have specified versions in the wscript rule
        return name
    (root1, ext1) = os.path.splitext(name)
    if python:
        return ctx.env.pyext_PATTERN % root1
    else:
        (root2, ext2) = os.path.splitext(ctx.env.cshlib_PATTERN)
    return root1+ext2
Build.BuildContext.map_shlib_extension = map_shlib_extension

def apply_pattern(filename, pattern):
    '''apply a filename pattern to a filename that may have a directory component'''
    dirname = os.path.dirname(filename)
    if not dirname:
        return pattern % filename
    basename = os.path.basename(filename)
    return os.path.join(dirname, pattern % basename)

def make_libname(ctx, name, nolibprefix=False, version=None, python=False):
    """make a library filename
         Options:
              nolibprefix: don't include the lib prefix
              version    : add a version number
              python     : if we should use python module name conventions"""

    if python:
        libname = apply_pattern(name, ctx.env.pyext_PATTERN)
    else:
        libname = apply_pattern(name, ctx.env.cshlib_PATTERN)
    if nolibprefix and libname[0:3] == 'lib':
        libname = libname[3:]
    if version:
        if version[0] == '.':
            version = version[1:]
        (root, ext) = os.path.splitext(libname)
        if ext == ".dylib":
            # special case - version goes before the prefix
            libname = "%s.%s%s" % (root, version, ext)
        else:
            libname = "%s%s.%s" % (root, ext, version)
    return libname
Build.BuildContext.make_libname = make_libname


def get_tgt_list(bld):
    '''return a list of build objects for samba'''

    targets = LOCAL_CACHE(bld, 'TARGET_TYPE')

    # build a list of task generators we are interested in
    tgt_list = []
    for tgt in targets:
        type = targets[tgt]
        if not type in ['SUBSYSTEM', 'MODULE', 'BINARY', 'LIBRARY', 'ASN1', 'PYTHON']:
            continue
        t = bld.get_tgen_by_name(tgt)
        if t is None:
            Logs.error("Target %s of type %s has no task generator" % (tgt, type))
            sys.exit(1)
        tgt_list.append(t)
    return tgt_list

from waflib.Context import WSCRIPT_FILE
def PROCESS_SEPARATE_RULE(self, rule):
    ''' cause waf to process additional script based on `rule'.
        You should have file named wscript_<stage>_rule in the current directory
        where stage is either 'configure' or 'build'
    '''
    stage = ''
    if isinstance(self, Configure.ConfigurationContext):
        stage = 'configure'
    elif isinstance(self, Build.BuildContext):
        stage = 'build'
    file_path = os.path.join(self.path.abspath(), WSCRIPT_FILE+'_'+stage+'_'+rule)
    node = self.root.find_node(file_path)
    if node:
        try:
            cache = self.recurse_cache
        except AttributeError:
            cache = self.recurse_cache = {}
        if node not in cache:
            cache[node] = True
            self.pre_recurse(node)
            try:
                function_code = node.read('r', None)
                exec(compile(function_code, node.abspath(), 'exec'), self.exec_dict)
            finally:
                self.post_recurse(node)

Build.BuildContext.PROCESS_SEPARATE_RULE = PROCESS_SEPARATE_RULE
ConfigurationContext.PROCESS_SEPARATE_RULE = PROCESS_SEPARATE_RULE

def AD_DC_BUILD_IS_ENABLED(self):
    if self.CONFIG_SET('AD_DC_BUILD_IS_ENABLED'):
        return True
    return False

Build.BuildContext.AD_DC_BUILD_IS_ENABLED = AD_DC_BUILD_IS_ENABLED

@feature('cprogram', 'cshlib', 'cstaticlib')
@after('apply_lib_vars')
@before('apply_obj_vars')
def samba_before_apply_obj_vars(self):
    """before apply_obj_vars for uselib, this removes the standard paths"""

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

def samba_add_onoff_option(opt, option, help=(), dest=None, default=True,
                           with_name="with", without_name="without"):
    if default is None:
        default_str = "auto"
    elif default is True:
        default_str = "yes"
    elif default is False:
        default_str = "no"
    else:
        default_str = str(default)

    if help == ():
        help = ("Build with %s support (default=%s)" % (option, default_str))
    if dest is None:
        dest = "with_%s" % option.replace('-', '_')

    with_val = "--%s-%s" % (with_name, option)
    without_val = "--%s-%s" % (without_name, option)

    opt.add_option(with_val, help=help, action="store_true", dest=dest,
                   default=default)
    opt.add_option(without_val, help=SUPPRESS_HELP, action="store_false",
                   dest=dest)
Options.OptionsContext.samba_add_onoff_option = samba_add_onoff_option

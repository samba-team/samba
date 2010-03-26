# a set of config tests that use the samba_autoconf functions
# to test for commonly needed configuration options
import os, Build, shutil, Utils
from Configure import conf

@conf
def CHECK_ICONV(conf, define='HAVE_NATIVE_ICONV'):
    '''check if the iconv library is installed
       optionally pass a define'''
    if conf.CHECK_FUNCS_IN('iconv_open', 'iconv', checklibc=True, headers='iconv.h'):
        conf.DEFINE(define, 1)
        return True
    return False


@conf
def CHECK_LARGEFILE(conf, define='HAVE_LARGEFILE'):
    '''see what we need for largefile support'''
    if conf.CHECK_CODE('return !(sizeof(off_t) >= 8)',
                       define,
                       execute=True,
                       msg='Checking for large file support'):
        return True
    if conf.CHECK_CODE('return !(sizeof(off_t) >= 8)',
                       define,
                       execute=True,
                       cflags='-D_FILE_OFFSET_BITS=64',
                       msg='Checking for -D_FILE_OFFSET_BITS=64'):
        conf.DEFINE('_FILE_OFFSET_BITS', 64)
        return True
    return False


@conf
def CHECK_C_PROTOTYPE(conf, function, prototype, define, headers=None):
    '''verify that a C prototype matches the one on the current system'''
    if not conf.CHECK_DECLS(function, headers=headers):
        return False
    return conf.CHECK_CODE('%s; void *_x = (void *)%s' % (prototype, function),
                           define=define,
                           local_include=False,
                           headers=headers,
                           msg='Checking C prototype for %s' % function)


@conf
def CHECK_CHARSET_EXISTS(conf, charset, outcharset='UCS2-LE', libs=None, headers=None, define=None):
    '''check that a named charset is able to be used with iconv_open() for conversion
    to a target charset
    '''
    msg = 'Checking if can we convert from %s to %s' % (charset, outcharset)
    if define is None:
        define = 'HAVE_CHARSET_%s' % charset.upper().replace('-','_')
    return conf.CHECK_CODE('''
                           iconv_t cd = iconv_open("%s", "%s");
                           if (cd == 0 || cd == (iconv_t)-1) {
                             return -1;
                             }
                             return 0;
                             ''' % (charset, outcharset),
                           define=define,
                           execute=True,
                           libs=libs,
                           msg=msg,
                           headers=headers)



# this one is quite complex, and should probably be broken up
# into several parts. I'd quite like to create a set of CHECK_COMPOUND()
# functions that make writing complex compound tests like this much easier
@conf
def CHECK_RPATH_SUPPORT(conf):
    '''see if the platform supports rpath for libraries'''
    k = 0
    while k < 10000:
        dir = os.path.join(conf.blddir, '.conf_check_%d' % k)
        try:
            shutil.rmtree(dir)
        except OSError:
            pass
        try:
            os.stat(dir)
        except:
            break
        k += 1

    try:
        os.makedirs(dir)
    except:
        conf.fatal('cannot create a configuration test folder %r' % dir)

    try:
        os.stat(dir)
    except:
        conf.fatal('cannot use the configuration test folder %r' % dir)

    bdir = os.path.join(dir, 'testbuild')
    if not os.path.exists(bdir):
        os.makedirs(bdir)

    env = conf.env

    subdir = os.path.join(dir, "libdir")

    os.makedirs(subdir)

    dest = open(os.path.join(subdir, 'lib1.c'), 'w')
    dest.write('int lib_func(void) { return 42; }\n')
    dest.close()

    dest = open(os.path.join(dir, 'main.c'), 'w')
    dest.write('int main(void) {return !(lib_func() == 42);}\n')
    dest.close()

    back = os.path.abspath('.')

    bld = Build.BuildContext()
    bld.log = conf.log
    bld.all_envs.update(conf.all_envs)
    bld.all_envs['default'] = env
    bld.lst_variants = bld.all_envs.keys()
    bld.load_dirs(dir, bdir)

    os.chdir(dir)

    bld.rescan(bld.srcnode)

    bld(features='cc cshlib',
        source='libdir/lib1.c',
        target='libdir/lib1',
        name='lib1')

    o = bld(features='cc cprogram',
            source='main.c',
            target='prog1',
            uselib_local='lib1',
            rpath=os.path.join(bdir, 'default/libdir'))

    # compile the program
    try:
        bld.compile()
    except:
        conf.check_message('rpath support', '', False)
        return False

    # chdir before returning
    os.chdir(back)

    # path for execution
    lastprog = o.link_task.outputs[0].abspath(env)

    # we need to run the program, try to get its result
    args = []
    proc = Utils.pproc.Popen([lastprog] + args, stdout=Utils.pproc.PIPE, stderr=Utils.pproc.PIPE)
    (out, err) = proc.communicate()
    w = conf.log.write
    w(str(out))
    w('\n')
    w(str(err))
    w('\nreturncode %r\n' % proc.returncode)
    ret = (proc.returncode == 0)

    conf.check_message('rpath support', '', ret)
    return ret

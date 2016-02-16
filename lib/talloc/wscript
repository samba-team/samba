#!/usr/bin/env python

APPNAME = 'talloc'
VERSION = '2.1.6'


blddir = 'bin'

import Logs
import os, sys

# find the buildtools directory
srcdir = '.'
while not os.path.exists(srcdir+'/buildtools') and len(srcdir.split('/')) < 5:
    srcdir = srcdir + '/..'
sys.path.insert(0, srcdir + '/buildtools/wafsamba')

import sys
sys.path.insert(0, srcdir+"/buildtools/wafsamba")
import wafsamba, samba_dist, Options

# setup what directories to put in a tarball
samba_dist.DIST_DIRS("""lib/talloc:. lib/replace:lib/replace
buildtools:buildtools third_party/waf:third_party/waf""")


def set_options(opt):
    opt.BUILTIN_DEFAULT('replace')
    opt.PRIVATE_EXTENSION_DEFAULT('talloc', noextension='talloc')
    opt.RECURSE('lib/replace')
    if opt.IN_LAUNCH_DIR():
        opt.add_option('--enable-talloc-compat1',
                       help=("Build talloc 1.x.x compat library [False]"),
                       action="store_true", dest='TALLOC_COMPAT1', default=False)
        opt.add_option('--disable-python',
                       help=("disable the pytalloc module"),
                       action="store_true", dest='disable_python', default=False)


def configure(conf):
    conf.RECURSE('lib/replace')

    conf.env.standalone_talloc = conf.IN_LAUNCH_DIR()

    conf.env.disable_python = getattr(Options.options, 'disable_python', False)

    if not conf.env.standalone_talloc:
        if conf.CHECK_BUNDLED_SYSTEM_PKG('talloc', minversion=VERSION,
                                     implied_deps='replace'):
            conf.define('USING_SYSTEM_TALLOC', 1)
        if conf.CHECK_BUNDLED_SYSTEM_PKG('pytalloc-util', minversion=VERSION,
                                     implied_deps='talloc replace'):
            conf.define('USING_SYSTEM_PYTALLOC_UTIL', 1)

    conf.env.TALLOC_COMPAT1 = False
    if conf.env.standalone_talloc:
        conf.env.TALLOC_COMPAT1 = Options.options.TALLOC_COMPAT1

    conf.CHECK_XSLTPROC_MANPAGES()

    if not conf.env.disable_python:
        # also disable if we don't have the python libs installed
        conf.SAMBA_CHECK_PYTHON(mandatory=False, version=(2,4,2))
        conf.SAMBA_CHECK_PYTHON_HEADERS(mandatory=False)
        if not conf.env.HAVE_PYTHON_H:
            Logs.warn('Disabling pytalloc-util as python devel libs not found')
            conf.env.disable_python = True

    conf.CHECK_HEADERS('sys/auxv.h')
    conf.CHECK_FUNCS('getauxval')

    conf.SAMBA_CONFIG_H()

    conf.SAMBA_CHECK_UNDEFINED_SYMBOL_FLAGS()


def build(bld):
    bld.RECURSE('lib/replace')

    if bld.env.standalone_talloc:
        bld.env.PKGCONFIGDIR = '${LIBDIR}/pkgconfig'
        bld.env.TALLOC_VERSION = VERSION
        private_library = False

        # should we also install the symlink to libtalloc1.so here?
        bld.SAMBA_LIBRARY('talloc-compat1-%s' % (VERSION),
                          'compat/talloc_compat1.c',
                          public_deps='talloc',
                          soname='libtalloc.so.1',
                          pc_files=[],
                          public_headers=[],
                          enabled=bld.env.TALLOC_COMPAT1)

        testsuite_deps = 'talloc'
        if bld.CONFIG_SET('HAVE_PTHREAD'):
            testsuite_deps += ' pthread'

        bld.SAMBA_BINARY('talloc_testsuite',
                         'testsuite_main.c testsuite.c',
                         testsuite_deps,
                         install=False)

        bld.SAMBA_BINARY('talloc_test_magic_differs_helper',
                         'test_magic_differs_helper.c',
                         'talloc', install=False)

    else:
        private_library = True

    if not bld.CONFIG_SET('USING_SYSTEM_TALLOC'):

        bld.SAMBA_LIBRARY('talloc',
                          'talloc.c',
                          deps='replace',
                          abi_directory='ABI',
                          abi_match='talloc* _talloc*',
                          hide_symbols=True,
                          vnum=VERSION,
                          public_headers=('' if private_library else 'talloc.h'),
                          pc_files='talloc.pc',
                          public_headers_install=not private_library,
                          private_library=private_library,
                          manpages='man/talloc.3')

    if not bld.CONFIG_SET('USING_SYSTEM_PYTALLOC_UTIL') and not bld.env.disable_python:
        for env in bld.gen_python_environments(['PKGCONFIGDIR']):
            name = bld.pyembed_libname('pytalloc-util')

            bld.SAMBA_LIBRARY(name,
                source='pytalloc_util.c',
                public_deps='talloc',
                pyembed=True,
                vnum=VERSION,
                hide_symbols=True,
                abi_directory='ABI',
                abi_match='pytalloc_* _pytalloc_*',
                private_library=private_library,
                public_headers=('' if private_library else 'pytalloc.h'),
                pc_files='pytalloc-util.pc'
                )
            bld.SAMBA_PYTHON('pytalloc',
                            'pytalloc.c',
                            deps='talloc ' + name,
                            enabled=True,
                            realname='talloc.so')

            bld.SAMBA_PYTHON('test_pytalloc',
                            'test_pytalloc.c',
                            deps='pytalloc',
                            enabled=True,
                            realname='_test_pytalloc.so',
                            install=False)


def test(ctx):
    '''run talloc testsuite'''
    import Utils, samba_utils
    cmd = os.path.join(Utils.g_module.blddir, 'talloc_testsuite')
    ret = samba_utils.RUN_COMMAND(cmd)
    print("testsuite returned %d" % ret)
    magic_helper_cmd = os.path.join(Utils.g_module.blddir, 'talloc_test_magic_differs_helper')
    magic_cmd = os.path.join(srcdir, 'lib', 'talloc',
                             'test_magic_differs.sh')

    magic_ret = samba_utils.RUN_COMMAND(magic_cmd + " " +  magic_helper_cmd)
    print("magic differs test returned %d" % magic_ret)
    pyret = samba_utils.RUN_PYTHON_TESTS(['test_pytalloc.py'])
    print("python testsuite returned %d" % pyret)
    sys.exit(ret or magic_ret or pyret)

def dist():
    '''makes a tarball for distribution'''
    samba_dist.dist()

def reconfigure(ctx):
    '''reconfigure if config scripts have changed'''
    import samba_utils
    samba_utils.reconfigure(ctx)


def pydoctor(ctx):
    '''build python apidocs'''
    cmd='PYTHONPATH=bin/python pydoctor --project-name=talloc --project-url=http://talloc.samba.org/ --make-html --docformat=restructuredtext --introspect-c-modules --add-module bin/python/talloc.*'
    print("Running: %s" % cmd)
    os.system(cmd)

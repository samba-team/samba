#!/usr/bin/env python

APPNAME = 'talloc'
VERSION = '2.3.1'

import os
import sys

# find the buildtools directory
top = '.'
while not os.path.exists(top+'/buildtools') and len(top.split('/')) < 5:
    top = top + '/..'
sys.path.insert(0, top + '/buildtools/wafsamba')

out = 'bin'

import wafsamba
from wafsamba import samba_dist, samba_utils
from waflib import Logs, Options, Context

# setup what directories to put in a tarball
samba_dist.DIST_DIRS("""lib/talloc:. lib/replace:lib/replace
buildtools:buildtools third_party/waf:third_party/waf""")


def options(opt):
    opt.BUILTIN_DEFAULT('replace')
    opt.PRIVATE_EXTENSION_DEFAULT('talloc', noextension='talloc')
    opt.RECURSE('lib/replace')
    if opt.IN_LAUNCH_DIR():
        opt.add_option('--enable-talloc-compat1',
                       help=("Build talloc 1.x.x compat library [False]"),
                       action="store_true", dest='TALLOC_COMPAT1', default=False)


def configure(conf):
    conf.RECURSE('lib/replace')

    conf.env.standalone_talloc = conf.IN_LAUNCH_DIR()

    conf.define('TALLOC_BUILD_VERSION_MAJOR', int(VERSION.split('.')[0]))
    conf.define('TALLOC_BUILD_VERSION_MINOR', int(VERSION.split('.')[1]))
    conf.define('TALLOC_BUILD_VERSION_RELEASE', int(VERSION.split('.')[2]))

    conf.env.TALLOC_COMPAT1 = False
    if conf.env.standalone_talloc:
        conf.env.TALLOC_COMPAT1 = Options.options.TALLOC_COMPAT1
        conf.env.PKGCONFIGDIR = '${LIBDIR}/pkgconfig'
        conf.env.TALLOC_VERSION = VERSION

    conf.CHECK_XSLTPROC_MANPAGES()

    conf.CHECK_HEADERS('sys/auxv.h')
    conf.CHECK_FUNCS('getauxval')

    conf.SAMBA_CONFIG_H()

    conf.SAMBA_CHECK_UNDEFINED_SYMBOL_FLAGS()

    conf.SAMBA_CHECK_PYTHON()
    conf.SAMBA_CHECK_PYTHON_HEADERS()

    if not conf.env.standalone_talloc:
        if conf.CHECK_BUNDLED_SYSTEM_PKG('talloc', minversion=VERSION,
                                     implied_deps='replace'):
            conf.define('USING_SYSTEM_TALLOC', 1)

        if conf.env.disable_python:
            using_system_pytalloc_util = False
        else:
            using_system_pytalloc_util = True
            name = 'pytalloc-util' + conf.all_envs['default']['PYTHON_SO_ABI_FLAG']
            if not conf.CHECK_BUNDLED_SYSTEM_PKG(name, minversion=VERSION,
                                                 implied_deps='talloc replace'):
                using_system_pytalloc_util = False

        if using_system_pytalloc_util:
            conf.define('USING_SYSTEM_PYTALLOC_UTIL', 1)


def build(bld):
    bld.RECURSE('lib/replace')

    if bld.env.standalone_talloc:
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

    if not bld.CONFIG_SET('USING_SYSTEM_PYTALLOC_UTIL'):
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
                pc_files='pytalloc-util.pc',
                enabled=bld.PYTHON_BUILD_IS_ENABLED()
                )
        bld.SAMBA_PYTHON('pytalloc',
                         'pytalloc.c',
                         deps='talloc ' + name,
                         enabled=bld.PYTHON_BUILD_IS_ENABLED(),
                         realname='talloc.so')

        bld.SAMBA_PYTHON('test_pytalloc',
                         'test_pytalloc.c',
                         deps=name,
                         enabled=bld.PYTHON_BUILD_IS_ENABLED(),
                         realname='_test_pytalloc.so',
                         install=False)


def testonly(ctx):
    '''run talloc testsuite'''
    import samba_utils

    samba_utils.ADD_LD_LIBRARY_PATH('bin/shared')
    samba_utils.ADD_LD_LIBRARY_PATH('bin/shared/private')

    cmd = os.path.join(Context.g_module.out, 'talloc_testsuite')
    ret = samba_utils.RUN_COMMAND(cmd)
    print("testsuite returned %d" % ret)
    magic_helper_cmd = os.path.join(Context.g_module.out, 'talloc_test_magic_differs_helper')
    magic_cmd = os.path.join(Context.g_module.top, 'lib', 'talloc',
                             'test_magic_differs.sh')
    if not os.path.exists(magic_cmd):
        magic_cmd = os.path.join(Context.g_module.top, 'test_magic_differs.sh')

    magic_ret = samba_utils.RUN_COMMAND(magic_cmd + " " +  magic_helper_cmd)
    print("magic differs test returned %d" % magic_ret)
    pyret = samba_utils.RUN_PYTHON_TESTS(['test_pytalloc.py'])
    print("python testsuite returned %d" % pyret)
    sys.exit(ret or magic_ret or pyret)

# WAF doesn't build the unit tests for this, maybe because they don't link with talloc?
# This forces it
def test(ctx):
    Options.commands.append('build')
    Options.commands.append('testonly')

def dist():
    '''makes a tarball for distribution'''
    samba_dist.dist()

def reconfigure(ctx):
    '''reconfigure if config scripts have changed'''
    samba_utils.reconfigure(ctx)


def pydoctor(ctx):
    '''build python apidocs'''
    cmd='PYTHONPATH=bin/python pydoctor --project-name=talloc --project-url=http://talloc.samba.org/ --make-html --docformat=restructuredtext --introspect-c-modules --add-module bin/python/talloc.*'
    print("Running: %s" % cmd)
    os.system(cmd)

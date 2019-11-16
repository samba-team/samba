#!/usr/bin/env python

APPNAME = 'tevent'
VERSION = '0.10.2'

import sys, os

# find the buildtools directory
top = '.'
while not os.path.exists(top+'/buildtools') and len(top.split('/')) < 5:
    top = top + '/..'
sys.path.insert(0, top + '/buildtools/wafsamba')

out = 'bin'

import wafsamba
from wafsamba import samba_dist, samba_utils
from waflib import Options, Logs, Context

samba_dist.DIST_DIRS('lib/tevent:. lib/replace:lib/replace lib/talloc:lib/talloc buildtools:buildtools third_party/waf:third_party/waf')

def options(opt):
    opt.BUILTIN_DEFAULT('replace')
    opt.PRIVATE_EXTENSION_DEFAULT('tevent', noextension='tevent')
    opt.RECURSE('lib/replace')
    opt.RECURSE('lib/talloc')


def configure(conf):
    conf.RECURSE('lib/replace')
    conf.RECURSE('lib/talloc')

    conf.env.standalone_tevent = conf.IN_LAUNCH_DIR()

    if not conf.env.standalone_tevent:
        if conf.CHECK_BUNDLED_SYSTEM_PKG('tevent', minversion=VERSION,
                                     onlyif='talloc', implied_deps='replace talloc'):
            conf.define('USING_SYSTEM_TEVENT', 1)
            if not conf.env.disable_python and \
                conf.CHECK_BUNDLED_SYSTEM_PYTHON('pytevent', 'tevent', minversion=VERSION):
                conf.define('USING_SYSTEM_PYTEVENT', 1)

    if conf.CHECK_FUNCS('epoll_create', headers='sys/epoll.h'):
        conf.DEFINE('HAVE_EPOLL', 1)

    tevent_num_signals = 64
    v = conf.CHECK_VALUEOF('NSIG', headers='signal.h')
    if v is not None:
        tevent_num_signals = max(tevent_num_signals, v)
    v = conf.CHECK_VALUEOF('_NSIG', headers='signal.h')
    if v is not None:
        tevent_num_signals = max(tevent_num_signals, v)
    v = conf.CHECK_VALUEOF('SIGRTMAX', headers='signal.h')
    if v is not None:
        tevent_num_signals = max(tevent_num_signals, v)
    v = conf.CHECK_VALUEOF('SIGRTMIN', headers='signal.h')
    if v is not None:
        tevent_num_signals = max(tevent_num_signals, v*2)

    if not conf.CONFIG_SET('USING_SYSTEM_TEVENT'):
        conf.DEFINE('TEVENT_NUM_SIGNALS', tevent_num_signals)

    conf.SAMBA_CHECK_PYTHON()
    conf.SAMBA_CHECK_PYTHON_HEADERS()

    conf.SAMBA_CONFIG_H()

    conf.SAMBA_CHECK_UNDEFINED_SYMBOL_FLAGS()

def build(bld):
    bld.RECURSE('lib/replace')
    bld.RECURSE('lib/talloc')

    SRC = '''tevent.c tevent_debug.c tevent_fd.c tevent_immediate.c
             tevent_queue.c tevent_req.c tevent_wrapper.c
             tevent_poll.c tevent_threads.c
             tevent_signal.c tevent_standard.c tevent_timed.c tevent_util.c tevent_wakeup.c'''

    if bld.CONFIG_SET('HAVE_EPOLL'):
        SRC += ' tevent_epoll.c'

    if bld.CONFIG_SET('HAVE_SOLARIS_PORTS'):
        SRC += ' tevent_port.c'

    if bld.env.standalone_tevent:
        bld.env.PKGCONFIGDIR = '${LIBDIR}/pkgconfig'
        private_library = False
    else:
        private_library = True

    if not bld.CONFIG_SET('USING_SYSTEM_TEVENT'):
        tevent_deps = 'replace talloc'
        if bld.CONFIG_SET('HAVE_PTHREAD'):
            tevent_deps += ' pthread'

        bld.SAMBA_LIBRARY('tevent',
                          SRC,
                          deps=tevent_deps,
                          enabled= not bld.CONFIG_SET('USING_SYSTEM_TEVENT'),
                          includes='.',
                          abi_directory='ABI',
                          abi_match='tevent_* _tevent_*',
                          vnum=VERSION,
                          public_headers=('' if private_library else 'tevent.h'),
                          public_headers_install=not private_library,
                          pc_files='tevent.pc',
                          private_library=private_library)

    if not bld.CONFIG_SET('USING_SYSTEM_PYTEVENT') and not bld.env.disable_python:
        bld.SAMBA_PYTHON('_tevent',
                         'pytevent.c',
                         deps='tevent',
                         realname='_tevent.so',
                         cflags='-DPACKAGE_VERSION=\"%s\"' % VERSION)


        bld.INSTALL_WILDCARD('${PYTHONARCHDIR}', 'tevent.py', flat=False)

        # install out various python scripts for use by make test
        bld.SAMBA_SCRIPT('tevent_python',
                         pattern='tevent.py',
                         installdir='python')


def test(ctx):
    '''test tevent'''
    print("The tevent testsuite is part of smbtorture in samba4")

    samba_utils.ADD_LD_LIBRARY_PATH('bin/shared')
    samba_utils.ADD_LD_LIBRARY_PATH('bin/shared/private')

    pyret = samba_utils.RUN_PYTHON_TESTS(['bindings.py'])
    sys.exit(pyret)


def dist():
    '''makes a tarball for distribution'''
    samba_dist.dist()

def reconfigure(ctx):
    '''reconfigure if config scripts have changed'''
    samba_utils.reconfigure(ctx)

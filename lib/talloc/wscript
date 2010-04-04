#!/usr/bin/env python

APPNAME = 'talloc'
VERSION = '2.0.2'

blddir = 'bin'

import os, sys

# find the buildtools directory
buildtools = 'buildtools'
while not os.path.exists(buildtools) and len(buildtools.split('/')) < 5:
    buildtools = '../' + buildtools
srcdir = os.path.dirname(buildtools) or '.'

sys.path.insert(0, buildtools + "/wafsamba")


LIBREPLACE_DIR= '../replace'

import sys
sys.path.insert(0, srcdir+"/buildtools/wafsamba")
import wafsamba, samba_dist

# setup what directories to put in a tarball
samba_dist.DIST_DIRS('lib/talloc:. lib/replace:lib/replace buildtools:buildtools')


def set_options(opt):
    opt.BUILTIN_DEFAULT('replace')
    opt.BUNDLED_EXTENSION_DEFAULT('talloc', noextenion='talloc')
    opt.recurse(LIBREPLACE_DIR)

def configure(conf):
    conf.sub_config(LIBREPLACE_DIR)

    if conf.CHECK_BUNDLED_SYSTEM('talloc', minversion=VERSION,
                                 implied_deps='replace'):
        conf.define('USING_SYSTEM_TALLOC', 1)

    conf.env.standalone_talloc = conf.IN_LAUNCH_DIR()

    conf.SAMBA_CONFIG_H()



def build(bld):
    bld.BUILD_SUBDIR(LIBREPLACE_DIR)

    if not bld.CONFIG_SET('USING_SYSTEM_TALLOC'):
        bld.SAMBA_LIBRARY('talloc',
                          'talloc.c',
                          deps='replace',
                          vnum=VERSION)

    if not getattr(bld.env, '_SAMBA_BUILD_', 0) == 4:
        # s4 already has the talloc testsuite builtin to smbtorture
        bld.SAMBA_BINARY('talloc_testsuite',
                         'testsuite_main.c testsuite.c',
                         deps='talloc',
                         install=False)

    if bld.env.standalone_talloc:
        bld.env.PKGCONFIGDIR = '${LIBDIR}/pkgconfig'
        bld.env.TALLOC_VERSION = VERSION
        bld.PKG_CONFIG_FILES('talloc.pc', vnum=VERSION)


def dist():
    '''makes a tarball for distribution'''
    samba_dist.dist()


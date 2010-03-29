#!/usr/bin/env python

VERSION = '2.0.1'

srcdir = '../..'
blddir = 'bin'

LIBREPLACE_DIR= srcdir + '/lib/replace'

import sys
sys.path.insert(0, srcdir+"/buildtools/wafsamba")
import wafsamba

def set_options(opt):
    opt.BUILTIN_DEFAULT('replace')
    opt.BUNDLED_EXTENSION_DEFAULT('talloc', noextenion='talloc')
    opt.recurse(LIBREPLACE_DIR)

def configure(conf):
    conf.sub_config(LIBREPLACE_DIR)

    if conf.CHECK_BUNDLED_SYSTEM('talloc', minversion=VERSION,
                                 implied_deps='replace'):
        conf.define('USING_SYSTEM_TALLOC', 1)

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

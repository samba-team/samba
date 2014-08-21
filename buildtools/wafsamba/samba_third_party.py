# functions to support third party libraries

from Configure import conf
import sys, Logs, os
from samba_bundled import *

@conf
def CHECK_FOR_THIRD_PARTY(conf):
    return os.path.exists(os.path.join(Utils.g_module.srcdir, 'third_party'))

Build.BuildContext.CHECK_FOR_THIRD_PARTY = CHECK_FOR_THIRD_PARTY

@conf
def CHECK_ZLIB(conf):
    version_check='''
    #if (ZLIB_VERNUM >= 0x1230)
    #else
    #error "ZLIB_VERNUM < 0x1230"
    #endif
    z_stream *z;
    inflateInit2(z, -15);
    '''
    return conf.CHECK_BUNDLED_SYSTEM('z', minversion='1.2.3', pkg='zlib',
                                     checkfunctions='zlibVersion',
                                     headers='zlib.h',
                                     checkcode=version_check,
                                     implied_deps='replace')

Build.BuildContext.CHECK_ZLIB = CHECK_ZLIB

@conf
def CHECK_POPT(conf):
    return conf.CHECK_BUNDLED_SYSTEM('popt', checkfunctions='poptGetContext', headers='popt.h')

Build.BuildContext.CHECK_POPT = CHECK_POPT

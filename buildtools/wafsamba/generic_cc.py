
# compiler definition for a generic C compiler
# based on suncc.py from waf

import os, optparse
from waflib import Errors
from waflib.Tools import ccroot, ar
from waflib.Configure import conf

#
# Let waflib provide useful defaults, but
# provide generic_cc as last resort fallback on
# all platforms
#
from waflib.Tools.compiler_c import c_compiler
for key in c_compiler.keys():
    c_compiler[key].append('generic_cc')

@conf
def find_generic_cc(conf):
    v = conf.env
    cc = None
    if v.CC:
        cc = v.CC
    elif 'CC' in conf.environ:
        cc = conf.environ['CC']
    if not cc:
        cc = conf.find_program('cc', var='CC')
    if not cc:
        conf.fatal('generic_cc was not found')

    try:
        conf.cmd_and_log(cc + ['--version'])
    except Errors.WafError:
        conf.fatal('%r --version could not be executed' % cc)

    v.CC = cc
    v.CC_NAME = 'generic_cc'

@conf
def generic_cc_common_flags(conf):
    v = conf.env

    v.CC_SRC_F            = ''
    v.CC_TGT_F            = ['-c', '-o']
    v.CPPPATH_ST          = '-I%s'
    v.DEFINES_ST          = '-D%s'

    if not v.LINK_CC:
        v.LINK_CC = v.CC

    v.CCLNK_SRC_F         = ''
    v.CCLNK_TGT_F         = ['-o']

    v.LIB_ST              = '-l%s' # template for adding libs
    v.LIBPATH_ST          = '-L%s' # template for adding libpaths
    v.STLIB_ST            = '-l%s'
    v.STLIBPATH_ST        = '-L%s'

    v.cprogram_PATTERN    = '%s'
    v.cshlib_PATTERN      = 'lib%s.so'
    v.cstlib_PATTERN      = 'lib%s.a'

def configure(conf):
    conf.find_generic_cc()
    conf.find_ar()
    conf.generic_cc_common_flags()
    conf.cc_load_tools()
    conf.cc_add_flags()
    conf.link_add_flags()

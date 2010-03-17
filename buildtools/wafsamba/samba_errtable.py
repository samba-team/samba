# waf build tool for building .et files with compile_et
import Build, os
from samba_utils import *

def SAMBA_ERRTABLE(bld, name, source):
    '''Build a heimdal errtable from a .et file'''

    bname = source[0:-3]; # strip off the .et suffix

    if not SET_TARGET_TYPE(bld, name, 'ET'):
        return

    bld.SET_BUILD_GROUP('build_source')

    out_files = []
    out_files.append('%s.c' % bname)
    out_files.append('%s.h' % bname)

    t = bld(rule='${SRC[0].abspath(env)} . ${TGT[0].parent.abspath(env)} default/source4/heimdal_build/compile_et ${SRC[2].abspath(env)} ${TGT[0].bldpath(env)}',
            ext_out = '.c',
            before  = 'cc',
            shell   = True,
            source  = ['et_compile_wrapper.sh', 'compile_et', source],
            target  = out_files,
            name    = name)
Build.BuildContext.SAMBA_ERRTABLE = SAMBA_ERRTABLE

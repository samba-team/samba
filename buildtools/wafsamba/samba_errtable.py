# waf build tool for building .et files with compile_et
import Build
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

    t = bld(rule='${SRC[1].abspath(env)} . ${TGT[0].parent.abspath(env)} default/source4/heimdal_build/compile_et ${SRC[0].abspath(env)} ${TGT[0].bldpath(env)}',
            ext_out = '.c',
            before  = 'cc',
            on_results = True,
            shell   = True,
            source  = [source, 'et_compile_wrapper.sh', 'compile_et'],
            target  = out_files,
            name    = name)
Build.BuildContext.SAMBA_ERRTABLE = SAMBA_ERRTABLE

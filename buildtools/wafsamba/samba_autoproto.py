# waf build tool for building automatic prototypes from C source

import Build
from samba_utils import *

def HEIMDAL_AUTOPROTO(bld, header, source, options=None, group='prototypes'):
    '''rule for heimdal prototype generation'''
    bld.SET_BUILD_GROUP(group)
    if options is None:
        options='-q -P comment -o'
    SET_TARGET_TYPE(bld, header, 'PROTOTYPE')
    t = bld(rule='${PERL} ${HEIMDAL}/cf/make-proto.pl ${OPTIONS} ${TGT[0].abspath(env)} ${SRC}',
            source=source,
            target=header,
            on_results=True,
            ext_out='.c',
            before='cc')
    t.env.HEIMDAL = os.path.join(bld.srcnode.abspath(), 'source4/heimdal')
    t.env.OPTIONS = options
Build.BuildContext.HEIMDAL_AUTOPROTO = HEIMDAL_AUTOPROTO


def HEIMDAL_AUTOPROTO_PRIVATE(bld, header, source):
    '''rule for private heimdal prototype generation'''
    bld.HEIMDAL_AUTOPROTO(header, source, options='-q -P comment -p')
Build.BuildContext.HEIMDAL_AUTOPROTO_PRIVATE = HEIMDAL_AUTOPROTO_PRIVATE


def SAMBA_AUTOPROTO(bld, header, source):
    '''rule for samba prototype generation'''
    bld.SET_BUILD_GROUP('prototypes')
    relpath = os_path_relpath(bld.curdir, bld.srcnode.abspath())
    name = os.path.join(relpath, header)
    SET_TARGET_TYPE(bld, name, 'PROTOTYPE')
    t = bld(
        name = name,
        source = source,
        target = header,
        on_results=True,
        ext_out='.c',
        before ='cc',
        rule = '${PERL} ${SCRIPT}/mkproto.pl --srcdir=.. --builddir=. --public=/dev/null --private=${TGT} ${SRC}'
        )
    t.env.SCRIPT = os.path.join(bld.srcnode.abspath(), 'source4/script')
Build.BuildContext.SAMBA_AUTOPROTO = SAMBA_AUTOPROTO


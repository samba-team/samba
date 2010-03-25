# waf build tool for building automatic prototypes from C source

import Build
from samba_utils import *

# rule for heimdal prototype generation
def HEIMDAL_AUTOPROTO(bld, header, source, options=None, group='prototypes'):
    bld.SET_BUILD_GROUP(group)
    if options is None:
        options='-q -P comment -o'
    t = bld(rule='${PERL} ../heimdal/cf/make-proto.pl ${OPTIONS} ${TGT[0].abspath(env)} ${SRC}',
            source=source,
            target=header,
            on_results=True,
            ext_out='.c',
            before='cc')
    t.env.OPTIONS = options
Build.BuildContext.HEIMDAL_AUTOPROTO = HEIMDAL_AUTOPROTO

# rule for private heimdal prototype generation
def HEIMDAL_AUTOPROTO_PRIVATE(bld, header, source):
    bld.HEIMDAL_AUTOPROTO(header, source, options='-q -P comment -p')
Build.BuildContext.HEIMDAL_AUTOPROTO_PRIVATE = HEIMDAL_AUTOPROTO_PRIVATE

# rule for samba prototype generation
def SAMBA_AUTOPROTO(bld, header, source):
    bld.SET_BUILD_GROUP('prototypes')
    bld(
        source = source,
        target = header,
        on_results=True,
        ext_out='.c',
        before ='cc',
        rule = '../script/mkproto.pl --srcdir=.. --builddir=. --public=/dev/null --private=${TGT} ${SRC}'
        )
Build.BuildContext.SAMBA_AUTOPROTO = SAMBA_AUTOPROTO


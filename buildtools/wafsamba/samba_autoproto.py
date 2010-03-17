# waf build tool for building automatic prototypes from C source

from TaskGen import taskgen, before
import Build, os, string, Utils
from samba_utils import *

# rule for heimdal prototype generation
def HEIMDAL_AUTOPROTO(bld, header, source, options='-q -P comment -o'):
    t = bld(rule='${PERL} -W ../heimdal/cf/make-proto.pl ${OPTIONS} ${TGT[0].abspath(env)} ${SRC}',
            source=source,
            target=header,
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
    print "TODO: add samba autoproto rule"
    return
Build.BuildContext.SAMBA_AUTOPROTO = SAMBA_AUTOPROTO




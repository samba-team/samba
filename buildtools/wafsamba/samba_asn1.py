# samba ASN1 rules

from TaskGen import before
import Build, os
from samba_utils import *
from samba_autoconf import *


# not sure if we need this exec_rule stuff ..., i'll leave it in for now
@feature('asn1')
@before('exec_rule')
def add_comp(self):
    y = self.bld.name_to_obj("asn1_compile", self.env)
    y.post()


def SAMBA_ASN1(bld, name, source,
               options='',
               directory='',
               option_file=None,
               includes=''):
    '''Build a ASN1 file using the asn1 compiler.
       This will produce 2 output files'''
    bname = os.path.basename(source)[0:-5];
    dname = os.path.dirname(source)
    asn1name = "%s_asn1" % bname

    if not SET_TARGET_TYPE(bld, name, 'ASN1'):
        return

    # for ASN1 compilation, I always put it in build_source, as it doesn't make
    # sense elsewhere
    bld.SET_BUILD_GROUP('build_source')

    # old build system for spnego.asn1:
    # /home/tnagy/samba_old/source4/./bin/asn1_compile --sequence=MechTypeList --one-code-file /home/tnagy/samba_old/source4/heimdal/lib/gssapi/spnego/spnego.asn1 spnego_asn1

    # new system: hmm, maybe options need to come earlier in the command line? We put them later
    # /home/tnagy/samba/source4/bin/asn1_compile  --one-code-file /home/tnagy/samba/source4/heimdal/lib/gssapi/spnego/spnego.asn1 spnego_asn1 --sequence=MechTypeList

    out_files = []
    out_files.append("../heimdal/%s/asn1_%s_asn1.x" % (directory, bname))
    out_files.append("../heimdal/%s/%s_asn1.hx" % (directory, bname))

    # the ${TGT[0].parent.abspath(env)} expression gives us the parent directory of
    # the first target in the build directory
    # SRC[0].abspath(env) gives the absolute path to the source directory for the first
    # source file. Note that in the case of a option_file, we have more than
    # one source file
    # SRC[1].abspath(env) gives the path of asn1_compile. This makes the asn1 output
    # correctly depend on the compiler binary
    cd_rule = 'cd ${TGT[0].parent.abspath(env)}'
    asn1_rule = cd_rule + ' && ${SRC[1].abspath(env)} ${OPTION_FILE} ${ASN1OPTIONS} --one-code-file ${SRC[0].abspath(env)} ${ASN1NAME}'

    source = TO_LIST(source)
    source.append('asn1_compile')

    if option_file is not None:
        source.append(option_file)

    t = bld(rule=asn1_rule,
            features = 'asn1',
            ext_out = '.x',
            before = 'cc',
            shell = True,
            source = source,
            target = out_files,
            name=name + '_ASN1')

    t.env.ASN1NAME     = asn1name
    t.env.ASN1OPTIONS  = options
    if option_file is not None:
        t.env.OPTION_FILE = "--option-file=%s" % os.path.normpath(os.path.join(bld.curdir, option_file))

    cfile = out_files[0][0:-2] + '.c'
    hfile = out_files[1][0:-3] + '.h',

    # now generate a .c file from the .x file
    t = bld(rule='''( echo '#include "config.h"' && cat ${SRC} ) > ${TGT}''',
            source = out_files[0],
            target = cfile,
            shell = True,
	    ext_out = '.c',
            ext_in = '.x',
            depends_on = name + '_ASN1',
            name = name + '_C')

    # and generate a .h file from the .hx file
    t = bld(rule='cp ${SRC} ${TGT}',
            source = out_files[1],
            ext_out = '.c',
            ext_in = '.x',
            target = hfile,
            depends_on = name + '_ASN1',
            name = name + '_H')

    bld.SET_BUILD_GROUP('main')

    includes = TO_LIST(includes)
    includes.append(os.path.dirname(out_files[0]))

    t = bld(features       = 'cc',
            source         = cfile,
            target         = name,
            samba_cflags   = CURRENT_CFLAGS(bld, name, ''),
            depends_on     = '',
            samba_deps     = TO_LIST('HEIMDAL_ROKEN'),
            samba_includes = includes,
            local_include  = True)

Build.BuildContext.SAMBA_ASN1 = SAMBA_ASN1

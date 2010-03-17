# waf build tool for building IDL files with pidl

from TaskGen import taskgen, before
import Build, os, string, Utils
from samba_utils import *

def SAMBA_PIDL(bld, pname, source, options='', output_dir='.'):
    '''Build a IDL file using pidl.
       This will produce up to 13 output files depending on the options used'''

    bname = source[0:-4]; # strip off the .idl suffix
    name = "%s_%s" % (pname, bname.upper())

    if not SET_TARGET_TYPE(bld, name, 'PIDL'):
        return

    bld.SET_BUILD_GROUP('build_source')

    # the output files depend on the options used. Use this dictionary
    # to map between the options and the resulting file names
    options_map = { '--header'            : '%s.h',
                    '--ndr-parser'        : 'ndr_%s.c ndr_%s.h',
                    '--samba3-ndr-server' : 'srv_%s.c srv_%s.h',
                    '--samba3-ndr-client' : 'cli_%s.c cli_%s.h',
                    '--server'            : 'ndr_%s_s.c',
                    '--client'            : 'ndr_%s_c.c ndr_%s_c.h',
                    '--python'            : 'py_%s.c',
                    '--tdr-parser'        : 'tdr_%s.c tdr_%s.h',
                    }

    table_header_idx = None
    out_files = []
    options_list = to_list(options)

    for o in options_list:
        if o in options_map:
            ofiles = to_list(options_map[o])
            for f in ofiles:
                out_files.append(os.path.join(output_dir, f % bname))
                if f == 'ndr_%s.h':
                    # remember this one for the tables generation
                    table_header_idx = len(out_files) - 1

    pidl = bld.srcnode.find_resource('pidl/pidl').relpath_gen(bld.path)

    # the cd .. is needed because pidl currently is sensitive to the directory it is run in
    t = bld(rule='cd .. && ${PIDL} ${OPTIONS} --outputdir ${OUTPUTDIR} -- ${SRC[0].abspath(env)}',
            ext_out = '.c',
            before  = 'cc',
            shell   = True,
            source  = source,
            target  = out_files,
            name    = name)

    t.env.PIDL = "../pidl/pidl"
    t.env.OPTIONS = to_list(options)
    t.env.OUTPUTDIR = 'bin/' + bld.BUILD_PATH(output_dir)


    if table_header_idx is not None:
        pidl_headers = LOCAL_CACHE(bld, 'PIDL_HEADERS')
        pidl_headers[name] = [bld.path.find_or_declare(out_files[table_header_idx])]

    t.more_includes = '#' + bld.path.relpath_gen(bld.srcnode)
Build.BuildContext.SAMBA_PIDL = SAMBA_PIDL


def SAMBA_PIDL_LIST(bld, name, source, options='', output_dir='.'):
    '''A wrapper for building a set of IDL files'''
    for p in to_list(source):
        bld.SAMBA_PIDL(name, p, options=options, output_dir=output_dir)
Build.BuildContext.SAMBA_PIDL_LIST = SAMBA_PIDL_LIST


#################################################################
# the rule for generating the NDR tables
from TaskGen import feature, before
@feature('collect')
@before('exec_rule')
def collect(self):
    pidl_headers = LOCAL_CACHE(self.bld, 'PIDL_HEADERS')
    for (name, hd) in pidl_headers.items():
        y = self.bld.name_to_obj(name, self.env)
        self.bld.ASSERT(y is not None, 'Failed to find PIDL header %s' % name)
        y.post()
        for node in hd:
            self.source += " " + node.relpath_gen(self.path)


def SAMBA_PIDL_TABLES(bld, name, target):
    headers = bld.env.PIDL_HEADERS
    t = bld(
            features = 'collect',
            rule     = '${SRC} --output ${TGT} > ${TGT}',
            ext_out  = '.c',
            before   = 'cc',
            shell    = True,
            source   = '../../librpc/tables.pl',
            target   = target,
            name     = name)
    print name
Build.BuildContext.SAMBA_PIDL_TABLES = SAMBA_PIDL_TABLES


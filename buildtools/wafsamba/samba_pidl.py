# waf build tool for building IDL files with pidl

from TaskGen import taskgen, before
import Build, os, string, Utils
from samba_utils import *

def SAMBA_PIDL(bld, pname, source, options=''):
    '''Build a IDL file using pidl.
       This will produce 7 output files'''

    bname = source[0:-4];
    name = "PIDL_%s" % bname.upper()

    if not SET_TARGET_TYPE(bld, name, 'PIDL'):
        return

    bld.SET_BUILD_GROUP('build_source')

    gen_ndr_dir = '../gen_ndr/'
    out_files = []
    out_files.append(gen_ndr_dir + 'ndr_%s.c' % bname)
    out_files.append(gen_ndr_dir + 'ndr_%s.h' % bname)
    out_files.append(gen_ndr_dir + '%s.h' % bname)
    out_files.append(gen_ndr_dir + 'ndr_%s_s.c' % bname)
    out_files.append(gen_ndr_dir + 'ndr_%s_c.c' % bname)
    out_files.append(gen_ndr_dir + 'ndr_%s_c.h' % bname)
    out_files.append(gen_ndr_dir + 'py_%s.c' % bname)

    pidl = bld.srcnode.find_resource('pidl/pidl').relpath_gen(bld.path)
    t = bld(rule='${PIDL} ${PIDL_BUILD_TYPES} ${OPTIONS} --outputdir ${OUTPUTDIR} -- ${SRC[0].abspath(env)}',
            ext_out = '.c',
            before = 'cc',
            shell = False,
            source=source,
            target = out_files,
            name=name)

    t.env.PIDL = "../../pidl/pidl"
    t.env.PIDL_BUILD_TYPES = '--header --ndr-parser --client --python --server'.split()
    t.env.OPTIONS = options
    t.env.OUTPUTDIR = bld.BUILD_PATH(gen_ndr_dir)

    try:
         bld.PIDL_STUFF[name] = [bld.path.find_or_declare(out_files[1])]
    except AttributeError:
         bld.PIDL_STUFF = {}
         bld.PIDL_STUFF[name] = [bld.path.find_or_declare(out_files[1])]

    t.more_includes = '#' + bld.path.relpath_gen(bld.srcnode)
Build.BuildContext.SAMBA_PIDL = SAMBA_PIDL


def SAMBA_PIDL_TDR(bld, pname, source, options=''):
    '''Build a IDL file using pidl.
    This will only produce the header and tdr parser'''

    bname = source[0:-4];
    name = "PIDL_%s" % bname.upper()

    if not SET_TARGET_TYPE(bld, name, 'PIDL'):
        return

    bld.SET_BUILD_GROUP('build_source')

    out_files = []
    out_files.append('tdr_%s.c' % bname)
    out_files.append('tdr_%s.h' % bname)

    pidl = bld.srcnode.find_resource('pidl/pidl').relpath_gen(bld.path)
    t = bld(rule='${PIDL} ${PIDL_BUILD_TYPES} ${OPTIONS} --outputdir ${TGT[0].parent.abspath(env)} -- ${SRC[0].abspath(env)}',
            ext_out = '.c',
            before = 'cc',
            shell = True,
            source=source,
            target = out_files,
            name=name)

    t.env.PIDL = "../../pidl/pidl"
    t.env.PIDL_BUILD_TYPES = '--header --tdr-parser'
    t.env.OPTIONS = options

Build.BuildContext.SAMBA_PIDL_TDR = SAMBA_PIDL_TDR


#################################################################
# define a set of Samba PIDL targets
def SAMBA_PIDL_LIST(bld, name, source,options=''):
    for p in to_list(source):
        bld.SAMBA_PIDL(name, p, options)
Build.BuildContext.SAMBA_PIDL_LIST = SAMBA_PIDL_LIST


#################################################################
# the rule for generating the NDR tables
from TaskGen import feature, before
@feature('collect')
@before('exec_rule')
def collect(self):
    for (name, hd) in self.bld.PIDL_STUFF.items():
        y = self.bld.name_to_obj(name, self.env)
        if not y:
            raise "!"+str(name)
        y.post()
        for node in hd:
            self.source += " " + node.relpath_gen(self.path)

def SAMBA_PIDL_TABLES(bld, name, target):
    headers = bld.env.PIDL_HEADERS
    # this print line should tell us what we ended up with
    # we're ending up with the wrong relative path
    #print "tables target=%s curdir=%s headers=%s" % (target, bld.curdir, headers)
    t = bld(
            features = 'collect',
            rule='${SRC} --output ${TGT} > ${TGT}',
            ext_out = '.c',
            before = 'cc',
            shell = True,
            source = '../../librpc/tables.pl',
            target=target,
            name=name)
    print name
Build.BuildContext.SAMBA_PIDL_TABLES = SAMBA_PIDL_TABLES


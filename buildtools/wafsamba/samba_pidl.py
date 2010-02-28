# waf build tool for building IDL files with pidl

from TaskGen import taskgen, before
import Build, os, string
from samba_utils import *

def SAMBA_PIDL(bld, directory, source, options=''):
    '''Build a IDL file using pidl.
       This will produce 7 output files'''

    name = os.path.basename(string.replace(source, '.idl', ''))
    name = "PIDL_%s" % name.upper()

    if not SET_TARGET_TYPE(bld, name, 'PIDL'):
        return

    bld.SET_BUILD_GROUP('build_source')
    t = bld(name=name, source=source, options=options)
    t.mappings['.idl'] = process_pidl
    t.env.PIDL = "../../pidl/pidl"
    t.env.PIDL_BUILD_TYPES = '--header --ndr-parser --client --python --server'.split()
    t.env.OPTIONS = options

Build.BuildContext.SAMBA_PIDL = SAMBA_PIDL


@taskgen
def process_pidl(self, node, options=''):
    '''Generate the list of output nodes for a given input IDL
       file, and create the task to build them'''
    bname       = node.file_base()
    # the output of pidl needs to go in the gen_ndr directory
    gen_ndr_dir = "../gen_ndr/"
    c_node     = NEW_NODE(node, gen_ndr_dir + 'ndr_%s.c' % bname)
    h1_node    = NEW_NODE(node, gen_ndr_dir + '%s.h' % bname)
    h2_node    = NEW_NODE(node, gen_ndr_dir + 'ndr_%s.h' % bname)
    s_node     = NEW_NODE(node, gen_ndr_dir + 'ndr_%s_s.c' % bname)
    cli_node   = NEW_NODE(node, gen_ndr_dir + 'ndr_%s_c.c' % bname)
    cli_h_node = NEW_NODE(node, gen_ndr_dir + 'ndr_%s_c.h' % bname)
    py_node    = NEW_NODE(node, gen_ndr_dir + 'py_%s.c' % bname)
    t = self.create_task('pidl', node, [c_node, h1_node, h2_node, s_node,
                                        cli_node, cli_h_node, py_node])
    # setup ${OUTPUTDIR} in the pidl rule, and make sure it exists
    t.env.OUTPUTDIR = os.path.dirname(c_node.abspath(self.env))
    if not os.path.isdir(t.env.OUTPUTDIR):
        os.mkdir(t.env.OUTPUTDIR, 0777)


# the pidl task itself
import Task
Task.simple_task_type('pidl',
                      '${PIDL} ${PIDL_BUILD_TYPES} ${OPTIONS} --outputdir ${OUTPUTDIR} -- ${SRC}',
                      color='BLUE', before='cc', shell=False)

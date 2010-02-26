# a waf tool to add extension based build patterns for Samba

import os, sys, Options
import string, Task, Utils, optparse
from Configure import conf
from Logs import debug
from TaskGen import extension
from samba_utils import *

##########################################################
# create a node with a new name, based on an existing node
def NEW_NODE(node, name):
    ret = node.parent.find_or_declare([name])
    ASSERT(node, ret is not None, "Unable to find new target with name '%s' from '%s'" % (
            name, node.name))
    return ret


################################################################################
# a et task which calls out to compile_et to do the work
Task.simple_task_type('et',
		      '../heimdal_build/et_compile_wrapper.sh . ${TGT[0].bld_dir(env)} default/source4/heimdal_build/compile_et ${SRC[0].abspath(env)} ${TGT[0].bldpath(env)}',
                      color='BLUE', ext_out='.c',
                      shell = False)

@extension('.et')
def process_et(self, node):
    c_node = node.change_ext('.c')
    h_node  = node.change_ext('.h')
    self.create_task('et', node, [c_node, h_node])
    self.allnodes.append(c_node)



################################################################################
# a idl task which calls out to pidl to do the work
Task.simple_task_type('idl', '../../pidl/pidl ${TGT[0].options} --header --ndr-parser --client --python --server --outputdir=${TGT[0].outputdir} -- ${SRC}', color='BLUE', ext_out='.c')

@extension('.idl')
def process_idl(self, node):
    bname      = node.file_base()
    c_node     = NEW_NODE(node, 'ndr_%s.c' % bname)
    h1_node    = NEW_NODE(node, '%s.h' % bname)
    h2_node    = NEW_NODE(node, 'ndr_%s.h' % bname)
    s_node     = NEW_NODE(node, 'ndr_%s_s.c' % bname)
    cli_node   = NEW_NODE(node, 'ndr_%s_c.c' % bname)
    cli_h_node = NEW_NODE(node, 'ndr_%s_c.h' % bname)
    py_node    = NEW_NODE(node, 'py_%s.c' % bname)


    dname = os.path.dirname(node.bld_dir(self.env)) + "/gen_ndr"
    c_node.outputdir = dname
    c_node.options   = self.options

    self.create_task('idl', node, [c_node, h1_node, h2_node, s_node, cli_node, cli_h_node, py_node])

    # reinject the c node to the list of nodes to process
    self.allnodes.append(c_node)




################################################################################
# a asn1 task which calls out to asn1_compile_wrapper.sh to do the work
Task.simple_task_type('asn1',
		      '''
# shell script to convert ASN1 to C. This could be separated out if we want to
set -e
compiler=${TGT[0].compiler}
destdir=${TGT[0].destdir}
wrapper=${TGT[0].asn1wrapper}
srcfile=${SRC[0].abspath(env)}
asn1name=${TGT[0].asn1name}
options="${TGT[0].asn1options}"

# run the wrapper
$wrapper . $destdir $compiler $srcfile $asn1name ${options} --one-code-file

# that generated 3 files:
#    ${asn1name}.hx
#    asn1_${asn1name}.x
#    ${asn1name}_files


hxfile=$destdir/$asn1name.hx
xfile=$destdir/asn1_$asn1name.x
listfilee=$destdir/"$asn1name"_files

cfile=${TGT[0].abspath(env)}
hfile=${TGT[1].abspath(env)}

cp $hxfile $hfile
echo '#include "config.h"' > $cfile
cat $xfile >> $cfile
rm -f $listfile

''',
                      color='BLUE',
                      ext_out='.c',
                      shell = True)

@extension('.asn1')
def process_asn1(self, node):

    asn1name = string.replace(node.file(), '.', '_')
    c_node  = NEW_NODE(node, 'asn1_%s.c' % asn1name)
    h_node  = NEW_NODE(node, '%s.h' % asn1name)

    c_node.destdir      = "default/source4/heimdal/" + self.asn1directory
    c_node.asn1options  = self.asn1options
    c_node.asn1name     = asn1name
    c_node.asn1wrapper  = "../heimdal_build/asn1_compile_wrapper.sh"
    c_node.compiler     = "default/source4/heimdal_build/asn1_compile"

    self.create_task('asn1', node, [c_node, h_node])
    self.allnodes.append(c_node)


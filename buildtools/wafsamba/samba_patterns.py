# a waf tool to add extension based build patterns for Samba

import os, sys, Options
import string, Task, Utils, optparse
from Configure import conf
from Logs import debug
from TaskGen import extension
from samba_utils import *

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



def SAMBA_MKVERSION(bld, target):
    '''generate the version.h header for Samba'''
    bld.SET_BUILD_GROUP('setup')
    t = bld(rule="${SRC} ${TGT}",
            source= [ "script/mkversion.sh", 'VERSION' ],
            target=target,
            before="cc")
    # force this rule to be constructed now
    t.post()
Build.BuildContext.SAMBA_MKVERSION = SAMBA_MKVERSION


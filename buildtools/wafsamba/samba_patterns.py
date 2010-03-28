# a waf tool to add extension based build patterns for Samba

import Task
from TaskGen import extension
from samba_utils import *

def SAMBA_MKVERSION(bld, target):
    '''generate the version.h header for Samba'''
    bld.SET_BUILD_GROUP('setup')
    t = bld(rule="cd .. && ${SRC[0].abspath(env)} VERSION ${TGT[0].abspath(env)}",
            source= [ "script/mkversion.sh", 'VERSION' ],
            target=target,
            shell=True,
            on_results=True,
            before="cc")
Build.BuildContext.SAMBA_MKVERSION = SAMBA_MKVERSION


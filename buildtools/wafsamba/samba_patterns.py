# a waf tool to add extension based build patterns for Samba

import Task
from TaskGen import extension
from samba_utils import *

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


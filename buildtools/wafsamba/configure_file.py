# handle substitution of variables in .in files

import sys
import re
import os
from waflib import Build, Logs
from samba_utils import SUBST_VARS_RECURSIVE

def subst_at_vars(task):
    '''substiture @VAR@ style variables in a file'''

    env = task.env
    s = task.inputs[0].read()

    # split on the vars
    a = re.split('(@\w+@)', s)
    out = []
    for v in a:
        if re.match('@\w+@', v):
            vname = v[1:-1]
            if not vname in task.env and vname.upper() in task.env:
                vname = vname.upper()
            if not vname in task.env:
                Logs.error("Unknown substitution %s in %s" % (v, task.name))
                sys.exit(1)
            v = SUBST_VARS_RECURSIVE(task.env[vname], task.env)
        out.append(v)
    contents = ''.join(out)
    task.outputs[0].write(contents)
    return 0

def CONFIGURE_FILE(bld, in_file, **kwargs):
    '''configure file'''

    base=os.path.basename(in_file)
    t = bld.SAMBA_GENERATOR('INFILE_%s' % base,
                            rule = subst_at_vars,
                            source = in_file + '.in',
                            target = in_file,
                            vars = kwargs)
Build.BuildContext.CONFIGURE_FILE = CONFIGURE_FILE

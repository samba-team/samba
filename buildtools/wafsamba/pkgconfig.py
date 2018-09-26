# handle substitution of variables in pc files

import os, re, sys
from waflib import Build, Logs
from samba_utils import SUBST_VARS_RECURSIVE, TO_LIST

def subst_at_vars(task):
    '''substiture @VAR@ style variables in a file'''

    s = task.inputs[0].read()
    # split on the vars
    a = re.split('(@\w+@)', s)
    out = []
    done_var = {}
    back_sub = [ ('PREFIX', '${prefix}'), ('EXEC_PREFIX', '${exec_prefix}')]
    for v in a:
        if re.match('@\w+@', v):
            vname = v[1:-1]
            if not vname in task.env and vname.upper() in task.env:
                vname = vname.upper()
            if not vname in task.env:
                Logs.error("Unknown substitution %s in %s" % (v, task.name))
                sys.exit(1)
            v = SUBST_VARS_RECURSIVE(task.env[vname], task.env)
            # now we back substitute the allowed pc vars
            for (b, m) in back_sub:
                s = task.env[b]
                if s == v[0:len(s)]:
                    if not b in done_var:
                        # we don't want to substitute the first usage
                        done_var[b] = True
                    else:
                        v = m + v[len(s):]
                    break
        out.append(v)
    contents = ''.join(out)
    task.outputs[0].write(contents)
    return 0


def PKG_CONFIG_FILES(bld, pc_files, vnum=None, extra_name=None):
    '''install some pkg_config pc files'''
    dest = '${PKGCONFIGDIR}'
    dest = bld.EXPAND_VARIABLES(dest)
    for f in TO_LIST(pc_files):
        if extra_name:
            target = f.split('.pc')[0] + extra_name + ".pc"
        else:
            target = f
        base=os.path.basename(target)
        t = bld.SAMBA_GENERATOR('PKGCONFIG_%s' % base,
                                rule=subst_at_vars,
                                source=f+'.in',
                                target=target)
        bld.add_manual_dependency(bld.path.find_or_declare(f), bld.env['PREFIX'].encode('utf8'))
        t.vars = []
        if t.env.RPATH_ON_INSTALL:
            t.env.LIB_RPATH = t.env.RPATH_ST % t.env.LIBDIR
        else:
            t.env.LIB_RPATH = ''
        if vnum:
            t.env.PACKAGE_VERSION = vnum
        for v in [ 'PREFIX', 'EXEC_PREFIX', 'LIB_RPATH' ]:
            t.vars.append(t.env[v])
        bld.INSTALL_FILES(dest, target, flat=True, destname=base)
Build.BuildContext.PKG_CONFIG_FILES = PKG_CONFIG_FILES



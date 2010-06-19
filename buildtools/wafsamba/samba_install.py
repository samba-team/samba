###########################
# this handles the magic we need to do for installing
# with all the configure options that affect rpath and shared
# library use

import Options
from TaskGen import feature, before, after
from samba_utils import *

@feature('install_bin')
@after('apply_core')
@before('apply_link', 'apply_obj_vars')
def install_binary(self):
    '''install a binary, taking account of the different rpath varients'''
    bld = self.bld

    # get the ldflags we will use for install and build
    install_ldflags = install_rpath(bld)
    build_ldflags   = build_rpath(bld)

    if not Options.is_install or not self.samba_install:
        # just need to set rpath if we are not installing
        self.env.RPATH = build_ldflags
        return

    # work out the install path, expanding variables
    install_path = self.samba_inst_path or '${BINDIR}'
    install_path = bld.EXPAND_VARIABLES(install_path)

    orig_target = os.path.basename(self.target)

    if install_ldflags != build_ldflags:
        # we will be creating a new target name, and using that for the
        # install link. That stops us from overwriting the existing build
        # target, which has different ldflags
        self.target += '.inst'

    # setup the right rpath link flags for the install
    self.env.RPATH = install_ldflags

    # tell waf to install the right binary
    bld.install_as(os.path.join(install_path, orig_target),
                   os.path.join(self.path.abspath(bld.env), self.target),
                   chmod=0755)



@feature('install_lib')
@after('apply_core')
@before('apply_link', 'apply_obj_vars')
def install_library(self):
    '''install a library, taking account of the different rpath varients'''
    if getattr(self, 'done_install_library', False):
        return

    bld = self.bld

    install_ldflags = install_rpath(bld)
    build_ldflags   = build_rpath(bld)

    if not Options.is_install or not self.samba_install:
        # just need to set the build rpath if we are not installing
        self.env.RPATH = build_ldflags
        return

    # setup the install path, expanding variables
    install_path = self.samba_inst_path or '${LIBDIR}'
    install_path = bld.EXPAND_VARIABLES(install_path)

    if install_ldflags != build_ldflags:
        # we will be creating a new target name, and using that for the
        # install link. That stops us from overwriting the existing build
        # target, which has different ldflags
        self.done_install_library = True
        t = self.clone('default')
        t.posted = False
        t.target += '.inst'
        self.env.RPATH = build_ldflags
    else:
        t = self

    t.env.RPATH = install_ldflags

    dev_link     = None

    if self.samba_realname:
        install_name = self.samba_realname
        install_link = None
        if getattr(self, 'samba_type', None) == 'PYTHON':
            inst_name    = '%s.so' % t.target
        else:
            inst_name    = 'lib%s.so' % t.target
    elif self.vnum:
        vnum_base    = self.vnum.split('.')[0]
        install_name = 'lib%s.so.%s' % (self.target, self.vnum)
        install_link = 'lib%s.so.%s' % (self.target, vnum_base)
        inst_name    = 'lib%s.so' % t.target
        if not self.is_bundled:
            # only generate the dev link for non-bundled libs
            dev_link     = 'lib%s.so' % self.target
    else:
        install_name = 'lib%s.so' % self.target
        install_link = None
        inst_name    = 'lib%s.so' % t.target

    if t.env.SONAME_ST and install_link:
        t.env.append_value('LINKFLAGS', t.env.SONAME_ST % install_link)
        t.env.SONAME_ST = ''

    # tell waf to install the library
    bld.install_as(os.path.join(install_path, install_name),
                   os.path.join(self.path.abspath(bld.env), inst_name))
    if install_link:
        # and the symlink if needed
        bld.symlink_as(os.path.join(install_path, install_link),
                       install_name)
    if dev_link:
        bld.symlink_as(os.path.join(install_path, dev_link),
                       install_name)



##############################
# handle the creation of links for libraries and binaries in the build tree

@feature('symlink_lib')
@after('apply_link')
def symlink_lib(self):
    '''symlink a shared lib'''

    if self.target.endswith('.inst'):
        return

    blddir = os.path.dirname(self.bld.srcnode.abspath(self.bld.env))
    libpath = self.link_task.outputs[0].abspath(self.env)

    # calculat the link target and put it in the environment
    soext=""
    vnum = getattr(self, 'vnum', None)
    if vnum is not None:
        soext = '.' + vnum.split('.')[0]

    link_target = getattr(self, 'link_name', '')
    if link_target == '':
        link_target = '%s/lib%s.so%s' % (LIB_PATH, self.target, soext)

    link_target = os.path.join(blddir, link_target)

    if os.path.lexists(link_target):
        if os.path.islink(link_target) and os.readlink(link_target) == libpath:
            return
        os.unlink(link_target)
    os.symlink(libpath, link_target)


@feature('symlink_bin')
@after('apply_link')
def symlink_bin(self):
    '''symlink a binary into the build directory'''

    if self.target.endswith('.inst'):
        return

    blddir = os.path.dirname(self.bld.srcnode.abspath(self.bld.env))
    binpath = self.link_task.outputs[0].abspath(self.env)
    bldpath = os.path.join(self.bld.env.BUILD_DIRECTORY, self.link_task.outputs[0].name)

    if os.path.lexists(bldpath):
        if os.path.islink(bldpath) and os.readlink(bldpath) == binpath:
            return
        os.unlink(bldpath)
    os.symlink(binpath, bldpath)

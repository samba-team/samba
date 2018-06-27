# compatibility layer for building with more recent waf versions

import os, shlex, sys
from waflib import Build, Configure, Node, Utils, Options, Logs
from waflib import ConfigSet
from waflib.TaskGen import feature, after
from waflib.Configure import conf, ConfigurationContext

from waflib.Tools import bison, flex
sys.modules['bison'] = bison
sys.modules['flex'] = flex

for y in (Build.BuildContext, Build.CleanContext, Build.InstallContext, Build.UninstallContext, Build.ListContext):
    class tmp(y):
        variant = 'default'

def pre_build(self):
    self.cwdx = self.bldnode.parent
    self.cwd = self.cwdx.abspath()
    self.bdir = self.bldnode.abspath()
    return Build.BuildContext.old_pre_build(self)
Build.BuildContext.old_pre_build = Build.BuildContext.pre_build
Build.BuildContext.pre_build = pre_build

def abspath(self, env=None):
    if env and hasattr(self, 'children'):
        return self.get_bld().abspath()
    return self.old_abspath()
Node.Node.old_abspath = Node.Node.abspath
Node.Node.abspath = abspath

def bldpath(self, env=None):
    return self.abspath()
    #return self.path_from(self.ctx.bldnode.parent)
Node.Node.bldpath = bldpath

def srcpath(self, env=None):
    return self.abspath()
    #return self.path_from(self.ctx.bldnode.parent)
Node.Node.srcpath = srcpath

def store_fast(self, filename):
    file = open(filename, 'wb')
    data = self.get_merged_dict()
    try:
        Build.cPickle.dump(data, file, -1)
    finally:
        file.close()
ConfigSet.ConfigSet.store_fast = store_fast

def load_fast(self, filename):
    file = open(filename, 'rb')
    try:
        data = Build.cPickle.load(file)
    finally:
        file.close()
    self.table.update(data)
ConfigSet.ConfigSet.load_fast = load_fast

@feature('c', 'cxx', 'd', 'asm', 'fc', 'includes')
@after('propagate_uselib_vars', 'process_source')
def apply_incpaths(self):
    lst = self.to_incnodes(self.to_list(getattr(self, 'includes', [])) + self.env['INCLUDES'])
    self.includes_nodes = lst
    cwdx = getattr(self.bld, 'cwdx', self.bld.bldnode)
    self.env['INCPATHS'] = [x.path_from(cwdx) for x in lst]

@conf
def define(self, key, val, quote=True, comment=None):
   assert key and isinstance(key, str)

   if val is True:
           val = 1
   elif val in (False, None):
           val = 0

   # waf 1.5
   self.env[key] = val

   if isinstance(val, int) or isinstance(val, float):
           s = '%s=%s'
   else:
           s = quote and '%s="%s"' or '%s=%s'
   app = s % (key, str(val))

   ban = key + '='
   lst = self.env.DEFINES
   for x in lst:
           if x.startswith(ban):
                   lst[lst.index(x)] = app
                   break
   else:
           self.env.append_value('DEFINES', app)

   self.env.append_unique('define_key', key)

# compat15 removes this but we want to keep it
@conf
def undefine(self, key, from_env=True, comment=None):
    assert key and isinstance(key, str)

    ban = key + '='
    self.env.DEFINES = [x for x in self.env.DEFINES if not x.startswith(ban)]
    self.env.append_unique('define_key', key)
    # waf 1.5
    if from_env:
        self.env[key] = ()

def install_dir(self, path):
        if not path:
                return []

        destpath = Utils.subst_vars(path, self.env)

        if self.is_install > 0:
                Logs.info('* creating %s', destpath)
                Utils.check_dir(destpath)
        elif self.is_install < 0:
                Logs.info('* removing %s', destpath)
                try:
                        os.remove(destpath)
                except OSError:
                        pass
Build.BuildContext.install_dir = install_dir

class ConfigurationContext(Configure.ConfigurationContext):
    def init_dirs(self):
        self.setenv('default')
        self.env.merge_config_header = True
        return super(ConfigurationContext, self).init_dirs()

def find_program_samba(self, *k, **kw):
    kw['mandatory'] = False
    ret = self.find_program_old(*k, **kw)
    return ret
Configure.ConfigurationContext.find_program_old = Configure.ConfigurationContext.find_program
Configure.ConfigurationContext.find_program = find_program_samba

Build.BuildContext.ENFORCE_GROUP_ORDERING = Utils.nada
Build.BuildContext.AUTOCLEANUP_STALE_FILES = Utils.nada

@conf
def check(self, *k, **kw):
    '''Override the waf defaults to inject --with-directory options'''

    # match the configuration test with speficic options, for example:
    # --with-libiconv -> Options.options.iconv_open -> "Checking for library iconv"
    self.validate_c(kw)

    additional_dirs = []
    if 'msg' in kw:
        msg = kw['msg']
        for x in Options.OptionsContext.parser.parser.option_list:
             if getattr(x, 'match', None) and msg in x.match:
                 d = getattr(Options.options, x.dest, '')
                 if d:
                     additional_dirs.append(d)

    # we add the additional dirs twice: once for the test data, and again if the compilation test suceeds below
    def add_options_dir(dirs, env):
        for x in dirs:
             if not x in env.CPPPATH:
                 env.CPPPATH = [os.path.join(x, 'include')] + env.CPPPATH
             if not x in env.LIBPATH:
                 env.LIBPATH = [os.path.join(x, 'lib')] + env.LIBPATH

    add_options_dir(additional_dirs, kw['env'])

    self.start_msg(kw['msg'], **kw)
    ret = None
    try:
        ret = self.run_build(*k, **kw)
    except self.errors.ConfigurationError:
        self.end_msg(kw['errmsg'], 'YELLOW', **kw)
        if Logs.verbose > 1:
            raise
        else:
            self.fatal('The configuration failed')
    else:
        kw['success'] = ret
        # success! time for brandy
        add_options_dir(additional_dirs, self.env)

    ret = self.post_check(*k, **kw)
    if not ret:
        self.end_msg(kw['errmsg'], 'YELLOW', **kw)
        self.fatal('The configuration failed %r' % ret)
    else:
        self.end_msg(self.ret_msg(kw['okmsg'], kw), **kw)
    return ret

@conf
def CHECK_LIBRARY_SUPPORT(conf, rpath=False, version_script=False, msg=None):
    '''see if the platform supports building libraries'''

    if msg is None:
        if rpath:
            msg = "rpath library support"
        else:
            msg = "building library support"

    def build(bld):
        lib_node = bld.srcnode.make_node('libdir/liblc1.c')
        lib_node.parent.mkdir()
        lib_node.write('int lib_func(void) { return 42; }\n', 'w')
        main_node = bld.srcnode.make_node('main.c')
        main_node.write('int main(void) {return !(lib_func() == 42);}', 'w')
        linkflags = []
        if version_script:
            script = bld.srcnode.make_node('ldscript')
            script.write('TEST_1.0A2 { global: *; };\n', 'w')
            linkflags.append('-Wl,--version-script=%s' % script.abspath())
        bld(features='c cshlib', source=lib_node, target='lib1', linkflags=linkflags, name='lib1')
        o = bld(features='c cprogram', source=main_node, target='prog1', uselib_local='lib1')
        if rpath:
            o.rpath = [lib_node.parent.abspath()]
        def run_app(self):
             args = conf.SAMBA_CROSS_ARGS(msg=msg)
             env = dict(os.environ)
             env['LD_LIBRARY_PATH'] = self.inputs[0].parent.abspath() + os.pathsep + env.get('LD_LIBRARY_PATH', '')
             self.generator.bld.cmd_and_log([self.inputs[0].abspath()] + args, env=env)
        o.post()
        bld(rule=run_app, source=o.link_task.outputs[0])

    # ok, so it builds
    try:
        conf.check(build_fun=build, msg='Checking for %s' % msg)
    except conf.errors.ConfigurationError:
        return False
    return True

@conf
def CHECK_NEED_LC(conf, msg):
    '''check if we need -lc'''
    def build(bld):
        lib_node = bld.srcnode.make_node('libdir/liblc1.c')
        lib_node.parent.mkdir()
        lib_node.write('#include <stdio.h>\nint lib_func(void) { FILE *f = fopen("foo", "r");}\n', 'w')
        bld(features='c cshlib', source=[lib_node], linkflags=conf.env.EXTRA_LDFLAGS, target='liblc')
    try:
        conf.check(build_fun=build, msg=msg, okmsg='-lc is unnecessary', errmsg='-lc is necessary')
    except conf.errors.ConfigurationError:
        return False
    return True

# already implemented on "waf -v"
def order(bld, tgt_list):
    return True
Build.BuildContext.check_group_ordering = order

@conf
def CHECK_CFG(self, *k, **kw):
    if 'args' in kw:
        kw['args'] = shlex.split(kw['args'])
    if not 'mandatory' in kw:
        kw['mandatory'] = False
    kw['global_define'] = True
    return self.check_cfg(*k, **kw)

def cmd_output(cmd, **kw):

	silent = False
	if 'silent' in kw:
		silent = kw['silent']
		del(kw['silent'])

	if 'e' in kw:
		tmp = kw['e']
		del(kw['e'])
		kw['env'] = tmp

	kw['shell'] = isinstance(cmd, str)
	kw['stdout'] = Utils.subprocess.PIPE
	if silent:
		kw['stderr'] = Utils.subprocess.PIPE

	try:
		p = Utils.subprocess.Popen(cmd, **kw)
		output = p.communicate()[0]
	except OSError as e:
		raise ValueError(str(e))

	if p.returncode:
		if not silent:
			msg = "command execution failed: %s -> %r" % (cmd, str(output))
			raise ValueError(msg)
		output = ''
	return output
Utils.cmd_output = cmd_output

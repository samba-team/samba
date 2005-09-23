"""SCons.Tool.pidl

Tool-specific initialization for pidl (Perl-based IDL compiler)

"""

import SCons.Defaults
import SCons.Util
import SCons.Scanner

idl_scanner = SCons.Scanner.ClassicCPP("PIDLScan", '.idl', 'CPPPATH', r'depends\(([^,]+),+\)', SCons.Node.FS.default_fs)

def idl_emitter(target, source, env):
	base, ext = SCons.Util.splitext(str(source[0]))
	result = ['gen_ndr/ndr_%s.c' % base, 'gen_ndr/ndr_%s.h' % base]
	return result, source

pidl_builder = SCons.Builder.Builder(action='$PIDLCOM',
				     emitter = idl_emitter,
                                     src_suffix = '.idl',
                                     suffix='.c',
                                     scanner = idl_scanner)

def generate(env):
	env['PIDL']          = env.Detect('pidl') or './pidl/pidl'
	env['PIDLFLAGS']     = ['--outputdir', 'librpc/gen_ndr', '--ndr-header', '--ndr-parser']
	env['PIDLCOM']       = '$PIDL $PIDLFLAGS -- $SOURCE'
	env['BUILDERS']['NdrMarshaller'] = pidl_builder

def exists(env):
	return env.Detect(['./pidl/pidl','pidl'])

"""SCons.Tool.pidl

Tool-specific initialization for pidl (Perl-based IDL compiler)

"""

import SCons.Defaults
import SCons.Util
import SCons.Scanner

idl_scanner = SCons.Scanner.ClassicCPP("PIDLScan", '.idl', 'CPPPATH', r'depends\(([^,]+),+\)', SCons.Node.FS.default_fs)

def idl_emitter(target, source, env):
	result = []
	for s in source:
		base, ext = SCons.Util.splitext(str(s).split('/')[-1])
		result.append('gen_ndr/ndr_%s.c' % base)
		result.append('gen_ndr/ndr_%s.h' % base)
		result.append('gen_ndr/%s.h' % base)
	return result, source

pidl_builder = SCons.Builder.Builder(action='$PIDLCOM',
				     emitter = idl_emitter,
					 src_suffix = '.idl',
                     scanner = idl_scanner)

def generate(env):
	env['PIDL']          = env.Detect(['./pidl/pidl', 'pidl'])
	env['PIDLFLAGS']     = ['--outputdir', 'librpc/gen_ndr', '--ndr-header', '--ndr-parser', '--header']
	env['PIDLCOM']       = '$PIDL $PIDLFLAGS -- $SOURCE'
	env['BUILDERS']['NdrMarshaller'] = pidl_builder

def exists(env):
	return env.Detect(['./pidl/pidl','pidl'])

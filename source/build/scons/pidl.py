"""SCons.Tool.pidl

Tool-specific initialization for pidl (Perl-based IDL compiler)

"""

import SCons.Defaults
import SCons.Util
import SCons.Scanner

idl_scanner = SCons.Scanner.ClassicCPP("PIDLScan", '.idl', 'CPPPATH', r'depends\(([^,]+),+\)', SCons.Node.FS.default_fs)

def ndr_emitter(target, source, env):
	result = []
	for s in source:
		base, ext = SCons.Util.splitext(str(s).split('/')[-1])
		result.append('gen_ndr/ndr_%s.c' % base)
		result.append('gen_ndr/ndr_%s.h' % base)
		result.append('gen_ndr/%s.h' % base)
	return result, source

ndr_builder = SCons.Builder.Builder(action='$NDRCOM',
				     emitter = ndr_emitter,
					 src_suffix = '.idl',
                     scanner = idl_scanner)

def tdr_emitter(target, source, env):
	result = []
	for s in source:
		base, ext = SCons.Util.splitext(str(s).split('/')[-1])
		result.append('%s/tdr_%s.c' % (s.get_dir(), base))
		result.append('%s/tdr_%s.h' % (s.get_dir(), base))
		result.append('%s/%s.h' % (s.get_dir(), base))
	return result, source

tdr_builder = SCons.Builder.Builder(action='$TDRCOM',
				     emitter = tdr_emitter,
					 src_suffix = '.idl',
					 single_source = True,
                     scanner = idl_scanner)

def generate(env):
	env['PIDL']          = env.Detect(['./pidl/pidl', 'pidl'])
	env['NDRFLAGS']     = ['--outputdir', 'librpc/gen_ndr','--ndr-header', '--ndr-parser','--header']
	env['TDRFLAGS']     = ['--tdr-parser', '--tdr-header','--header']
	env['NDRCOM']       = '$PIDL $NDRFLAGS -- $SOURCES'
	env['TDRCOM']       = 'cd ${SOURCE.dir} && $PIDL $TDRFLAGS -- ${SOURCE.file}'
	env['BUILDERS']['NdrMarshaller'] = ndr_builder
	env['BUILDERS']['TdrMarshaller'] = tdr_builder

def exists(env):
	return env.Detect(['./pidl/pidl','pidl'])

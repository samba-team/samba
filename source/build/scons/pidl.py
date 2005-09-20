"""SCons.Tool.pidl

Tool-specific initialization for pidl (Perl-based IDL compiler)

"""

import SCons.Defaults
import SCons.Util
import SCons.Scanner

idl_scanner = SCons.Scanner.ClassicCPP("PIDLScan", '.idl', 'CPPPATH', r'depends\(([^,]+),+\)', SCons.Node.FS.default_fs)

pidl_builder = SCons.Builder.Builder(action='$PIDLCOM',
                                     src_suffix = '.idl',
                                     suffix='.c',
                                     scanner = idl_scanner)

def generate(env):
	env['PIDL']          = env.Detect('pidl') or './pidl/pidl'
	env['PIDLFLAGS']     = []
	env['PIDLCOM']       = 'CPP=$CPP $PIDL $PIDLFLAGS -- $SOURCE'
	env['BUILDERS']['NdrMarshaller'] = pidl_builder

def exists(env):
	return env.Detect(['./pidl/pidl','pidl'])

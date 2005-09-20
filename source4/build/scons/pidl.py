"""SCons.Tool.pidl

Tool-specific initialization for pidl (Perl-based IDL compiler)

"""

import SCons.Defaults
import SCons.Scanner.IDL
import SCons.Util

idl_scanner = SCons.Scanner.IDL.IDLScan()

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

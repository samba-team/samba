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
    env['PIDL']          = 'pidl'
	env['PIDLCPP']		 = env['CPP']
    env['PIDLFLAGS']     = []
    env['PIDLCOM']       = 'CPP=$PIDLCPP $PIDL $PIDLFLAGS -- $SOURCE'
    env['BUILDERS']['NdrMarshaller'] = pidl_builder

def exists(env):
	if (env.Detect('./pidl/pidl')):
		return 1

	if (env.Detect('pidl')):
		return 1

	return 0

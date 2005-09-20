"""SCons.Tool.et

Tool-specific initialization for et

"""

import SCons.Defaults
import SCons.Util
import SCons.Tool

et_builder = SCons.Builder.Builder(action='$ETCOM',
                                     src_suffix = '.et',
                                     suffix='.c')

def generate(env):
    env['ET']          = env.Detect('et_compile')
    env['ETCOM']       = '$ET $SOURCE'
    env['BUILDERS']['ET'] = et_builder

def exists(env):
	return env.Detect(['et_compile'])

def generate(env):
    """Add Builders and construction variables for lex to an Environment."""
    c_file, cxx_file = SCons.Tool.createCFileBuilders(env)

    c_file.add_action('.l', SCons.Defaults.LexAction)
    cxx_file.add_action('.ll', SCons.Defaults.LexAction)

    env['LEX']      = env.Detect('flex') or 'lex'
    env['LEXFLAGS'] = SCons.Util.CLVar('')
    env['LEXCOM']   = '$LEX $LEXFLAGS -t $SOURCES > $TARGET'
    

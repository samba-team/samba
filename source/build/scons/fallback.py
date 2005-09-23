# Generate fallback configure + Makefile
# Copyright (C) 2005 Jelmer Vernooij <jelmer@samba.org>

# No support for:
#  - cross-compilation
#  - caching
#  - config.status (?)

import SCons.Defaults
import SCons.Util
import SCons.Tool

# Configure structure:
# - Check for available tools first
# - Check for available tool capabilities (C99, volatile, etc)
# - Check for available `base' headers 
# - Check for available types
# - Check for libs / headers
def configure_builder(target, source, env):
	pass

# Makefile structure:
# - Declare all variables first
# - Declare targets + dependencies + actions

def makefile_builder(target, source, env):
	pass

def generate(env):
    env['BUILDERS']['ConfigureScript'] = configure_builder
    env['BUILDERS']['MakefileIn'] = makefile_in_builder

def exists(env):
	return 1

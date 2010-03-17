# a includes processing tool to speed up include path calculations

from TaskGen import feature, before, after
import preproc
import os

kak = {}
@feature('cc', 'cxx')
@after('apply_type_vars', 'apply_lib_vars', 'apply_core')
def apply_incpaths(self):
	lst = []
	# TODO move the uselib processing out of here
	for lib in self.to_list(self.uselib):
		for path in self.env['CPPPATH_' + lib]:
			if not path in lst:
				lst.append(path)
	if preproc.go_absolute:
		for path in preproc.standard_includes:
			if not path in lst:
				lst.append(path)

	for path in self.to_list(self.includes):
		if not path in lst:
			if preproc.go_absolute or not os.path.isabs(path):
				lst.append(path)
			else:
				self.env.prepend_value('CPPPATH', path)

	for path in lst:
		node = None
		if os.path.isabs(path):
			if preproc.go_absolute:
				node = self.bld.root.find_dir(path)
		elif path[0] == '#':
			node = self.bld.srcnode
			if len(path) > 1:
				try:
					node = kak[path]
				except KeyError:
					kak[path] = node = node.find_dir(path[1:])
		else:
			try:
				node = kak[(self.path.id, path)]
			except KeyError:
				kak[(self.path.id, path)] = node = self.path.find_dir(path)

		if node:
			self.env.append_value('INC_PATHS', node)

cac = {}
@feature('cc')
@after('apply_incpaths')
def apply_obj_vars_cc(self):
    """after apply_incpaths for INC_PATHS"""
    env = self.env
    app = env.append_unique
    cpppath_st = env['CPPPATH_ST']

    global cac

    # local flags come first
    # set the user-defined includes paths
    for i in env['INC_PATHS']:

        try:
            app('_CCINCFLAGS', cac[i.id])
        except KeyError:
            cac[i.id] = [cpppath_st % i.bldpath(env), cpppath_st % i.srcpath(env)]
            app('_CCINCFLAGS', cac[i.id])

    # set the library include paths
    for i in env['CPPPATH']:
        app('_CCINCFLAGS', cpppath_st % i)

import Node, Environment

def vari(self):
	return "default"
Environment.Environment.variant = vari

def variant(self, env):
	if not env: return 0
	elif self.id & 3 == Node.FILE: return 0
	else: return "default"
Node.Node.variant = variant




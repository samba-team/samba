#! /usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2015

"""
Force tasks to use file timestamps to force partial rebuilds when touch-ing build files

touch out/libfoo.a
... rebuild what depends on libfoo.a

to use::
    def options(opt):
        opt.tool_options('build_file_tracker')
"""

import os
import Task, Utils

def signature(self):
	try: return self.cache_sig[0]
	except AttributeError: pass

	self.m = Utils.md5()

	# explicit deps
	exp_sig = self.sig_explicit_deps()

	# env vars
	var_sig = self.sig_vars()

	# implicit deps
	imp_sig = Task.SIG_NIL
	if self.scan:
		try:
			imp_sig = self.sig_implicit_deps()
		except ValueError:
			return self.signature()

	# timestamp dependency on build files only (source files are hashed)
	buf = []
	for k in self.inputs + getattr(self, 'dep_nodes', []) + self.generator.bld.node_deps.get(self.unique_id(), []):
		if k.id & 3 == 3:
			t = os.stat(k.abspath(self.env)).st_mtime
			buf.append(t)
	self.m.update(str(buf))

	# we now have the signature (first element) and the details (for debugging)
	ret = self.m.digest()
	self.cache_sig = (ret, exp_sig, imp_sig, var_sig)
	return ret

Task.Task.signature_bak = Task.Task.signature # unused, kept just in case
Task.Task.signature = signature # overridden

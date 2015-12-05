#!/usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2008-2010 (ita)

"""
Execute the tasks with gcc -MD, read the dependencies from the .d file
and prepare the dependency calculation for the next run.

Usage:
	def configure(conf):
		conf.load('gccdeps')
"""

import os, re, threading
import Options, Task, Logs, Utils, Constants, preproc
from TaskGen import before, feature

lock = threading.Lock()

gccdeps_flags = ['-MD']
if not preproc.go_absolute:
	gccdeps_flags = ['-MMD']

# Third-party tools are allowed to add extra names in here with append()
supported_compilers = ['gcc', 'icc', 'clang']

def scan(self):
	if not self.__class__.__name__ in self.env.ENABLE_GCCDEPS:
		if not self.env.GCCDEPS:
			raise Utils.WafError('Load gccdeps in configure!')
		return self.no_gccdeps_scan()
	nodes = self.generator.bld.node_deps.get(self.unique_id(), [])
	names = []
	return (nodes, names)

re_o = re.compile("\.o$")
re_splitter = re.compile(r'(?<!\\)\s+') # split by space, except when spaces are escaped

def remove_makefile_rule_lhs(line):
	# Splitting on a plain colon would accidentally match inside a
	# Windows absolute-path filename, so we must search for a colon
	# followed by whitespace to find the divider between LHS and RHS
	# of the Makefile rule.
	rulesep = ': '

	sep_idx = line.find(rulesep)
	if sep_idx >= 0:
		return line[sep_idx + 2:]
	else:
		return line

def path_to_node(base_node, path, cached_nodes):
	# Take the base node and the path and return a node
	# Results are cached because searching the node tree is expensive
	# The following code is executed by threads, it is not safe, so a lock is needed...
	if getattr(path, '__hash__'):
		node_lookup_key = (id(base_node), path)
	else:
		# Not hashable, assume it is a list and join into a string
		node_lookup_key = (id(base_node), os.path.sep.join(path))
	try:
		lock.acquire()
		node = cached_nodes[node_lookup_key]
	except KeyError:
		node = base_node.find_resource(path)
		cached_nodes[node_lookup_key] = node
	finally:
		lock.release()
	return node

def post_run(self):
	# The following code is executed by threads, it is not safe, so a lock is needed...

	if not self.__class__.__name__ in self.env.ENABLE_GCCDEPS:
		return self.no_gccdeps_post_run()

	if getattr(self, 'cached', None):
		return Task.Task.post_run(self)

	name = self.outputs[0].abspath(self.env)
	name = re_o.sub('.d', name)
	txt = Utils.readf(name)
	#os.remove(name)

	# Compilers have the choice to either output the file's dependencies
	# as one large Makefile rule:
	#
	#   /path/to/file.o: /path/to/dep1.h \
	#                    /path/to/dep2.h \
	#                    /path/to/dep3.h \
	#                    ...
	#
	# or as many individual rules:
	#
	#   /path/to/file.o: /path/to/dep1.h
	#   /path/to/file.o: /path/to/dep2.h
	#   /path/to/file.o: /path/to/dep3.h
	#   ...
	#
	# So the first step is to sanitize the input by stripping out the left-
	# hand side of all these lines. After that, whatever remains are the
	# implicit dependencies of task.outputs[0]
	txt = '\n'.join([remove_makefile_rule_lhs(line) for line in txt.splitlines()])

	# Now join all the lines together
	txt = txt.replace('\\\n', '')

	val = txt.strip()
	val = [x.replace('\\ ', ' ') for x in re_splitter.split(val) if x]

	nodes = []
	bld = self.generator.bld
	variant = self.env.variant()

	# Dynamically bind to the cache
	try:
		cached_nodes = bld.cached_nodes
	except AttributeError:
		cached_nodes = bld.cached_nodes = {}

	for x in val:

		node = None
		if os.path.isabs(x):
			if not preproc.go_absolute:
				continue
			node = path_to_node(bld.root, x, cached_nodes)
		else:
			# when calling find_resource, make sure the path does not contain '..'
			x = [k for k in Utils.split_path(x) if k and k != '.']


			level = 0
			while '..' in x:
				idx = x.index('..')
				if idx == 0:
					x = x[1:]
					level += 1
				else:
					del x[idx]
					del x[idx-1]

			path = bld.bldnode
			if x and x[0] == variant:
				x = x[1:]
				path = bld.srcnode
			else:
				while level:
					path = path.parent
					level -= 1
			node = path_to_node(path, x, cached_nodes)

		if not node:
			raise ValueError('could not find %r for %r' % (x, self))

		if id(node) == id(self.inputs[0]):
			# ignore the source file, it is already in the dependencies
			# this way, successful config tests may be retrieved from the cache
			continue
		nodes.append(node)

	Logs.debug('deps: gccdeps for %s returned %s' % (str(self), str(nodes)))
	bld.node_deps[self.unique_id()] = nodes
	bld.raw_deps[self.unique_id()] = []

	try:
		del self.cache_sig
	except AttributeError:
		pass

	Task.Task.post_run(self)

def sig_implicit_deps(self):
	if not self.__class__.__name__ in self.env.ENABLE_GCCDEPS:
		return self.no_gccdeps_sig_implicit_deps()
	try:
		return Task.Task.sig_implicit_deps(self)
	except Utils.WafError:
		return Constants.SIG_NIL

for name in 'cc cxx'.split():
	try:
		cls = Task.TaskBase.classes[name]
	except KeyError:
		pass
	else:
		cls.no_gccdeps_scan = cls.scan
		cls.no_gccdeps_post_run = cls.post_run
		cls.no_gccdeps_sig_implicit_deps = cls.sig_implicit_deps

		cls.scan = scan
		cls.post_run = post_run
		cls.sig_implicit_deps = sig_implicit_deps

@before('apply_core')
@feature('force_gccdeps')
def force_gccdeps(self):
	self.env.ENABLE_GCCDEPS = ['cc', 'cxx']

def detect(conf):
	# record that the configuration was executed properly
	conf.env.GCCDEPS = True

	# in case someone provides a --enable-gccdeps or --disable-gccdeps command-line option
	if not getattr(Options.options, 'enable_gccdeps', True):
		return

	global gccdeps_flags
	flags = conf.env.GCCDEPS_FLAGS or gccdeps_flags
	if conf.env.CC_NAME in supported_compilers:
		try:
			conf.check(fragment='int main() { return 0; }', features='c force_gccdeps', ccflags=flags, msg='Checking for c flags %r' % ''.join(flags))
		except Utils.WafError:
			pass
		else:
			conf.env.append_value('CCFLAGS', gccdeps_flags)
			conf.env.append_unique('ENABLE_GCCDEPS', 'cc')

	if conf.env.CXX_NAME in supported_compilers:
		try:
			conf.check(fragment='int main() { return 0; }', features='cxx force_gccdeps', cxxflags=flags, msg='Checking for cxx flags %r' % ''.join(flags))
		except Utils.WafError:
			pass
		else:
			conf.env.append_value('CXXFLAGS', gccdeps_flags)
			conf.env.append_unique('ENABLE_GCCDEPS', 'cxx')


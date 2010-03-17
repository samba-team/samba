#!/usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2008-2010 (ita)

"""
Execute the tasks with gcc -MD, read the dependencies from the .d file
and prepare the dependency calculation for the next run
"""

import os, re, threading
import Task, Logs, Utils, preproc

lock = threading.Lock()


def detect(conf):
	conf.env.append_unique('CCFLAGS', '-MD')

def scan(self):
	"the scanner does not do anything initially"
	nodes = self.generator.bld.node_deps.get(self.unique_id(), [])
	names = []
	return (nodes, names)

re_src = re.compile("^(\.\.)[\\/](.*)$")

def post_run(self):
	# The following code is executed by threads, it is not safe, so a lock is needed...

	if getattr(self, 'cached', None):
		return Task.Task.post_run(self)

	name = self.outputs[0].abspath(self.env)
	name = name.rstrip('.o') + '.d'
	txt = Utils.readf(name)
	#os.unlink(name)

	txt = txt.replace('\\\n', '')

	lst = txt.strip().split(':')
	val = ":".join(lst[1:])
	val = val.split()

	nodes = []
	bld = self.generator.bld

	f = re.compile("^("+self.env.variant()+"|\.\.)[\\/](.*)$")
	for x in val:
		if os.path.isabs(x):

			if not preproc.go_absolute:
				continue

			lock.acquire()
			try:
				node = bld.root.find_resource(x)
			finally:
				lock.release()
		else:
			g = re.search(re_src, x)
			if g:
				x = g.group(2)
				lock.acquire()
				try:
					node = bld.bldnode.parent.find_resource(x)
				finally:
					lock.release()
			else:
				g = re.search(f, x)
				if g:
					x = g.group(2)
					lock.acquire()
					try:
						node = bld.srcnode.find_resource(x)
					finally:
						lock.release()

		if id(node) == id(self.inputs[0]):
			# ignore the source file, it is already in the dependencies
			# this way, successful config tests may be retrieved from the cache
			continue

		if not node:
			raise ValueError('could not find %r for %r' % (x, self))
		else:
			nodes.append(node)

	Logs.debug('deps: real scanner for %s returned %s' % (str(self), str(nodes)))

	bld.node_deps[self.unique_id()] = nodes
	bld.raw_deps[self.unique_id()] = []

	try:
		del self.cache_sig
	except:
		pass

	Task.Task.post_run(self)

for name in 'cc cxx'.split():
	try:
		cls = Task.TaskBase.classes[name]
	except KeyError:
		pass
	else:
		cls.post_run = post_run
		cls.scan = scan


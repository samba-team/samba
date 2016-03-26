#! /usr/bin/env python
# encoding: utf-8
# WARNING! Do not edit! https://waf.io/book/index.html#_obtaining_the_waf_file

#!/usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2005-2016 (ita)

"""
Runner.py: Task scheduling and execution
"""

import random
try:
	from queue import Queue
except ImportError:
	from Queue import Queue
from waflib import Utils, Task, Errors, Logs

GAP = 20
"""
Wait for at least ``GAP * njobs`` before trying to enqueue more tasks to run
"""

class Consumer(Utils.threading.Thread):
	"""
	Daemon thread object that executes a task. It shares a semaphore with
	the coordinator :py:class:`waflib.Runner.Spawner`. There is one
	instance per task to consume.
	"""
	def __init__(self, spawner, task):
		Utils.threading.Thread.__init__(self)
		self.task = task
		"""Task to execute"""
		self.spawner = spawner
		"""Coordinator object"""
		self.setDaemon(1)
		self.start()
	def run(self):
		"""
		Processes a single task
		"""
		try:
			if not self.spawner.master.stop:
				self.task.process()
		finally:
			self.spawner.sem.release()
			self.spawner.master.out.put(self.task)
			self.task = None
			self.spawner = None

class Spawner(Utils.threading.Thread):
	"""
	Daemon thread that consumes tasks from :py:class:`waflib.Runner.Parallel` producer and
	spawns a consuming thread :py:class:`waflib.Runner.Consumer` for each
	:py:class:`waflib.Task.TaskBase` instance.
	"""
	def __init__(self, master):
		Utils.threading.Thread.__init__(self)
		self.master = master
		""":py:class:`waflib.Runner.Parallel` producer instance"""
		self.sem = Utils.threading.Semaphore(master.numjobs)
		"""Bounded semaphore that prevents spawning more than *n* concurrent consumers"""
		self.setDaemon(1)
		self.start()
	def run(self):
		"""
		Spawns new consumers to execute tasks by delegating to :py:meth:`waflib.Runner.Spawner.loop`
		"""
		try:
			self.loop()
		except Exception:
			# Python 2 prints unnecessary messages when shutting down
			# we also want to stop the thread properly
			pass
	def loop(self):
		"""
		Consumes task objects from the producer; ends when the producer has no more
		task to provide.
		"""
		master = self.master
		while 1:
			task = master.ready.get()
			self.sem.acquire()
			if not master.stop:
				task.log_display(task.generator.bld)
			Consumer(self, task)

class Parallel(object):
	"""
	Schedule the tasks obtained from the build context for execution.
	"""
	def __init__(self, bld, j=2):
		"""
		The initialization requires a build context reference
		for computing the total number of jobs.
		"""

		self.numjobs = j
		"""
		Amount of parallel consumers to use
		"""

		self.bld = bld
		"""
		Instance of :py:class:`waflib.Build.BuildContext`
		"""

		self.outstanding = Utils.deque()
		"""List of :py:class:`waflib.Task.TaskBase` that may be ready to be executed"""

		self.frozen = Utils.deque()
		"""List of :py:class:`waflib.Task.TaskBase` that are not ready yet"""

		self.ready = Queue(0)
		"""List of :py:class:`waflib.Task.TaskBase` ready to be executed by consumers"""

		self.out = Queue(0)
		"""List of :py:class:`waflib.Task.TaskBase` returned by the task consumers"""

		self.count = 0
		"""Amount of tasks that may be processed by :py:class:`waflib.Runner.TaskConsumer`"""

		self.processed = 1
		"""Amount of tasks processed"""

		self.stop = False
		"""Error flag to stop the build"""

		self.error = []
		"""Tasks that could not be executed"""

		self.biter = None
		"""Task iterator which must give groups of parallelizable tasks when calling ``next()``"""

		self.dirty = False
		"""
		Flag that indicates that the build cache must be saved when a task was executed
		(calls :py:meth:`waflib.Build.BuildContext.store`)"""

		self.spawner = Spawner(self)
		"""
		Coordinating daemon thread that spawns thread consumers
		"""

	def get_next_task(self):
		"""
		Obtains the next Task instance to run

		:rtype: :py:class:`waflib.Task.TaskBase`
		"""
		if not self.outstanding:
			return None
		return self.outstanding.popleft()

	def postpone(self, tsk):
		"""
		Adds the task to the list :py:attr:`waflib.Runner.Parallel.frozen`.
		The order is scrambled so as to consume as many tasks in parallel as possible.

		:param tsk: task instance
		:type tsk: :py:class:`waflib.Task.TaskBase`
		"""
		if random.randint(0, 1):
			self.frozen.appendleft(tsk)
		else:
			self.frozen.append(tsk)

	def refill_task_list(self):
		"""
		Adds the next group of tasks to execute in :py:attr:`waflib.Runner.Parallel.outstanding`.
		"""
		while self.count > self.numjobs * GAP:
			self.get_out()

		while not self.outstanding:
			if self.count:
				self.get_out()
			elif self.frozen:
				try:
					cond = self.deadlock == self.processed
				except AttributeError:
					pass
				else:
					if cond:
						msg = 'check the build order for the tasks'
						for tsk in self.frozen:
							if not tsk.run_after:
								msg = 'check the methods runnable_status'
								break
						lst = []
						for tsk in self.frozen:
							lst.append('%s\t-> %r' % (repr(tsk), [id(x) for x in tsk.run_after]))
						raise Errors.WafError('Deadlock detected: %s%s' % (msg, ''.join(lst)))
				self.deadlock = self.processed

			if self.frozen:
				self.outstanding.extend(self.frozen)
				self.frozen.clear()
			elif not self.count:
				self.outstanding.extend(self.biter.next())
				self.total = self.bld.total()
				break

	def add_more_tasks(self, tsk):
		"""
		If a task provides :py:attr:`waflib.Task.TaskBase.more_tasks`, then the tasks contained
		in that list are added to the current build and will be processed before the next build group.

		:param tsk: task instance
		:type tsk: :py:attr:`waflib.Task.TaskBase`
		"""
		if getattr(tsk, 'more_tasks', None):
			self.outstanding.extend(tsk.more_tasks)
			self.total += len(tsk.more_tasks)

	def get_out(self):
		"""
		Waits for a Task that task consumers add to :py:attr:`waflib.Runner.Parallel.out` after execution.
		Adds more Tasks if necessary through :py:attr:`waflib.Runner.Parallel.add_more_tasks`.

		:rtype: :py:attr:`waflib.Task.TaskBase`
		"""
		tsk = self.out.get()
		if not self.stop:
			self.add_more_tasks(tsk)
		self.count -= 1
		self.dirty = True
		return tsk

	def add_task(self, tsk):
		"""
		Enqueue a Task to :py:attr:`waflib.Runner.Parallel.ready` so that consumers can run them.

		:param tsk: task instance
		:type tsk: :py:attr:`waflib.Task.TaskBase`
		"""
		self.ready.put(tsk)

	def skip(self, tsk):
		"""
		Mark a task as skipped/up-to-date
		"""
		tsk.hasrun = Task.SKIPPED

	def error_handler(self, tsk):
		"""
		Called when a task cannot be executed. The flag :py:attr:`waflib.Runner.Parallel.stop` is set, unless
		the build is executed with::

			$ waf build -k

		:param tsk: task instance
		:type tsk: :py:attr:`waflib.Task.TaskBase`
		"""
		if hasattr(tsk, 'scan') and hasattr(tsk, 'uid'):
			# TODO waf 2.0 - this breaks encapsulation
			try:
				del self.bld.imp_sigs[tsk.uid()]
			except KeyError:
				pass
		if not self.bld.keep:
			self.stop = True
		self.error.append(tsk)

	def task_status(self, tsk):
		"""
		Obtains the task status to decide whether to run it immediately or not.

		:return: the exit status, for example :py:attr:`waflib.Task.ASK_LATER`
		:rtype: integer
		"""
		try:
			return tsk.runnable_status()
		except Exception:
			self.processed += 1
			tsk.err_msg = Utils.ex_stack()
			if not self.stop and self.bld.keep:
				self.skip(tsk)
				if self.bld.keep == 1:
					# if -k stop at the first exception, if -kk try to go as far as possible
					if Logs.verbose > 1 or not self.error:
						self.error.append(tsk)
					self.stop = True
				else:
					if Logs.verbose > 1:
						self.error.append(tsk)
				return Task.EXCEPTION
			tsk.hasrun = Task.EXCEPTION

			self.error_handler(tsk)
			return Task.EXCEPTION

	def start(self):
		"""
		Obtains Task instances from the BuildContext instance and adds the ones that need to be executed to
		:py:class:`waflib.Runner.Parallel.ready` so that the :py:class:`waflib.Runner.Spawner` consumer thread
		has them executed. Obtains the executed Tasks back from :py:class:`waflib.Runner.Parallel.out`
		and marks the build as failed by setting the ``stop`` flag.
		If only one job is used, then executes the tasks one by one, without consumers.
		"""
		self.total = self.bld.total()

		while not self.stop:

			self.refill_task_list()

			# consider the next task
			tsk = self.get_next_task()
			if not tsk:
				if self.count:
					# tasks may add new ones after they are run
					continue
				else:
					# no tasks to run, no tasks running, time to exit
					break

			if tsk.hasrun:
				# if the task is marked as "run", just skip it
				self.processed += 1
				continue

			if self.stop: # stop immediately after a failure was detected
				break


			st = self.task_status(tsk)
			if st == Task.RUN_ME:
				self.count += 1
				self.processed += 1

				if self.numjobs == 1:
					tsk.log_display(tsk.generator.bld)
					try:
						tsk.process()
					finally:
						self.out.put(tsk)
				else:
					self.add_task(tsk)
			if st == Task.ASK_LATER:
				self.postpone(tsk)
			elif st == Task.SKIP_ME:
				self.processed += 1
				self.skip(tsk)
				self.add_more_tasks(tsk)

		# self.count represents the tasks that have been made available to the consumer threads
		# collect all the tasks after an error else the message may be incomplete
		while self.error and self.count:
			self.get_out()

		self.ready.put(None)
		assert (self.count == 0 or self.stop)


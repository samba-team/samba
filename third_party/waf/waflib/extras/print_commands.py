#! /usr/bin/env python
# encoding: utf-8
# WARNING! Do not edit! https://waf.io/book/index.html#_obtaining_the_waf_file

#! /usr/bin/env python

"""
Illustrate how to override a class method to do something

In this case, print the commands being executed as strings
(the commands are usually lists, so this can be misleading)
"""

import sys
from waflib import Context, Utils, Errors, Logs

def exec_command(self, cmd, **kw):
	subprocess = Utils.subprocess
	kw['shell'] = isinstance(cmd, str)

	if isinstance(cmd, str):
		kw['shell'] = True
		txt = cmd
	else:
		txt = ' '.join(repr(x) if ' ' in x else x for x in cmd)

	Logs.debug('runner: %s', txt)
	Logs.debug('runner_env: kw=%s', kw)

	if self.logger:
		self.logger.info(cmd)

	if 'stdout' not in kw:
		kw['stdout'] = subprocess.PIPE
	if 'stderr' not in kw:
		kw['stderr'] = subprocess.PIPE

	if Logs.verbose and not kw['shell'] and not Utils.check_exe(cmd[0]):
		raise Errors.WafError("Program %s not found!" % cmd[0])

	wargs = {}
	if 'timeout' in kw:
		if kw['timeout'] is not None:
			wargs['timeout'] = kw['timeout']
		del kw['timeout']
	if 'input' in kw:
		if kw['input']:
			wargs['input'] = kw['input']
			kw['stdin'] = Utils.subprocess.PIPE
		del kw['input']

	if 'cwd' in kw:
		if not isinstance(kw['cwd'], str):
			kw['cwd'] = kw['cwd'].abspath()

	try:
		if kw['stdout'] or kw['stderr']:
			p = subprocess.Popen(cmd, **kw)
			(out, err) = p.communicate(**wargs)
			ret = p.returncode
		else:
			out, err = (None, None)
			ret = subprocess.Popen(cmd, **kw).wait(**wargs)
	except Exception ,e:
		raise Errors.WafError('Execution failure: %s' % str(e), ex=e)

	if out:
		if not isinstance(out, str):
			out = out.decode(sys.stdout.encoding or 'iso8859-1')
		if self.logger:
			self.logger.debug('out: %s' % out)
		else:
			Logs.info(out, extra={'stream':sys.stdout, 'c1': ''})
	if err:
		if not isinstance(err, str):
			err = err.decode(sys.stdout.encoding or 'iso8859-1')
		if self.logger:
			self.logger.error('err: %s' % err)
		else:
			Logs.info(err, extra={'stream':sys.stderr, 'c1': ''})

	return ret

Context.Context.exec_command = exec_command



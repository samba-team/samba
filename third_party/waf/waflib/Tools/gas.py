#!/usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2008-2018 (ita)

"""Detect as/gas/gcc for compiling assembly files

To force a specific compiler::

	def configure(conf):
		conf.find_program(['clang'], var='AS')
		conf.load('gas')
"""

import waflib.Tools.asm # - leave this
from waflib.Tools import ar

def configure(conf):
	"""
	Find the programs gas/as/gcc and set the variable *AS*
	"""
	names = ['gas', 'gcc', 'clang']
	if conf.env.COMPILER_CC == 'clang':
		names = ['clang', 'gas', 'gcc']
	conf.find_program(names, var='AS')
	conf.env.AS_TGT_F = ['-c', '-o']
	conf.env.ASLNK_TGT_F = ['-o']
	conf.find_ar()
	conf.load('asm')
	conf.env.ASM_NAME = 'gas'

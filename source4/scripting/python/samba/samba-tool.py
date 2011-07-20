#!/usr/bin/env python

# Unix SMB/CIFS implementation.
# Copyright (C) Amitay Isaacs <amitay@gmail.com> 211
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
from os.path import dirname

samba_pymodule_dir = dirname(dirname(sys.argv[0]))
sys.path.append(samba_pymodule_dir)

from samba import netcmd
from samba.netcmd import Command, CommandError, Option

class MainCommand(Command):
	"""Main class for samba tool commands"""

	commands = {}

	def _run(self, myname, command=None, *args):
		if command in self.commands:
			return self.commands[command]._run(command, *args)

		print "Syntax: %s <command> [options]" % (myname)
		print "Available commands:"
		for cmd in self.commands:
			print "  %-12s - %s" % (cmd, self.commands[cmd].description)
		if command in [None, 'help', '-h', '--help']:
			return 0
		raise CommandError("No such command '%s'" % command)

	def usage(self, myname, command=None, *args):
		if command is None or not command in self.commands:
			print "Usage: %s (%s) [options]" % (myname,
					" | ".join(self.commands.keys()))
		else:
			return self.commands[command].usage(*args)


class cmd_sambatool(MainCommand):
	"""Samba Tool Commands"""
	commands = netcmd.commands


if __name__ == '__main__':
	cmd = cmd_sambatool()

	command = None
	args = ()

	if len(sys.argv) > 1:
		command = sys.argv[1]
		if len(sys.argv) > 2:
			args = sys.argv[2:]

	cmd._run("samba-tool.py", command, *args)

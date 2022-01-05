/*
   Print a backtrace when a test aborts

   Copyright (C) Martin Schwenke, DataDirect Networks  2022

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"

#include "lib/util/fault.h"
#include "lib/util/signal.h"

#include "tests/src/test_backtrace.h"

static void test_abort_backtrace_handler(int sig)
{
	log_stack_trace();
	CatchSignal(SIGABRT, SIG_DFL);
	abort();
}

void test_backtrace_setup(void)
{
	CatchSignal(SIGABRT, test_abort_backtrace_handler);
}

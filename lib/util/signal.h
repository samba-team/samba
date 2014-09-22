/*
   Unix SMB/CIFS implementation.
   signal handling functions

   Copyright (C) Andrew Tridgell 1998

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SAMBA_UTIL_SIGNAL_H_
#define _SAMBA_UTIL_SIGNAL_H_

#include <stdbool.h>

/**
 Block sigs.
**/
void BlockSignals(bool block, int signum);

/**
 Catch a signal. This should implement the following semantics:

 1) The handler remains installed after being called.
 2) The signal should be blocked during handler execution.
**/
void (*CatchSignal(int signum,void (*handler)(int )))(int);

/**
 Ignore SIGCLD via whatever means is necessary for this OS.
**/
void (*CatchChild(void))(int);

/**
 Catch SIGCLD but leave the child around so it's status can be reaped.
**/
void (*CatchChildLeaveStatus(void))(int);

#endif /* _SAMBA_UTIL_SIGNAL_H_ */

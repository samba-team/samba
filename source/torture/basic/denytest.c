/* 
   Unix SMB/CIFS implementation.
   SMB torture tester - deny mode scanning functions
   Copyright (C) Andrew Tridgell 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"

extern BOOL torture_showall;
extern int torture_failures;

#define CHECK_MAX_FAILURES(label) do { if (++failures >= torture_failures) goto label; } while (0)

enum deny_result {A_0=0, A_X=1, A_R=2, A_W=3, A_RW=5};

static const char *denystr(int denymode)
{
	struct {
		int v;
		const char *name; 
	} deny_modes[] = {
		{DENY_DOS, "DENY_DOS"},
		{DENY_ALL, "DENY_ALL"},
		{DENY_WRITE, "DENY_WRITE"},
		{DENY_READ, "DENY_READ"},
		{DENY_NONE, "DENY_NONE"},
		{DENY_FCB, "DENY_FCB"},
		{-1, NULL}};
	int i;
	for (i=0;deny_modes[i].name;i++) {
		if (deny_modes[i].v == denymode) return deny_modes[i].name;
	}
	return "DENY_XXX";
}

static const char *openstr(int mode)
{
	struct {
		int v;
		const char *name; 
	} open_modes[] = {
		{O_RDWR, "O_RDWR"},
		{O_RDONLY, "O_RDONLY"},
		{O_WRONLY, "O_WRONLY"},
		{-1, NULL}};
	int i;
	for (i=0;open_modes[i].name;i++) {
		if (open_modes[i].v == mode) return open_modes[i].name;
	}
	return "O_XXX";
}

static const char *resultstr(enum deny_result res)
{
	struct {
		enum deny_result res;
		const char *name; 
	} results[] = {
		{A_X, "X"},
		{A_0, "-"},
		{A_R, "R"},
		{A_W, "W"},
		{A_RW,"RW"}};
	int i;
	for (i=0;ARRAY_SIZE(results);i++) {
		if (results[i].res == res) return results[i].name;
	}
	return "*";
}

static const struct {
	int isexe;
	int mode1, deny1;
	int mode2, deny2;
	enum deny_result result;
} denytable2[] = {
{1,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_RW},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_W},
{1,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_RW},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_R},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_W},
{1,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_RW},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_R},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_W},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_RW},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,  DENY_READ,     A_RW},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_R},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_W},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_RW},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_R},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_R},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_R},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_W},
{1,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{1,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_W},
{1, O_RDONLY,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,  DENY_READ,     A_W},
{1, O_WRONLY,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_RW},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_R},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_W},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_RW},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_R},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_W},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,  DENY_READ,     A_RW},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_R},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_W},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_R},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_R},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_R},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{0,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_W},
{0, O_RDONLY,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{0, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,  DENY_READ,     A_W},
{0, O_WRONLY,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{0, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_RW},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_R},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_W},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,  DENY_READ,     A_RW},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_R},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_W},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_0}
};


static const struct {
	int isexe;
	int mode1, deny1;
	int mode2, deny2;
	enum deny_result result;
} denytable1[] = {
{1,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_RW},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_W},
{1,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_RW},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_R},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_W},
{1,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_RW},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_R},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_W},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_RW},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,  DENY_READ,     A_RW},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_R},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_W},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_RW},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_R},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{1,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_R},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_R},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_W},
{1,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{1,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_W},
{1, O_RDONLY,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,  DENY_READ,     A_W},
{1, O_WRONLY,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_RW},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_R},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_W},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{1,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_RW},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_R},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_W},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,  DENY_READ,     A_RW},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_R},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_W},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{1, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{1, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_RW},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_R},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_W},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{1,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_RW},
{1,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_RW},
{1,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_RW},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_RW},
{1, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_RW},
{1, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_RW},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_RW},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_R},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_W},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{1, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_RW},
{1, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_RW},
{1, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_RW},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_RW},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_W},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_RW},
{0,   O_RDWR,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_RW},
{0,   O_RDWR,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_RW},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_R},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_DOS,     A_RW},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_DOS,     A_W},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_DOS,      O_RDWR,   DENY_FCB,     A_RW},
{0, O_WRONLY,   DENY_DOS,    O_RDONLY,   DENY_FCB,     A_RW},
{0, O_WRONLY,   DENY_DOS,    O_WRONLY,   DENY_FCB,     A_RW},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_ALL,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,   DENY_ALL,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{0,   O_RDWR, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_R},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_RDONLY, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,  DENY_READ,     A_R},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,  DENY_READ,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_WRONLY, DENY_WRITE,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY, DENY_WRITE,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{0,   O_RDWR,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_W},
{0, O_RDONLY,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{0, O_RDONLY,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_READ,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_READ,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,  DENY_READ,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,  DENY_READ,     A_W},
{0, O_WRONLY,  DENY_READ,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,  DENY_NONE,     A_W},
{0, O_WRONLY,  DENY_READ,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_READ,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_READ,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{0,   O_RDWR,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_RW},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_R},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_W},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{0, O_RDONLY,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_RDONLY,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_DOS,     A_0},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,  DENY_NONE,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,  DENY_READ,     A_RW},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,  DENY_READ,     A_R},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,  DENY_READ,     A_W},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,  DENY_NONE,     A_RW},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,  DENY_NONE,     A_R},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,  DENY_NONE,     A_W},
{0, O_WRONLY,  DENY_NONE,      O_RDWR,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_RDONLY,   DENY_FCB,     A_0},
{0, O_WRONLY,  DENY_NONE,    O_WRONLY,   DENY_FCB,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_RW},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_R},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_W},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{0,   O_RDWR,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_RW},
{0,   O_RDWR,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_RW},
{0,   O_RDWR,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_RW},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_RW},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_W},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_RDONLY,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_RW},
{0, O_RDONLY,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_RW},
{0, O_RDONLY,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_RW},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_DOS,     A_RW},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_DOS,     A_R},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_DOS,     A_W},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_ALL,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY, DENY_WRITE,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,  DENY_READ,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,  DENY_NONE,     A_0},
{0, O_WRONLY,   DENY_FCB,      O_RDWR,   DENY_FCB,     A_RW},
{0, O_WRONLY,   DENY_FCB,    O_RDONLY,   DENY_FCB,     A_RW},
{0, O_WRONLY,   DENY_FCB,    O_WRONLY,   DENY_FCB,     A_RW}
};


static void progress_bar(uint_t i, uint_t total)
{
	printf("%5d/%5d\r", i, total);
	fflush(stdout);
}

/*
  this produces a matrix of deny mode behaviour for 1 connection
 */
BOOL torture_denytest1(void)
{
	static struct smbcli_state *cli1;
	int fnum1, fnum2;
	int i;
	BOOL correct = True;
	struct timeval tv, tv_start;
	const char *fnames[2] = {"\\denytest1.dat", "\\denytest1.exe"};
	int failures=0;

	if (!torture_open_connection(&cli1)) {
		return False;
	}

	printf("starting denytest1\n");

	printf("Testing deny modes with 1 connection\n");

	for (i=0;i<2;i++) {
		smbcli_unlink(cli1->tree, fnames[i]);
		fnum1 = smbcli_open(cli1->tree, fnames[i], O_RDWR|O_CREAT, DENY_NONE);
		smbcli_write(cli1->tree, fnum1, 0, fnames[i], 0, strlen(fnames[i]));
		smbcli_close(cli1->tree, fnum1);
	}

	printf("testing %d entries\n", ARRAY_SIZE(denytable1));

	GetTimeOfDay(&tv_start);

	for (i=0; i<ARRAY_SIZE(denytable1); i++) {
		enum deny_result res;
		const char *fname = fnames[denytable1[i].isexe];

		progress_bar(i, ARRAY_SIZE(denytable1));

		fnum1 = smbcli_open(cli1->tree, fname, 
				 denytable1[i].mode1,
				 denytable1[i].deny1);
		fnum2 = smbcli_open(cli1->tree, fname, 
				 denytable1[i].mode2,
				 denytable1[i].deny2);

		if (fnum1 == -1) {
			res = A_X;
		} else if (fnum2 == -1) {
			res = A_0;
		} else {
			char x = 1;
			res = A_0;
			if (smbcli_read(cli1->tree, fnum2, (void *)&x, 0, 1) == 1) {
				res += A_R;
			}
			if (smbcli_write(cli1->tree, fnum2, 0, (void *)&x, 0, 1) == 1) {
				res += A_W;
			}
		}

		if (torture_showall || res != denytable1[i].result) {
			int64_t tdif;
			GetTimeOfDay(&tv);
			tdif = usec_time_diff(&tv, &tv_start);
			tdif /= 1000;
			printf("%lld: %s %8s %10s    %8s %10s    %s (correct=%s)\n",
			       tdif,
			       fname,
			       denystr(denytable1[i].deny1),
			       openstr(denytable1[i].mode1),
			       denystr(denytable1[i].deny2),
			       openstr(denytable1[i].mode2),
			       resultstr(res),
			       resultstr(denytable1[i].result));
		}

		if (res != denytable1[i].result) {
			correct = False;
			CHECK_MAX_FAILURES(failed);
		}

		smbcli_close(cli1->tree, fnum1);
		smbcli_close(cli1->tree, fnum2);
	}

failed:
	for (i=0;i<2;i++) {
		smbcli_unlink(cli1->tree, fnames[i]);
	}
		
	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	
	printf("finshed denytest1 (%d failures)\n", failures);
	return correct;
}


/*
  this produces a matrix of deny mode behaviour with 2 connections
 */
BOOL torture_denytest2(void)
{
	static struct smbcli_state *cli1, *cli2;
	int fnum1, fnum2;
	int i;
	BOOL correct = True;
	const char *fnames[2] = {"\\denytest2.dat", "\\denytest2.exe"};
	struct timeval tv, tv_start;
	int failures=0;

	if (!torture_open_connection(&cli1) || !torture_open_connection(&cli2)) {
		return False;
	}

	printf("starting denytest2\n");

	printf("Testing deny modes with 2 connections\n");

	for (i=0;i<2;i++) {
		smbcli_unlink(cli1->tree, fnames[i]);
		fnum1 = smbcli_open(cli1->tree, fnames[i], O_RDWR|O_CREAT, DENY_NONE);
		smbcli_write(cli1->tree, fnum1, 0, fnames[i], 0, strlen(fnames[i]));
		smbcli_close(cli1->tree, fnum1);
	}

	GetTimeOfDay(&tv_start);

	for (i=0; i<ARRAY_SIZE(denytable2); i++) {
		enum deny_result res;
		const char *fname = fnames[denytable2[i].isexe];

		progress_bar(i, ARRAY_SIZE(denytable1));

		fnum1 = smbcli_open(cli1->tree, fname, 
				 denytable2[i].mode1,
				 denytable2[i].deny1);
		fnum2 = smbcli_open(cli2->tree, fname, 
				 denytable2[i].mode2,
				 denytable2[i].deny2);

		if (fnum1 == -1) {
			res = A_X;
		} else if (fnum2 == -1) {
			res = A_0;
		} else {
			char x = 1;
			res = A_0;
			if (smbcli_read(cli2->tree, fnum2, (void *)&x, 0, 1) == 1) {
				res += A_R;
			}
			if (smbcli_write(cli2->tree, fnum2, 0, (void *)&x, 0, 1) == 1) {
				res += A_W;
			}
		}

		if (torture_showall || res != denytable2[i].result) {
			int64_t tdif;
			GetTimeOfDay(&tv);
			tdif = usec_time_diff(&tv, &tv_start);
			tdif /= 1000;
			printf("%lld: %s %8s %10s    %8s %10s    %s (correct=%s)\n",
				tdif,
			       fname,
			       denystr(denytable2[i].deny1),
			       openstr(denytable2[i].mode1),
			       denystr(denytable2[i].deny2),
			       openstr(denytable2[i].mode2),
			       resultstr(res),
			       resultstr(denytable2[i].result));
		}

		if (res != denytable2[i].result) {
			correct = False;
			CHECK_MAX_FAILURES(failed);
		}

		smbcli_close(cli1->tree, fnum1);
		smbcli_close(cli2->tree, fnum2);
	}

failed:		
	for (i=0;i<2;i++) {
		smbcli_unlink(cli1->tree, fnames[i]);
	}

	if (!torture_close_connection(cli1)) {
		correct = False;
	}
	if (!torture_close_connection(cli2)) {
		correct = False;
	}
	
	printf("finshed denytest2 (%d failures)\n", failures);
	return correct;
}



/*
   simple test harness for playing with deny modes
 */
BOOL torture_denytest3(void)
{
	struct smbcli_state *cli1, *cli2;
	int fnum1, fnum2;
	const char *fname;

	printf("starting deny3 test\n");

	printf("Testing simple deny modes\n");
	
	if (!torture_open_connection(&cli1)) {
		return False;
	}
	if (!torture_open_connection(&cli2)) {
		return False;
	}

	fname = "\\deny_dos1.dat";

	smbcli_unlink(cli1->tree, fname);
	fnum1 = smbcli_open(cli1->tree, fname, O_CREAT|O_TRUNC|O_WRONLY, DENY_DOS);
	fnum2 = smbcli_open(cli1->tree, fname, O_CREAT|O_TRUNC|O_WRONLY, DENY_DOS);
	if (fnum1 != -1) smbcli_close(cli1->tree, fnum1);
	if (fnum2 != -1) smbcli_close(cli1->tree, fnum2);
	smbcli_unlink(cli1->tree, fname);
	printf("fnum1=%d fnum2=%d\n", fnum1, fnum2);


	fname = "\\deny_dos2.dat";

	smbcli_unlink(cli1->tree, fname);
	fnum1 = smbcli_open(cli1->tree, fname, O_CREAT|O_TRUNC|O_WRONLY, DENY_DOS);
	fnum2 = smbcli_open(cli2->tree, fname, O_CREAT|O_TRUNC|O_WRONLY, DENY_DOS);
	if (fnum1 != -1) smbcli_close(cli1->tree, fnum1);
	if (fnum2 != -1) smbcli_close(cli2->tree, fnum2);
	smbcli_unlink(cli1->tree, fname);
	printf("fnum1=%d fnum2=%d\n", fnum1, fnum2);


	torture_close_connection(cli1);
	torture_close_connection(cli2);

	return True;
}

struct bit_value {
	uint32_t value;
	const char *name;
};

static uint32_t map_bits(const struct bit_value *bv, int b, int nbits)
{
	int i;
	uint32_t ret = 0;
	for (i=0;i<nbits;i++) {
		if (b & (1<<i)) {
			ret |= bv[i].value;
		}
	}
	return ret;
}

static const char *bit_string(TALLOC_CTX *mem_ctx, const struct bit_value *bv, int b, int nbits)
{
	char *ret = NULL;
	int i;
	for (i=0;i<nbits;i++) {
		if (b & (1<<i)) {
			if (ret == NULL) {
				ret = talloc_asprintf(mem_ctx, "%s", bv[i].name);
			} else {
				ret = talloc_asprintf_append(ret, " | %s", bv[i].name);
			}
		}
	}
	if (ret == NULL) ret = talloc_strdup(mem_ctx, "(NONE)");
	return ret;
}


/*
  determine if two opens conflict
*/
static NTSTATUS predict_share_conflict(uint32_t sa1, uint32_t am1, uint32_t sa2, uint32_t am2,
				       uint16_t flags2, enum deny_result *res)
{
#define CHECK_MASK(am, sa, right, share) do { \
	if (((am) & (right)) && !((sa) & (share))) { \
		*res = A_0; \
		return NT_STATUS_SHARING_VIOLATION; \
	}} while (0)

	*res = A_0;
	if (am2 & SA_RIGHT_FILE_WRITE_APPEND) {
		*res += A_W;
	}
	if (am2 & SA_RIGHT_FILE_READ_DATA) {
		*res += A_R;
	} else if ((am2 & SA_RIGHT_FILE_EXECUTE) && 
		   (flags2 & FLAGS2_READ_PERMIT_EXECUTE)) {
		*res += A_R;
	}

	/* if either open involves no read.write or delete access then
	   it can't conflict */
	if (!(am1 & (SA_RIGHT_FILE_WRITE_APPEND | 
		     SA_RIGHT_FILE_READ_EXEC | 
		     STD_RIGHT_DELETE_ACCESS))) {
		return NT_STATUS_OK;
	}
	if (!(am2 & (SA_RIGHT_FILE_WRITE_APPEND | 
		     SA_RIGHT_FILE_READ_EXEC | 
		     STD_RIGHT_DELETE_ACCESS))) {
		return NT_STATUS_OK;
	}

	/* check the basic share access */
	CHECK_MASK(am1, sa2, 
		   SA_RIGHT_FILE_WRITE_APPEND, 
		   NTCREATEX_SHARE_ACCESS_WRITE);
	CHECK_MASK(am2, sa1, 
		   SA_RIGHT_FILE_WRITE_APPEND, 
		   NTCREATEX_SHARE_ACCESS_WRITE);

	CHECK_MASK(am1, sa2, 
		   SA_RIGHT_FILE_READ_EXEC, 
		   NTCREATEX_SHARE_ACCESS_READ);
	CHECK_MASK(am2, sa1, 
		   SA_RIGHT_FILE_READ_EXEC, 
		   NTCREATEX_SHARE_ACCESS_READ);

	CHECK_MASK(am1, sa2, 
		   STD_RIGHT_DELETE_ACCESS, 
		   NTCREATEX_SHARE_ACCESS_DELETE);
	CHECK_MASK(am2, sa1, 
		   STD_RIGHT_DELETE_ACCESS, 
		   NTCREATEX_SHARE_ACCESS_DELETE);

	return NT_STATUS_OK;
}

/*
  a denytest for ntcreatex
 */
static BOOL torture_ntdenytest(struct smbcli_state *cli1, struct smbcli_state *cli2, int client)
{
	const struct bit_value share_access_bits[] = {
		{ NTCREATEX_SHARE_ACCESS_READ,   "S_R" },
		{ NTCREATEX_SHARE_ACCESS_WRITE,  "S_W" },
		{ NTCREATEX_SHARE_ACCESS_DELETE, "S_D" }
	};
	const struct bit_value access_mask_bits[] = {
		{ SA_RIGHT_FILE_READ_DATA,        "R_DATA" },
		{ SA_RIGHT_FILE_WRITE_DATA,       "W_DATA" },
		{ SA_RIGHT_FILE_READ_ATTRIBUTES,  "R_ATTR" },
		{ SA_RIGHT_FILE_WRITE_ATTRIBUTES, "W_ATTR" },
		{ SA_RIGHT_FILE_READ_EA,          "R_EAS " },
		{ SA_RIGHT_FILE_WRITE_EA,         "W_EAS " },
		{ SA_RIGHT_FILE_APPEND_DATA,      "A_DATA" },
		{ SA_RIGHT_FILE_EXECUTE,          "EXEC  " }
	};
	int fnum1;
	int i;
	BOOL correct = True;
	struct timeval tv, tv_start;
	const char *fname;
	int nbits1 = ARRAY_SIZE(share_access_bits);
	int nbits2 = ARRAY_SIZE(access_mask_bits);
	union smb_open io1, io2;
	extern int torture_numops;
	int failures = 0;
	char buf[1];

	ZERO_STRUCT(buf);

	fname = talloc_asprintf(cli1, "\\ntdeny_%d.dll", client);

	smbcli_unlink(cli1->tree, fname);
	fnum1 = smbcli_open(cli1->tree, fname, O_RDWR|O_CREAT, DENY_NONE);
	smbcli_write(cli1->tree, fnum1, 0, buf, 0, sizeof(buf));
	smbcli_close(cli1->tree, fnum1);

	GetTimeOfDay(&tv_start);

	io1.ntcreatex.level = RAW_OPEN_NTCREATEX;
	io1.ntcreatex.in.root_fid = 0;
	io1.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED;
	io1.ntcreatex.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io1.ntcreatex.in.file_attr = 0;
	io1.ntcreatex.in.alloc_size = 0;
	io1.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io1.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_IMPERSONATION;
	io1.ntcreatex.in.security_flags = 0;
	io1.ntcreatex.in.fname = fname;
	io2 = io1;

	printf("testing %d entries on %s\n", torture_numops, fname);

	for (i=0;i<torture_numops;i++) {
		NTSTATUS status1, status2, status2_p;
		int64_t tdif;
		TALLOC_CTX *mem_ctx = talloc(NULL, 0);
		enum deny_result res, res2;
		int b_sa1 = random() & ((1<<nbits1)-1);
		int b_am1 = random() & ((1<<nbits2)-1);
		int b_sa2 = random() & ((1<<nbits1)-1);
		int b_am2 = random() & ((1<<nbits2)-1);

		progress_bar(i, torture_numops);
		
		io1.ntcreatex.in.share_access = map_bits(share_access_bits, b_sa1, nbits1);
		io1.ntcreatex.in.access_mask  = map_bits(access_mask_bits,  b_am1, nbits2);
		
		io2.ntcreatex.in.share_access = map_bits(share_access_bits, b_sa2, nbits1);
		io2.ntcreatex.in.access_mask  = map_bits(access_mask_bits,  b_am2, nbits2);

		status1 = smb_raw_open(cli1->tree, mem_ctx, &io1);
		status2 = smb_raw_open(cli2->tree, mem_ctx, &io2);

		if (random() % 2 == 0) {
			cli2->tree->session->flags2 |= FLAGS2_READ_PERMIT_EXECUTE;
		} else {
			cli2->tree->session->flags2 &= ~FLAGS2_READ_PERMIT_EXECUTE;
		}
		
		if (!NT_STATUS_IS_OK(status1)) {
			res = A_X;
		} else if (!NT_STATUS_IS_OK(status2)) {
			res = A_0;
		} else {
			res = A_0;
			if (smbcli_read(cli2->tree, 
					io2.ntcreatex.out.fnum, (void *)buf, 0, sizeof(buf)) >= 1) {
				res += A_R;
			}
			if (smbcli_write(cli2->tree, 
					 io2.ntcreatex.out.fnum, 0, (void *)buf, 0, sizeof(buf)) >= 1) {
				res += A_W;
			}
		}
		
		if (NT_STATUS_IS_OK(status1)) {
			smbcli_close(cli1->tree, io1.ntcreatex.out.fnum);
		}
		if (NT_STATUS_IS_OK(status2)) {
			smbcli_close(cli2->tree, io2.ntcreatex.out.fnum);
		}
		
		status2_p = predict_share_conflict(io1.ntcreatex.in.share_access,
						   io1.ntcreatex.in.access_mask,
						   io2.ntcreatex.in.share_access,
						   io2.ntcreatex.in.access_mask, 
						   cli2->tree->session->flags2,
						   &res2);
		
		GetTimeOfDay(&tv);
		tdif = usec_time_diff(&tv, &tv_start);
		tdif /= 1000;
		if (torture_showall || 
		    !NT_STATUS_EQUAL(status2, status2_p) ||
		    res != res2) {
			printf("\n%-20s %-70s\n%-20s %-70s %4s %4s  %s/%s\n",
			       bit_string(mem_ctx, share_access_bits, b_sa1, nbits1),
			       bit_string(mem_ctx, access_mask_bits,  b_am1, nbits2),
			       bit_string(mem_ctx, share_access_bits, b_sa2, nbits1),
			       bit_string(mem_ctx, access_mask_bits,  b_am2, nbits2),
			       resultstr(res),
			       resultstr(res2),
			       nt_errstr(status2),
			       nt_errstr(status2_p));
			fflush(stdout);
		}
		
		if (res != res2 ||
		    !NT_STATUS_EQUAL(status2, status2_p)) {
			CHECK_MAX_FAILURES(failed);
			correct = False;
		}
		
		talloc_free(mem_ctx);
	}

failed:
	smbcli_unlink(cli1->tree, fname);
	
	printf("finshed ntdenytest (%d failures)\n", failures);
	return correct;
}



/*
  a denytest for ntcreatex
 */
BOOL torture_ntdenytest1(struct smbcli_state *cli, int client)
{
	extern int torture_seed;

	srandom(torture_seed + client);

	printf("starting ntdenytest1 client %d\n", client);

	return torture_ntdenytest(cli, cli, client);
}

/*
  a denytest for ntcreatex
 */
BOOL torture_ntdenytest2(void)
{
	struct smbcli_state *cli1, *cli2;
	BOOL ret;

	if (!torture_open_connection(&cli1)) {
		return False;
	}

	if (!torture_open_connection(&cli2)) {
		return False;
	}

	printf("starting ntdenytest2\n");

	ret = torture_ntdenytest(cli1, cli2, 0);

	torture_close_connection(cli1);
	torture_close_connection(cli2);

	return ret;
}


#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) wrong value for %s  0x%x - should be 0x%x\n", \
		       __location__, #v, (int)(v), (int)correct); \
		ret = False; \
	}} while (0)

/*
  test sharing of handles with DENY_DOS on a single connection
*/
BOOL torture_denydos_sharing(void)
{
	struct smbcli_state *cli;
	union smb_open io;
	union smb_fileinfo finfo;
	const char *fname = "\\torture_denydos.txt";
	NTSTATUS status;
	int fnum1, fnum2;
	BOOL ret = True;
	union smb_setfileinfo sfinfo;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc(cli, 0);

	printf("Checking DENY_DOS shared handle semantics\n");
	smbcli_unlink(cli->tree, fname);

	io.openx.level = RAW_OPEN_OPENX;
	io.openx.in.fname = fname;
	io.openx.in.flags = OPENX_FLAGS_ADDITIONAL_INFO;
	io.openx.in.open_mode = OPENX_MODE_ACCESS_RDWR | OPENX_MODE_DENY_DOS;
	io.openx.in.open_func = OPENX_OPEN_FUNC_OPEN | OPENX_OPEN_FUNC_CREATE;
	io.openx.in.search_attrs = 0;
	io.openx.in.file_attrs = 0;
	io.openx.in.write_time = 0;
	io.openx.in.size = 0;
	io.openx.in.timeout = 0;

	printf("openx twice with RDWR/DENY_DOS\n");
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum1 = io.openx.out.fnum;

	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.openx.out.fnum;

	printf("fnum1=%d fnum2=%d\n", fnum1, fnum2);

	sfinfo.generic.level = RAW_SFILEINFO_POSITION_INFORMATION;
	sfinfo.position_information.file.fnum = fnum1;
	sfinfo.position_information.in.position = 1000;
	status = smb_raw_setfileinfo(cli->tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("two handles should be same file handle\n");
	finfo.position_information.level = RAW_FILEINFO_POSITION_INFORMATION;
	finfo.position_information.in.fnum = fnum1;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(finfo.position_information.out.position, 1000);

	finfo.position_information.in.fnum = fnum2;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(finfo.position_information.out.position, 1000);


	smbcli_close(cli->tree, fnum1);
	smbcli_close(cli->tree, fnum2);

	printf("openx twice with RDWR/DENY_NONE\n");
	io.openx.in.open_mode = OPENX_MODE_ACCESS_RDWR | OPENX_MODE_DENY_NONE;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum1 = io.openx.out.fnum;

	io.openx.in.open_func = OPENX_OPEN_FUNC_OPEN;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.openx.out.fnum;

	printf("fnum1=%d fnum2=%d\n", fnum1, fnum2);

	printf("two handles should be separate\n");
	sfinfo.generic.level = RAW_SFILEINFO_POSITION_INFORMATION;
	sfinfo.position_information.file.fnum = fnum1;
	sfinfo.position_information.in.position = 1000;
	status = smb_raw_setfileinfo(cli->tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	finfo.position_information.level = RAW_FILEINFO_POSITION_INFORMATION;
	finfo.position_information.in.fnum = fnum1;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(finfo.position_information.out.position, 1000);

	finfo.position_information.in.fnum = fnum2;
	status = smb_raw_fileinfo(cli->tree, mem_ctx, &finfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(finfo.position_information.out.position, 0);

done:
	smbcli_close(cli->tree, fnum1);
	smbcli_close(cli->tree, fnum2);
	smbcli_unlink(cli->tree, fname);

	return ret;
}



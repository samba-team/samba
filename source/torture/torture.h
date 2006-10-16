/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   
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

#ifndef __TORTURE_H__
#define __TORTURE_H__

#include "torture/ui.h"

struct smbcli_state;

extern struct torture_suite *torture_root;

extern BOOL use_oplocks;
extern BOOL torture_showall;
extern int torture_entries;
extern int torture_nprocs;
extern int torture_seed;
extern int torture_numops;
extern int torture_failures;
extern int torture_numasync;
extern BOOL use_level_II_oplocks;

struct torture_test;

#include "torture/proto.h"

#endif /* __TORTURE_H__ */

/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   
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

#ifndef __SMBTORTURE_H__
#define __SMBTORTURE_H__

#include "../lib/torture/torture.h"

struct smbcli_state;

extern struct torture_suite *torture_root;

extern int torture_entries;
extern int torture_seed;
extern int torture_numops;
extern int torture_failures;
extern int torture_numasync;

struct torture_test;
int torture_init(void);
bool torture_register_suite(struct torture_suite *suite);

#endif /* __SMBTORTURE_H__ */

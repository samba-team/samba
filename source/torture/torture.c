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

#include "includes.h"
#include "system/time.h"
#include "torture/torture.h"
#include "build.h"
#include "lib/util/dlinklist.h"

_PUBLIC_ int torture_nprocs=4;
_PUBLIC_ int torture_numops=10;
_PUBLIC_ int torture_entries=1000;
_PUBLIC_ int torture_failures=1;
_PUBLIC_ int torture_seed=0;
_PUBLIC_ int torture_numasync=100;
_PUBLIC_ bool torture_showall = false;

struct torture_suite_list *torture_suites = NULL;

NTSTATUS torture_register_suite(struct torture_suite *suite)
{
	struct torture_suite_list *p, *n;

	if (!suite) {
		return NT_STATUS_OK;
	}

	n = talloc(talloc_autofree_context(), struct torture_suite_list);
	n->suite = suite;

	for (p = torture_suites; p; p = p->next) {
		if (strcmp(p->suite->name, suite->name) == 0) {
			/* Check for duplicates */
			DEBUG(0,("There already is a suite registered with the name %s!\n", suite->name));
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}

		if (strcmp(p->suite->name, suite->name) < 0 && 
			(!p->next || strcmp(p->next->suite->name, suite->name) > 0)) {
			DLIST_ADD_AFTER(torture_suites, n, p);
			return NT_STATUS_OK;
		}
	}

	DLIST_ADD_END(torture_suites, n, struct torture_suite_list *);

	return NT_STATUS_OK;
}

int torture_init(void)
{
	init_module_fn static_init[] = STATIC_torture_MODULES;
	init_module_fn *shared_init = load_samba_modules(NULL, "torture");
	
	run_init_functions(static_init);
	run_init_functions(shared_init);

	talloc_free(shared_init);

	return 0;
}

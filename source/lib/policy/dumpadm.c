/* 
   Unix SMB/CIFS implementation.
   Copyright (C) 2006 Wilco Baan Hofman <wilco@baanhofman.nl>
   Copyright (C) 2006 Jelmer Vernooij <jelmer@samba.org>
   
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
#include "lib/popt/popt.h"
#include "lib/policy/adm.h"

int main(int argc, char **argv) 
{
	BOOL ret = True;
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{ 0, 0, 0, 0 }
	};
	
	pc = poptGetContext(argv[0], argc, (const char **)argv, long_options, 0);
	
	poptSetOtherOptionHelp(pc, "<ADM-FILE> ...");

	while ((poptGetNextOpt(pc) != -1)) 

	if(!poptPeekArg(pc)) { 
		poptPrintUsage(pc, stderr, 0);
		exit(1);
	}
	
	while (poptPeekArg(pc)) {
		const char *name = poptGetArg(pc);

		adm_read_file(name);
	}

	poptFreeContext(pc);

	return ret;
}

/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   functions to calculate the free disk space
   Copyright (C) Andrew Tridgell 1998
   
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

/****************************************************************************
 Normalise for DOS usage.
****************************************************************************/

static void disk_norm(BOOL small_query, SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize)
{
	/* check if the disk is beyond the max disk size */
	SMB_BIG_UINT maxdisksize = lp_maxdisksize();
	if (maxdisksize) {
		/* convert to blocks - and don't overflow */
		maxdisksize = ((maxdisksize*1024)/(*bsize))*1024;
		if (*dsize > maxdisksize) *dsize = maxdisksize;
		if (*dfree > maxdisksize) *dfree = maxdisksize-1; 
		/* the -1 should stop applications getting div by 0
		   errors */
	}  

	while (*dfree > WORDMAX || *dsize > WORDMAX || *bsize < 512) {
		*dfree /= 2;
		*dsize /= 2;
		*bsize *= 2;
		if(small_query) {	
			/*
			 * Force max to fit in 16 bit fields.
			 */
			if (*bsize > (WORDMAX*512)) {
				*bsize = (WORDMAX*512);
				if (*dsize > WORDMAX)
					*dsize = WORDMAX;
				if (*dfree >  WORDMAX)
					*dfree = WORDMAX;
				break;
			}
		}
	}
}



/****************************************************************************
 Return number of 1K blocks available on a path and total number.
****************************************************************************/

static SMB_BIG_UINT disk_free(char *path, BOOL small_query, 
                              SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize)
{
	int dfree_retval;
	SMB_BIG_UINT dfree_q = 0;
	SMB_BIG_UINT bsize_q = 0;
	SMB_BIG_UINT dsize_q = 0;
	char *dfree_command;

	(*dfree) = (*dsize) = 0;
	(*bsize) = 512;

	/*
	 * If external disk calculation specified, use it.
	 */

	dfree_command = lp_dfree_command();
	if (dfree_command && *dfree_command) {
		char *p;
		char **lines;
		pstring syscmd;

		slprintf(syscmd, sizeof(syscmd)-1, "%s %s", dfree_command, path);
		DEBUG (3, ("disk_free: Running command %s\n", syscmd));

		lines = file_lines_pload(syscmd, NULL, True);
		if (lines) {
			char *line = lines[0];

			DEBUG (3, ("Read input from dfree, \"%s\"\n", line));

			*dsize = (SMB_BIG_UINT)strtoul(line, &p, 10);
			while (p && *p & isspace(*p))
				p++;
			if (p && *p)
				*dfree = (SMB_BIG_UINT)strtoul(p, &p, 10);
			while (p && *p & isspace(*p))
				p++;
			if (p && *p)
				*bsize = (SMB_BIG_UINT)strtoul(p, NULL, 10);
			else
				*bsize = 1024;
			file_lines_free(lines);
			DEBUG (3, ("Parsed output of dfree, dsize=%u, dfree=%u, bsize=%u\n",
				(unsigned int)*dsize, (unsigned int)*dfree, (unsigned int)*bsize));

			if (!*dsize)
				*dsize = 2048;
			if (!*dfree)
				*dfree = 1024;
		} else {
			DEBUG (0, ("disk_free: sys_popen() failed for command %s. Error was : %s\n",
				syscmd, strerror(errno) ));
			sys_fsusage(path, dfree, dsize);
		}
	} else
		sys_fsusage(path, dfree, dsize);

	if (disk_quotas(path, &bsize_q, &dfree_q, &dsize_q)) {
		(*bsize) = bsize_q;
		(*dfree) = MIN(*dfree,dfree_q);
		(*dsize) = MIN(*dsize,dsize_q);
	}

	/* FIXME : Any reason for this assumption ? */
	if (*bsize < 256) {
		DEBUG(5,("disk_free:Warning: bsize == %d < 256 . Changing to assumed correct bsize = 512\n",(int)*bsize));
		*bsize = 512;
	}

	if ((*dsize)<1) {
		static int done;
		if (!done) {
			DEBUG(0,("WARNING: dfree is broken on this system\n"));
			done=1;
		}
		*dsize = 20*1024*1024/(*bsize);
		*dfree = MAX(1,*dfree);
	}

	disk_norm(small_query,bsize,dfree,dsize);

	if ((*bsize) < 1024) {
		dfree_retval = (*dfree)/(1024/(*bsize));
	} else {
		dfree_retval = ((*bsize)/1024)*(*dfree);
	}

	return(dfree_retval);
}

/****************************************************************************
 Wrap it to get filenames right.
****************************************************************************/

SMB_BIG_UINT sys_disk_free(const char *path, BOOL small_query, 
                           SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize)
{
	return(disk_free(dos_to_unix_static(path),small_query, bsize,dfree,dsize));
}

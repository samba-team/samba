/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper functions - shared variables
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

extern int DEBUGLEVEL;

static int shared_fd;
static char *variables;
static int shared_size;

/***************************************************** 
setup the shared area 
*******************************************************/
void smbw_setup_shared(void)
{
	int fd;
	pstring s, name;

	slprintf(s,sizeof(s)-1, "%s/smbw.XXXXXX",tmpdir());

	fstrcpy(name,(char *)mktemp(s));

	/* note zero permissions! don't change this */
	fd = open(name,O_RDWR|O_CREAT|O_TRUNC|O_EXCL,0); 
	if (fd == -1) goto failed;
	unlink(name);

	shared_fd = set_maxfiles(SMBW_MAX_OPEN);
	
	while (shared_fd && dup2(fd, shared_fd) != shared_fd) shared_fd--;

	if (shared_fd == 0) goto failed;

	close(fd);

	DEBUG(4,("created shared_fd=%d\n", shared_fd));

	slprintf(s,sizeof(s)-1,"%d", shared_fd);

	smbw_setenv("SMBW_HANDLE", s);

	return;

 failed:
	perror("Failed to setup shared variable area ");
	exit(1);
}


/***************************************************** 
lock the shared variable area
*******************************************************/
static void lockit(void)
{
	if (shared_fd == 0) {
		char *p = getenv("SMBW_HANDLE");
		if (!p) {
			DEBUG(0,("ERROR: can't get smbw shared handle\n"));
			exit(1);
		}
		shared_fd = atoi(p);
	}
	if (fcntl_lock(shared_fd,SMB_F_SETLKW,0,1,F_WRLCK)==False) {
		DEBUG(0,("ERROR: can't get smbw shared lock\n"));
		exit(1);
	}
}

/***************************************************** 
unlock the shared variable area
*******************************************************/
static void unlockit(void)
{
	fcntl_lock(shared_fd,SMB_F_SETLK,0,1,F_UNLCK);
}


/***************************************************** 
get a variable from the shared area
*******************************************************/
char *smbw_getshared(const char *name)
{
	int i;
	struct stat st;

	lockit();

	/* maybe the area has changed */
	if (fstat(shared_fd, &st)) goto failed;

	if (st.st_size != shared_size) {
		variables = (char *)Realloc(variables, st.st_size);
		if (!variables) goto failed;
		shared_size = st.st_size;
		lseek(shared_fd, 0, SEEK_SET);
		if (read(shared_fd, variables, shared_size) != shared_size) {
			goto failed;
		}
	}

	unlockit();

	i=0;
	while (i < shared_size) {
		char *n, *v;

		n = &variables[i];
		i += strlen(n)+1;
		v = &variables[i];
		i += strlen(v)+1;

		if (strcmp(name,n)) {
			continue;
		}
		return v;
	}

	return NULL;

 failed:
	DEBUG(0,("smbw: shared variables corrupt (%s)\n", strerror(errno)));
	exit(1);
	return NULL;
}



/***************************************************** 
set a variable in the shared area
*******************************************************/
void smbw_setshared(const char *name, const char *val)
{
	int len;

	/* we don't allow variable overwrite */
	if (smbw_getshared(name)) return;

	lockit();

	len = strlen(name) + strlen(val) + 2;

	variables = (char *)Realloc(variables, shared_size + len);

	if (!variables) {
		DEBUG(0,("out of memory in smbw_setshared\n"));
		exit(1);
	}

	pstrcpy(&variables[shared_size], name);
	shared_size += strlen(name)+1;
	pstrcpy(&variables[shared_size], val);
	shared_size += strlen(val)+1;

	lseek(shared_fd, 0, SEEK_SET);
	if (write(shared_fd, variables, shared_size) != shared_size) {
		DEBUG(0,("smbw_setshared failed (%s)\n", strerror(errno)));
		exit(1);
	}

	unlockit();
}


/*****************************************************************
set an env variable - some systems don't have this
*****************************************************************/  
int smbw_setenv(const char *name, const char *value)
{
	pstring s;
	char *p;

	slprintf(s,sizeof(s)-1,"%s=%s", name, value);

	p = strdup(s);

	if (p) p = putenv(p);

	return p;
}


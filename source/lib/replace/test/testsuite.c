/* 
   Unix SMB/CIFS implementation.

   libreplace tests

   Copyright (C) Jelmer Vernooij 2006

     ** NOTE! The following LGPL license applies to the talloc
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "../replace.h"
#include <stdio.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#if HAVE_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <fcntl.h>
#include <errno.h>

#define TESTFILE "testfile.dat"

/*
  test ftruncate() function
 */
static int test_ftruncate()
{
	struct stat st;
	int fd, i;
	const int size;
	printf("testing ftruncate\n");
	unlink(TESTFILE);
	fd = open(TESTFILE, O_RDWR|O_CREAT, 0600);
	if (fd == -1) {
		printf("creating '%s' failed - %s\n", TESTFILE, strerror(errno));
		return false;
	}
	if (ftruncate(fd, size) != 0) {
		printf("ftruncate failed - %s\n", strerror(errno));
		return false;
	}
	if (fstat(fd, &st) != 0) {
		printf("fstat failed - %s\n", strerror(errno));
		return false;
	}
	if (st.st_size != size) {
		printf("ftruncate gave wrong size %d - expected %d\n",
		       (int)st.st_size, size);
		return false;
	}
	return true;
}

static int test_strlcpy()
{
	/* FIXME */
	return true;
}

static int test_strlcat()
{
	/* FIXME */
	return true;
}

static int test_mktime()
{
	/* FIXME */
	return true;
}

static int test_rename()
{
	/* FIXME */
	return true;
}

static int test_innetgr()
{
	/* FIXME */
	return true;
}

static int test_initgroups()
{
	/* FIXME */
	return true;
}

static int test_memmove()
{
	/* FIXME */
	return true;
}

static int test_strdup()
{
	/* FIXME */
	return true;
}	

static int test_setlinebuf()
{
	/* FIXME */
	return true;
}

static int test_vsyslog()
{
	/* FIXME */
	return true;
}

static int test_timegm()
{
	/* FIXME */
	return true;
}

static int test_setenv()
{
	/* FIXME */
	return true;
}

static int test_strndup()
{
	/* FIXME */
	return true;
}

static int test_strnlen()
{
	/* FIXME */
	return true;
}

static int test_waitpid()
{
	/* FIXME */
	return true;
}

static int test_seteuid()
{
	/* FIXME */
	return true;
}

static int test_setegid()
{
	/* FIXME */
	return true;
}

static int test_asprintf()
{
	/* FIXME */
	return true;
}

static int test_snprintf()
{
	/* FIXME */
	return true;
}

static int test_vasprintf()
{
	/* FIXME */
	return true;
}

static int test_vsnprintf()
{
	/* FIXME */
	return true;
}

static int test_opendir()
{
	/* FIXME */
	return true;
}

static int test_readdir()
{
	/* FIXME */
	return true;
}

static int test_telldir()
{
	/* FIXME */
	return true;
}

static int test_seekdir()
{
	/* FIXME */
	return true;
}

static int test_dlopen()
{
	/* FIXME: test dlopen, dlsym, dlclose, dlerror */
	return true;
}


static int test_chroot()
{
	/* FIXME: chroot() */
	return true;
}

static int test_bzero()
{
	/* FIXME: bzero */
	return true;
}

static int test_strerror()
{
	/* FIXME */
	return true;
}

static int test_errno()
{
	/* FIXME */
	return true;
}

static int test_mkdtemp()
{
	/* FIXME */
	return true;
}

static int test_mkstemp()
{
	/* FIXME */
	return true;
}

static int test_pread()
{
	/* FIXME */
	return true;
}

static int test_pwrite()
{
	/* FIXME */
	return true;
}

static int test_getpass()
{
	/* FIXME */
	return true;
}

static int test_inet_ntoa()
{
	/* FIXME */
	return true;
}

static int test_strtoll()
{
	/* FIXME */
	return true;
}

static int test_strtoull()
{
	/* FIXME */
	return true;
}

/* 
FIXME:
Types:
bool
socklen_t
uint_t
uint{8,16,32,64}_t
int{8,16,32,64}_t
intptr_t

Constants:
PATH_NAME_MAX
UINT{16,32,64}_MAX
INT32_MAX
*/

static int test_va_copy()
{
	/* FIXME */
	return true;
}

static int test_FUNCTION()
{
	/* FIXME: test __FUNCTION__ macro */
	return true;
}

static int test_MIN()
{
	/* FIXME */
	return true;
}

static int test_MAX()
{
	/* FIXME */
	return true;
}

int torture_local_replace()
{
	int ret = true;
;
	ret &= test_ftruncate();
	ret &= test_strlcpy();
	ret &= test_strlcat();
	ret &= test_mktime();
	ret &= test_rename();
	ret &= test_innetgr();
	ret &= test_initgroups();
	ret &= test_memmove();
	ret &= test_strdup();
	ret &= test_setlinebuf();
	ret &= test_vsyslog();
	ret &= test_timegm();
	ret &= test_setenv();
	ret &= test_strndup();
	ret &= test_strnlen();
	ret &= test_waitpid();
	ret &= test_seteuid();
	ret &= test_setegid();
	ret &= test_asprintf();
	ret &= test_snprintf();
	ret &= test_vasprintf();
	ret &= test_vsnprintf();
	ret &= test_opendir();
	ret &= test_readdir() ;
	ret &= test_telldir();
	ret &= test_seekdir();
	ret &= test_dlopen();
	ret &= test_chroot();
	ret &= test_bzero();
	ret &= test_strerror();
	ret &= test_errno();
	ret &= test_mkdtemp();
	ret &= test_mkstemp();
	ret &= test_pread();
	ret &= test_pwrite();
	ret &= test_getpass();
	ret &= test_inet_ntoa();
	ret &= test_strtoll();
	ret &= test_strtoll();
	ret &= test_strtoull();
	ret &= test_va_copy();
	ret &= test_FUNCTION();
	ret &= test_MIN();
	ret &= test_MAX();

	return ret;
}

#if !defined(_SAMBA_BUILD_) || ((SAMBA_VERSION_MAJOR==3)&&(SAMBA_VERSION_MINOR<9))
int main(void)
{
	if (!torture_local_replace(NULL)) {
		printf("ERROR: TESTSUITE FAILED\n");
		return -1;
	}
	return 0;
}
#endif

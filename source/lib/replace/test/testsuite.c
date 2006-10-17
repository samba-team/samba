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

#include "replace.h"

/*
  we include all the system/ include files here so that libreplace tests
  them in the build farm
*/
#include "system/capability.h"
#include "system/dir.h"
#include "system/filesys.h"
#include "system/glob.h"
#include "system/iconv.h"
#include "system/locale.h"
#include "system/network.h"
#include "system/passwd.h"
#include "system/printing.h"
#include "system/readline.h"
#include "system/select.h"
#include "system/shmem.h"
#include "system/syslog.h"
#include "system/terminal.h"
#include "system/time.h"
#include "system/wait.h"

#define TESTFILE "testfile.dat"

/*
  test ftruncate() function
 */
static int test_ftruncate(void)
{
	struct stat st;
	int fd;
	const int size = 1234;
	printf("test: ftruncate\n");
	unlink(TESTFILE);
	fd = open(TESTFILE, O_RDWR|O_CREAT, 0600);
	if (fd == -1) {
		printf("failure: ftruncate [\n"
			   "creating '%s' failed - %s\n]\n", TESTFILE, strerror(errno));
		return false;
	}
	if (ftruncate(fd, size) != 0) {
		printf("failure: ftruncate [\n%s\n]\n", strerror(errno));
		return false;
	}
	if (fstat(fd, &st) != 0) {
		printf("failure: ftruncate [\nfstat failed - %s\n]\n", strerror(errno));
		return false;
	}
	if (st.st_size != size) {
		printf("failure: ftruncate [\ngave wrong size %d - expected %d\n]\n",
		       (int)st.st_size, size);
		return false;
	}
	printf("success: ftruncate\n");
	return true;
}

/*
  test strlcpy() function.
  see http://www.gratisoft.us/todd/papers/strlcpy.html
 */
static int test_strlcpy(void)
{
	char buf[4];
	const struct {
		const char *src;
		size_t result;
	} tests[] = {
		{ "abc", 3 },
		{ "abcdef", 6 },
		{ "abcd", 4 },
		{ "", 0 },
		{ NULL, 0 }
	};
	int i;
	printf("test: strlcpy\n");
	for (i=0;tests[i].src;i++) {
		if (strlcpy(buf, tests[i].src, sizeof(buf)) != tests[i].result) {
			printf("failure: strlcpy [\ntest %d failed\n]\n", i);
			return false;
		}
	}
	printf("success: strlcpy\n");
	return true;
}

static int test_strlcat(void)
{
	/* FIXME */
	return true;
}

static int test_mktime(void)
{
	/* FIXME */
	return true;
}

static int test_innetgr(void)
{
	/* FIXME */
	return true;
}

static int test_initgroups(void)
{
	/* FIXME */
	return true;
}

static int test_memmove(void)
{
	/* FIXME */
	return true;
}

static int test_strdup(void)
{
	/* FIXME */
	return true;
}	

static int test_setlinebuf(void)
{
	printf("test: setlinebuf\n");
	setlinebuf(stdout);
	printf("success: setlinebuf\n");
	return true;
}

static int test_vsyslog(void)
{
	/* FIXME */
	return true;
}

static int test_timegm(void)
{
	/* FIXME */
	return true;
}

static int test_setenv(void)
{
	/* FIXME */
	return true;
}

static int test_strndup(void)
{
	/* FIXME */
	return true;
}

static int test_strnlen(void)
{
	/* FIXME */
	return true;
}

static int test_waitpid(void)
{
	/* FIXME */
	return true;
}

static int test_seteuid(void)
{
	/* FIXME */
	return true;
}

static int test_setegid(void)
{
	/* FIXME */
	return true;
}

static int test_asprintf(void)
{
	/* FIXME */
	return true;
}

static int test_snprintf(void)
{
	/* FIXME */
	return true;
}

static int test_vasprintf(void)
{
	/* FIXME */
	return true;
}

static int test_vsnprintf(void)
{
	/* FIXME */
	return true;
}

static int test_opendir(void)
{
	/* FIXME */
	return true;
}

extern int test_readdir_os2_delete(void);

static int test_readdir(void)
{
	printf("test: readdir\n");
	if (test_readdir_os2_delete() != 0) {
		return false;
	}
	printf("success: readdir\n");
	return true;
}

static int test_telldir(void)
{
	/* FIXME */
	return true;
}

static int test_seekdir(void)
{
	/* FIXME */
	return true;
}

static int test_dlopen(void)
{
	/* FIXME: test dlopen, dlsym, dlclose, dlerror */
	return true;
}


static int test_chroot(void)
{
	/* FIXME: chroot() */
	return true;
}

static int test_bzero(void)
{
	/* FIXME: bzero */
	return true;
}

static int test_strerror(void)
{
	/* FIXME */
	return true;
}

static int test_errno(void)
{
	/* FIXME */
	return true;
}

static int test_mkdtemp(void)
{
	/* FIXME */
	return true;
}

static int test_mkstemp(void)
{
	/* FIXME */
	return true;
}

static int test_pread(void)
{
	/* FIXME */
	return true;
}

static int test_pwrite(void)
{
	/* FIXME */
	return true;
}

static int test_getpass(void)
{
	/* FIXME */
	return true;
}

static int test_inet_ntoa(void)
{
	/* FIXME */
	return true;
}

static int test_strtoll(void)
{
	/* FIXME */
	return true;
}

static int test_strtoull(void)
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

static int test_va_copy(void)
{
	/* FIXME */
	return true;
}

static int test_FUNCTION(void)
{
	/* FIXME: test __FUNCTION__ macro */
	return true;
}

static int test_MIN(void)
{
	/* FIXME */
	return true;
}

static int test_MAX(void)
{
	/* FIXME */
	return true;
}

struct torture_context;

int main()
{
	bool ret = true;
	ret &= test_ftruncate();
	ret &= test_strlcpy();
	ret &= test_strlcat();
	ret &= test_mktime();
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
	ret &= test_readdir();
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

	if (ret) 
		return 0;
	return -1;
}

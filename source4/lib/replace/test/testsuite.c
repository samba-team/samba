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
#include "system/aio.h"

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
	unlink(TESTFILE);
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
	char tmp[10];
	printf("test: strlcat\n");
	strcpy(tmp, "");
	if (strlcat(tmp, "bla", 3) != 3) {
		printf("failure: strlcat [\ninvalid return code\n]\n");
		return false;
	}
	if (strcmp(tmp, "bl") != 0) {
		printf("failure: strlcat [\nexpected \"bl\", got \"%s\"\n]\n", 
			   tmp);
		return false;
	}

	strcpy(tmp, "da");
	if (strlcat(tmp, "me", 4) != 4) {
		printf("failure: strlcat [\nexpected \"dam\", got \"%s\"\n]\n",
			   tmp);
		return false;
	}

	printf("success: strlcat\n");
	return true;
}

static int test_mktime(void)
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
	char *x;
	printf("test: strdup\n");
	x = strdup("bla");
	if (strcmp("bla", x) != 0) {
		printf("failure: strdup [\nfailed: expected \"bla\", got \"%s\"\n]\n",
			   x);
		return false;
	}
	free(x);
	printf("success: strdup\n");
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
#define TEST_SETENV(key, value, overwrite, result) do { \
	int _ret; \
	char *_v; \
	_ret = setenv(key, value, overwrite); \
	if (_ret != 0) { \
		printf("failure: setenv [\n" \
			"setenv(%s, %s, %d) failed\n" \
			"]\n", \
			key, value, overwrite); \
		return false; \
	} \
	_v=getenv(key); \
	if (!_v) { \
		printf("failure: setenv [\n" \
			"getenv(%s) returned NULL\n" \
			"]\n", \
			key); \
		return false; \
	} \
	if (strcmp(result, _v) != 0) { \
		printf("failure: setenv [\n" \
			"getenv(%s): '%s' != '%s'\n" \
			"]\n", \
			key, result, _v); \
		return false; \
	} \
} while(0)

#define TEST_UNSETENV(key) do { \
	char *_v; \
	unsetenv(key); \
	_v=getenv(key); \
	if (_v) { \
		printf("failure: setenv [\n" \
			"getenv(%s): NULL != '%s'\n" \
			"]\n", \
			SETENVTEST_KEY, _v); \
		return false; \
	} \
} while (0)

#define SETENVTEST_KEY "SETENVTESTKEY"
#define SETENVTEST_VAL "SETENVTESTVAL"

	printf("test: setenv\n");
	TEST_SETENV(SETENVTEST_KEY, SETENVTEST_VAL"1", 0, SETENVTEST_VAL"1");
	TEST_SETENV(SETENVTEST_KEY, SETENVTEST_VAL"2", 0, SETENVTEST_VAL"1");
	TEST_SETENV(SETENVTEST_KEY, SETENVTEST_VAL"3", 1, SETENVTEST_VAL"3");
	TEST_SETENV(SETENVTEST_KEY, SETENVTEST_VAL"4", 1, SETENVTEST_VAL"4");
	TEST_UNSETENV(SETENVTEST_KEY);
	TEST_UNSETENV(SETENVTEST_KEY);
	TEST_SETENV(SETENVTEST_KEY, SETENVTEST_VAL"5", 0, SETENVTEST_VAL"5");
	TEST_UNSETENV(SETENVTEST_KEY);
	TEST_UNSETENV(SETENVTEST_KEY);
	printf("success: setenv\n");
	return true;
}

static int test_strndup(void)
{
	char *x;
	printf("test: strndup\n");
	x = strndup("bla", 0);
	if (strcmp(x, "") != 0) {
		printf("failure: strndup [\ninvalid\n]\n");
		return false;
	}
	free(x);
	x = strndup("bla", 2);
	if (strcmp(x, "bl") != 0) {
		printf("failure: strndup [\ninvalid\n]\n");
		return false;
	}
	free(x);
	x = strndup("bla", 10);
	if (strcmp(x, "bla") != 0) {
		printf("failure: strndup [\ninvalid\n]\n");
		return false;
	}
	free(x);
	printf("success: strndup\n");
	return true;
}

static int test_strnlen(void)
{
	printf("test: strnlen\n");
	if (strnlen("bla", 2) != 2) {
		printf("failure: strnlen [\nunexpected length\n]\n");
		return false;
	}

	if (strnlen("some text\n", 0) != 0) {
		printf("failure: strnlen [\nunexpected length\n]\n");
		return false;
	}

	if (strnlen("some text", 20) != 9) {
		printf("failure: strnlen [\nunexpected length\n]\n");
		return false;
	}

	printf("success: strnlen\n");
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
	char *x;
	printf("test: asprintf\n");
	if (asprintf(&x, "%d", 9) != 1) {
		printf("failure: asprintf [\ngenerate asprintf\n]\n");
		return false;
	}
	if (strcmp(x, "9") != 0) {
		printf("failure: asprintf [\ngenerate asprintf\n]\n");
		return false;
	}
	if (asprintf(&x, "dat%s", "a") != 4) {
		printf("failure: asprintf [\ngenerate asprintf\n]\n");
		return false;
	}
	if (strcmp(x, "data") != 0) {
		printf("failure: asprintf [\ngenerate asprintf\n]\n");
		return false;
	}
	printf("success: asprintf\n");
	return true;
}

static int test_snprintf(void)
{
	char tmp[10];
	printf("test: snprintf\n");
	if (snprintf(tmp, 3, "foo%d", 9) != 4) {
		printf("failure: snprintf [\nsnprintf return code failed\n]\n");
		return false;
	}

	if (strcmp(tmp, "fo") != 0) {
		printf("failure: snprintf [\nsnprintf failed\n]\n");
		return false;
	}

	printf("success: snprintf\n");
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
	printf("test: strerror\n");
	/* FIXME */
	printf("failure: sterror\n");
	return true;
}

static int test_errno(void)
{
	printf("test: errno\n");
	errno = 3;
	if (errno != 3) {
		printf("failure: errno [\nerrno failed\n]\n");
		return false;
	}

	printf("success: errno\n");
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
	printf("test: strtoll\n");
	if (strtoll("15", NULL, 10) != 15) {
		printf("failure: strtoll [\nstrtoll failed\n]\n");
		return false;
	}
	if (strtoll("10", NULL, 16) != 16) {
		printf("failure: strtoll [\nstrtoll hex failed\n]\n");
		return false;
	}
	if (strtoll("11", NULL, 2) != 3) {
		printf("failure: strtoll [\nstrtoll binary failed\n]\n");
		return false;
	}
	printf("success: strtoll\n");
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
	printf("test: FUNCTION\n");
	if (strcmp(__FUNCTION__, "test_FUNCTION") != 0) {
		printf("failure: FAILURE [\nFAILURE invalid\n]\n");
		return false;
	}
	printf("success: FUNCTION\n");
	return true;
}

static int test_MIN(void)
{
	printf("test: MIN\n");
	if (MIN(20, 1) != 1) {
		printf("failure: MIN [\nMIN invalid\n]\n");
		return false;
	}
	if (MIN(1, 20) != 1) {
		printf("failure: MIN [\nMIN invalid\n]\n");
		return false;
	}
	printf("success: MIN\n");
	return true;
}

static int test_MAX(void)
{
	printf("test: MAX\n");
	if (MAX(20, 1) != 20) {
		printf("failure: MAX [\nMAX invalid\n]\n");
		return false;
	}
	if (MAX(1, 20) != 20) {
		printf("failure: MAX [\nMAX invalid\n]\n");
		return false;
	}
	printf("success: MAX\n");
	return true;
}

static int test_socketpair(void)
{
	int sock[2];
	char buf[20];

	printf("test: socketpair\n");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock) == -1) {
		printf("failure: socketpair [\n"
			   "socketpair() failed\n"
			   "]\n");
		return false;
	}

	if (write(sock[1], "automatisch", 12) == -1) {
		printf("failure: socketpair [\n"
			   "write() failed: %s\n"
			   "]\n", strerror(errno));
		return false;
	}

	if (read(sock[0], buf, 12) == -1) {
		printf("failure: socketpair [\n"
			   "read() failed: %s\n"
			   "]\n", strerror(errno));
		return false;
	}

	if (strcmp(buf, "automatisch") != 0) {
		printf("failure: socketpair [\n"
			   "expected: automatisch, got: %s\n"
			   "]\n", buf);
		return false;
	}

	printf("success: socketpair\n");

	return true;
}

static int test_strptime(void)
{
	const char *s = "20070414101546Z";
	char *ret;
	struct tm t, t2;

	printf("test: strptime\n");

	ret = strptime(s, "%Y%m%d%H%M%S", &t);
	if ( ret == NULL ) {
		printf("failure: strptime [\n"
		       "returned NULL\n"
		       "]\n");
		return false;
	}

	ret = strptime(s, "%Y%m%d%H%M%SZ", &t2);
	if ( ret == NULL ) {
		printf("failure: strptime [\n"
		       "returned NULL with Z\n"
		       "]\n");
		return false;
	}

	if (memcmp(&t, &t2, sizeof(t)) == 0) {
		printf("failure: strptime [\n"
		       "result differs if the format string has a 'Z' at the end\n"
		       "]\n");
		return false;
	}

	if (t.tm_sec != 46) {
		printf("failure: strptime [\n"
		       "tm_sec: expected: 46, got: %d\n"
		       "]\n",
		       t.tm_sec);
		return false;
	}

	if (t.tm_min != 15) {
		printf("failure: strptime [\n"
		       "tm_min: expected: 15, got: %d\n"
		       "]\n",
		       t.tm_min);
		return false;
	}

	if (t.tm_hour != 10) {
		printf("failure: strptime [\n"
		       "tm_hour: expected: 10, got: %d\n"
		       "]\n",
		       t.tm_hour);
		return false;
	}

	if (t.tm_mday != 14) {
		printf("failure: strptime [\n"
		       "tm_mday: expected: 14, got: %d\n"
		       "]\n",
		       t.tm_mday);
		return false;
	}

	if (t.tm_mon != 3) {
		printf("failure: strptime [\n"
		       "tm_mon: expected: 3, got: %d\n"
		       "]\n",
		       t.tm_mon);
		return false;
	}

	if (t.tm_year != 107) {
		printf("failure: strptime [\n"
		       "tm_year: expected: 107, got: %d\n"
		       "]\n",
		       t.tm_year);
		return false;
	}

	if (t.tm_wday != 6) { /* saturday */
		printf("failure: strptime [\n"
		       "tm_wday: expected: 6, got: %d\n"
		       "]\n",
		       t.tm_wday);
		return false;
	}

	if (t.tm_yday != 103) {
		printf("failure: strptime [\n"
		       "tm_yday: expected: 103, got: %d\n"
		       "]\n",
		       t.tm_yday);
		return false;
	}

	/* we don't test this as it depends on the host configuration
	if (t.tm_isdst != 0) {
		printf("failure: strptime [\n"
		       "tm_isdst: expected: 0, got: %d\n"
		       "]\n",
		       t.tm_isdst);
		return false;
	}*/

	printf("success: strptime\n");

	return true;
}

struct torture_context;
bool torture_local_replace(struct torture_context *ctx)
{
	bool ret = true;
	ret &= test_ftruncate();
	ret &= test_strlcpy();
	ret &= test_strlcat();
	ret &= test_mktime();
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
	ret &= test_socketpair();
	ret &= test_strptime();

	return ret;
}

#if _SAMBA_BUILD_<4
int main(void)
{
	bool ret = torture_local_replace(NULL);
	if (ret) 
		return 0;
	return -1;
}
#endif
